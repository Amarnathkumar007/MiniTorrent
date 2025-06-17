#include "common.h"

// Global client state
static client_state_t client_state;

// Signal handler for clean shutdown
void signal_handler(int signal) {
    printf("\nReceived signal %d, shutting down client...\n", signal);
    client_state.is_running = 0;
}

int connect_to_tracker(client_state_t* client) {
    if (client->tracker_socket >= 0) {
        close_socket(client->tracker_socket);
    }
    
    client->tracker_socket = connect_to_server(client->tracker_ip, client->tracker_port);
    if (client->tracker_socket < 0) {
        printf("Failed to connect to tracker at %s:%d\n", client->tracker_ip, client->tracker_port);
        return -1;
    }
    
    return 0;
}

void handle_peer_connection(client_state_t* client, int peer_fd) {
    message_t request;
    if (receive_message(peer_fd, &request) <= 0) {
        return;
    }
    
    if (request.type == MSG_PIECE_REQUEST) {
        char filename[MAX_FILENAME_SIZE];
        int piece_index;
        
        if (sscanf(request.data, "%255[^:]:%d", filename, &piece_index) == 2) {
            // Find the file in shared files
            pthread_mutex_lock(&client->client_mutex);
            
            file_info_t* file_info = NULL;
            for (int i = 0; i < client->shared_file_count; i++) {
                if (strcmp(client->shared_files[i].filename, filename) == 0) {
                    file_info = &client->shared_files[i];
                    break;
                }
            }
            
            if (file_info != NULL && piece_index >= 0 && piece_index < file_info->total_pieces) {
                printf("%sServing piece %d of %s%s\n", CYAN, piece_index, filename, RESET);
                
                // Read the piece from file
                int fd = open(file_info->filepath, O_RDONLY);
                if (fd >= 0) {
                    char buffer[PIECE_SIZE];
                    off_t offset = (off_t)piece_index * PIECE_SIZE;
                    size_t bytes_to_read = PIECE_SIZE;
                    
                    // Last piece might be smaller
                    if (piece_index == file_info->total_pieces - 1) {
                        bytes_to_read = file_info->file_size - offset;
                    }
                    
                    if (lseek(fd, offset, SEEK_SET) == offset) {
                        ssize_t bytes_read = read(fd, buffer, bytes_to_read);
                        if (bytes_read > 0) {
                            // Compute piece hash
                            unsigned char piece_hash[SHA1_DIGEST_LENGTH];
                            compute_piece_sha1(file_info->filepath, piece_index, piece_hash);
                            
                            // Send piece response with hash: size:hash:data
                            message_t response;
                            response.type = MSG_PIECE_RESPONSE;
                            
                            int header_len = snprintf(response.data, MAX_BUFFER_SIZE, "%ld:%s:", 
                                                    bytes_read, sha1_to_string(piece_hash));
                            
                            // Copy piece data after header
                            if (header_len + bytes_read <= MAX_BUFFER_SIZE) {
                                memcpy(response.data + header_len, buffer, bytes_read);
                                response.data_length = header_len + bytes_read;
                                send_message(peer_fd, &response);
                                
                                printf("%s✓ Sent piece %d (%ld bytes) with hash%s\n", 
                                       GREEN, piece_index, bytes_read, RESET);
                                log_message(client->log_file, client->verbose_mode,
                                          "Sent piece %d of %s to peer (%ld bytes)", 
                                          piece_index, filename, bytes_read);
                            } else {
                                printf("%sError: Piece too large for buffer%s\n", RED, RESET);
                            }
                        } else {
                            printf("%sError: Failed to read piece %d%s\n", RED, piece_index, RESET);
                        }
                    } else {
                        printf("%sError: Failed to seek to piece %d%s\n", RED, piece_index, RESET);
                    }
                    close(fd);
                } else {
                    printf("%sError: Failed to open file %s%s\n", RED, file_info->filepath, RESET);
                }
            } else {
                printf("%sError: Invalid piece request for %s (piece %d)%s\n", 
                       RED, filename, piece_index, RESET);
            }
            
            pthread_mutex_unlock(&client->client_mutex);
        }
    }
}

void* peer_server_thread(void* arg) {
    client_state_t* client = (client_state_t*)arg;
    
    while (client->is_running) {
        char peer_ip[INET_ADDRSTRLEN];
        int peer_port;
        int peer_fd = accept_connection(client->peer_socket, peer_ip, &peer_port);
        
        if (peer_fd >= 0) {
            log_message(client->log_file, client->verbose_mode,
                      "Peer connected from %s:%d", peer_ip, peer_port);
            
            handle_peer_connection(client, peer_fd);
            close_socket(peer_fd);
            
            log_message(client->log_file, client->verbose_mode,
                      "Peer disconnected from %s:%d", peer_ip, peer_port);
        }
    }
    
    return NULL;
}

void handle_client_command(client_state_t* client, const char* command) {
    char cmd[256];
    strncpy(cmd, command, sizeof(cmd) - 1);
    cmd[sizeof(cmd) - 1] = '\0';
    trim_string(cmd);
    
    if (strcmp(cmd, "help") == 0) {
        print_help(0);
    } else if (strncmp(cmd, "create_user ", 12) == 0) {
        char user_id[MAX_USERNAME_SIZE], password[MAX_PASSWORD_SIZE];
        if (sscanf(cmd + 12, "%63s %63s", user_id, password) == 2) {
            if (client->tracker_socket < 0 && connect_to_tracker(client) < 0) {
                printf("%sError: Failed to connect to tracker%s\n", RED, RESET);
                return;
            }
            
            message_t msg;
            msg.type = MSG_CREATE_USER;
            snprintf(msg.data, MAX_BUFFER_SIZE, "%s %s", user_id, password);
            msg.data_length = strlen(msg.data);
            
            if (send_message(client->tracker_socket, &msg) == 0) {
                message_t response;
                if (receive_message(client->tracker_socket, &response) > 0) {
                    if (response.type == MSG_SUCCESS) {
                        printf("%s✓ %s%s\n", GREEN, response.data, RESET);
                    } else {
                        printf("%s✗ %s%s\n", RED, response.data, RESET);
                    }
                }
            } else {
                printf("%sError: Failed to send message to tracker%s\n", RED, RESET);
            }
        } else {
            printf("%sUsage:%s create_user <user_id> <password>\n", YELLOW, RESET);
        }
    } else if (strncmp(cmd, "login ", 6) == 0) {
        char user_id[MAX_USERNAME_SIZE], password[MAX_PASSWORD_SIZE];
        if (sscanf(cmd + 6, "%63s %63s", user_id, password) == 2) {
            if (client->tracker_socket < 0 && connect_to_tracker(client) < 0) {
                printf("%sError: Failed to connect to tracker%s\n", RED, RESET);
                return;
            }
            
            message_t msg;
            msg.type = MSG_LOGIN;
            snprintf(msg.data, MAX_BUFFER_SIZE, "%s %s", user_id, password);
            msg.data_length = strlen(msg.data);
            
            if (send_message(client->tracker_socket, &msg) == 0) {
                message_t response;
                if (receive_message(client->tracker_socket, &response) > 0) {
                    if (response.type == MSG_SUCCESS) {
                        strncpy(client->user_id, user_id, MAX_USERNAME_SIZE - 1);
                        client->user_id[MAX_USERNAME_SIZE - 1] = '\0';
                        client->is_logged_in = 1;
                        printf("%s✓ Login successful! Welcome %s%s%s\n", GREEN, CYAN, user_id, RESET);
                    } else {
                        printf("%s✗ %s%s\n", RED, response.data, RESET);
                    }
                }
            } else {
                printf("%sError: Failed to send login request%s\n", RED, RESET);
            }
        } else {
            printf("%sUsage:%s login <user_id> <password>\n", YELLOW, RESET);
        }
    } else if (strncmp(cmd, "create_group ", 13) == 0) {
        if (!client->is_logged_in) {
            printf("Please login first\n");
            return;
        }
        
        char group_id[MAX_GROUP_ID_SIZE];
        if (sscanf(cmd + 13, "%63s", group_id) == 1) {
            message_t msg;
            msg.type = MSG_CREATE_GROUP;
            snprintf(msg.data, MAX_BUFFER_SIZE, "%s %s", group_id, client->user_id);
            msg.data_length = strlen(msg.data);
            
            if (send_message(client->tracker_socket, &msg) == 0) {
                message_t response;
                if (receive_message(client->tracker_socket, &response) > 0) {
                    printf("%s\n", response.data);
                }
            }
        } else {
            printf("Usage: create_group <group_id>\n");
        }
    } else if (strncmp(cmd, "join_group ", 11) == 0) {
        if (!client->is_logged_in) {
            printf("Please login first\n");
            return;
        }
        
        char group_id[MAX_GROUP_ID_SIZE];
        if (sscanf(cmd + 11, "%63s", group_id) == 1) {
            message_t msg;
            msg.type = MSG_JOIN_GROUP;
            snprintf(msg.data, MAX_BUFFER_SIZE, "%s %s", group_id, client->user_id);
            msg.data_length = strlen(msg.data);
            
            if (send_message(client->tracker_socket, &msg) == 0) {
                message_t response;
                if (receive_message(client->tracker_socket, &response) > 0) {
                    printf("%s\n", response.data);
                }
            }
        } else {
            printf("Usage: join_group <group_id>\n");
        }
    } else if (strcmp(cmd, "list_groups") == 0) {
        if (!client->is_logged_in) {
            printf("Please login first\n");
            return;
        }
        
        message_t msg;
        msg.type = MSG_LIST_GROUPS;
        msg.data_length = 0;
        
        if (send_message(client->tracker_socket, &msg) == 0) {
            message_t response;
            if (receive_message(client->tracker_socket, &response) > 0) {
                printf("\n=== GROUPS ===\n");
                if (strlen(response.data) > 0) {
                    char* line = strtok(response.data, "\n");
                    while (line != NULL) {
                        char* colon = strchr(line, ':');
                        if (colon != NULL) {
                            *colon = '\0';
                            printf("Group: %s (Owner: %s)\n", line, colon + 1);
                        }
                        line = strtok(NULL, "\n");
                    }
                } else {
                    printf("No groups found\n");
                }
                printf("\n");
            }
        }
    } else if (strncmp(cmd, "list_files ", 11) == 0) {
        if (!client->is_logged_in) {
            printf("Please login first\n");
            return;
        }
        
        char group_id[MAX_GROUP_ID_SIZE];
        if (sscanf(cmd + 11, "%63s", group_id) == 1) {
            message_t msg;
            msg.type = MSG_LIST_FILES;
            snprintf(msg.data, MAX_BUFFER_SIZE, "%s", group_id);
            msg.data_length = strlen(msg.data);
            
            if (send_message(client->tracker_socket, &msg) == 0) {
                message_t response;
                if (receive_message(client->tracker_socket, &response) > 0) {
                    if (response.type == MSG_SUCCESS) {
                        printf("\n=== FILES IN GROUP %s ===\n", group_id);
                        if (strlen(response.data) > 0) {
                            char* line = strtok(response.data, "\n");
                            while (line != NULL) {
                                char filename[MAX_FILENAME_SIZE];
                                size_t file_size;
                                char sha1[41];
                                if (sscanf(line, "%255[^:]:%zu:%40s", filename, &file_size, sha1) == 3) {
                                    printf("%s (Size: %zu bytes, SHA1: %s)\n", filename, file_size, sha1);
                                }
                                line = strtok(NULL, "\n");
                            }
                        } else {
                            printf("No files found in group\n");
                        }
                        printf("\n");
                    } else {
                        printf("%s\n", response.data);
                    }
                }
            }
        } else {
            printf("Usage: list_files <group_id>\n");
        }
    } else if (strncmp(cmd, "upload_file ", 12) == 0) {
        if (!client->is_logged_in) {
            printf("%sPlease login first%s\n", RED, RESET);
            return;
        }
        
        char filepath[MAX_PATH_SIZE], group_id[MAX_GROUP_ID_SIZE];
        if (sscanf(cmd + 12, "%511s %63s", filepath, group_id) == 2) {
            // Step 2: Check if file exists before proceeding
            if (!check_file_exists(filepath)) {
                return;
            }
            
            file_info_t file_info;
            printf("%sProcessing file metadata...%s\n", CYAN, RESET);
            
            if (upload_file_metadata(filepath, group_id, &file_info) == 0) {
                strncpy(file_info.uploader, client->user_id, MAX_USERNAME_SIZE - 1);
                file_info.uploader[MAX_USERNAME_SIZE - 1] = '\0';
                
                // Step 1: Show progress bar for file processing
                long long total_size = file_info.file_size;
                long long processed = 0;
                
                display_progress_bar("Processing", processed, total_size);
                usleep(100000); // Brief pause for visual effect
                processed = total_size / 2;
                display_progress_bar("Processing", processed, total_size);
                usleep(100000);
                processed = total_size;
                display_progress_bar("Processing", processed, total_size);
                
                printf("%sUploading metadata to tracker...%s\n", CYAN, RESET);
                
                // Send file metadata to tracker with peer info
                message_t msg;
                msg.type = MSG_UPLOAD_FILE;
                // Include peer info for P2P downloads: filename:group_id:size:sha1:uploader:ip:port:total_pieces
                snprintf(msg.data, MAX_BUFFER_SIZE, "%s:%s:%lld:%s:%s:%s:%d:%d", 
                        file_info.filename, file_info.group_id, (long long)file_info.file_size,
                        sha1_to_string(file_info.file_sha1), file_info.uploader,
                        "127.0.0.1", client->peer_port, file_info.total_pieces);
                msg.data_length = strlen(msg.data);
                
                if (send_message(client->tracker_socket, &msg) == 0) {
                    message_t response;
                    if (receive_message(client->tracker_socket, &response) > 0) {
                        if (response.type == MSG_SUCCESS) {
                            // Add to shared files
                            pthread_mutex_lock(&client->client_mutex);
                            if (client->shared_file_count < MAX_FILES_PER_GROUP) {
                                client->shared_files[client->shared_file_count] = file_info;
                                client->shared_file_count++;
                            }
                            pthread_mutex_unlock(&client->client_mutex);
                            printf("%s✓ %s%s\n", GREEN, response.data, RESET);
                        } else {
                            printf("%s✗ %s%s\n", RED, response.data, RESET);
                        }
                    }
                } else {
                    printf("%sError: Failed to communicate with tracker%s\n", RED, RESET);
                }
            } else {
                printf("%sError: Failed to process file: %s%s\n", RED, filepath, RESET);
            }
        } else {
            printf("%sUsage:%s upload_file <file_path> <group_id>\n", YELLOW, RESET);
        }
    } else if (strncmp(cmd, "download_file ", 14) == 0) {
        if (!client->is_logged_in) {
            printf("%sPlease login first%s\n", RED, RESET);
            return;
        }
        
        char group_id[MAX_GROUP_ID_SIZE], filename[MAX_FILENAME_SIZE], dest_path[MAX_PATH_SIZE];
        if (sscanf(cmd + 14, "%63s %255s %511s", group_id, filename, dest_path) == 3) {
            printf("%s🚀 Starting P2P download of %s%s from group %s%s...%s\n", 
                   CYAN, YELLOW, filename, YELLOW, group_id, RESET);
            
            // Step 1: Get detailed file info including peer details from tracker
            message_t msg;
            msg.type = MSG_GET_FILE_INFO;
            snprintf(msg.data, MAX_BUFFER_SIZE, "%s:%s", group_id, filename);
            msg.data_length = strlen(msg.data);
            
            if (send_message(client->tracker_socket, &msg) == 0) {
                message_t response;
                if (receive_message(client->tracker_socket, &response) > 0) {
                    if (response.type == MSG_SUCCESS) {
                        // Parse file info: filename:size:sha1:uploader:ip:port:total_pieces
                        char file_filename[MAX_FILENAME_SIZE], uploader[MAX_USERNAME_SIZE];
                        char uploader_ip[INET_ADDRSTRLEN], file_sha1[41];
                        long long file_size;
                        int uploader_port, total_pieces;
                        
                        if (sscanf(response.data, "%255[^:]:%lld:%40[^:]:%63[^:]:%15[^:]:%d:%d",
                                  file_filename, &file_size, file_sha1, uploader, uploader_ip, 
                                  &uploader_port, &total_pieces) == 7) {
                            
                            printf("%s📋 File Info:%s\n", CYAN, RESET);
                            printf("  📁 File: %s%s%s (%s%lld bytes%s)\n", YELLOW, filename, RESET, CYAN, file_size, RESET);
                            printf("  👤 Uploader: %s%s%s\n", YELLOW, uploader, RESET);
                            printf("  🌐 Peer: %s%s:%d%s\n", YELLOW, uploader_ip, uploader_port, RESET);
                            printf("  🧩 Pieces: %s%d%s\n", YELLOW, total_pieces, RESET);
                            printf("  🔒 SHA1: %s%s%s\n", YELLOW, file_sha1, RESET);
                            
                            // Step 2: Create destination file
                            int dest_fd = open(dest_path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
                            if (dest_fd < 0) {
                                printf("%s❌ Error: Failed to create destination file: %s%s\n", RED, dest_path, RESET);
                                return;
                            }
                            
                            if (file_size > 0) {
                                printf("%s🔄 Starting piece-by-piece download...%s\n", CYAN, RESET);
                                
                                // Step 3: Download pieces from uploader peer
                                int downloaded_pieces = 0;
                                int failed_pieces = 0;
                                unsigned char final_file_hash[SHA1_DIGEST_LENGTH];
                                string_to_sha1(file_sha1, final_file_hash);
                                
                                display_progress_bar("Download", 0, file_size);
                                
                                for (int piece_idx = 0; piece_idx < total_pieces; piece_idx++) {
                                    // Connect to uploader peer
                                    int peer_fd = connect_to_server(uploader_ip, uploader_port);
                                    if (peer_fd < 0) {
                                        printf("%s❌ Failed to connect to peer %s:%d%s\n", 
                                               RED, uploader_ip, uploader_port, RESET);
                                        failed_pieces++;
                                        break;
                                    }
                                    
                                    // Request piece
                                    message_t piece_request;
                                    piece_request.type = MSG_PIECE_REQUEST;
                                    snprintf(piece_request.data, MAX_BUFFER_SIZE, "%s:%d", filename, piece_idx);
                                    piece_request.data_length = strlen(piece_request.data);
                                    
                                    if (send_message(peer_fd, &piece_request) == 0) {
                                        message_t piece_response;
                                        if (receive_message(peer_fd, &piece_response) > 0 && 
                                            piece_response.type == MSG_PIECE_RESPONSE) {
                                            
                                            // Parse response: size:hash:data
                                            char *first_colon = strchr(piece_response.data, ':');
                                            char *second_colon = strchr(first_colon + 1, ':');
                                            
                                            if (first_colon && second_colon) {
                                                *first_colon = '\0';
                                                *second_colon = '\0';
                                                
                                                long piece_size = atol(piece_response.data);
                                                char *piece_hash_str = first_colon + 1;
                                                char *piece_data = second_colon + 1;
                                                
                                                // Verify piece hash
                                                unsigned char received_hash[SHA1_DIGEST_LENGTH];
                                                string_to_sha1(piece_hash_str, received_hash);
                                                
                                                unsigned char computed_hash[SHA1_DIGEST_LENGTH];
                                                compute_sha1(piece_data, piece_size, computed_hash);
                                                
                                                if (memcmp(received_hash, computed_hash, SHA1_DIGEST_LENGTH) == 0) {
                                                    // Hash verified, write piece to file
                                                    off_t offset = (off_t)piece_idx * PIECE_SIZE;
                                                    if (lseek(dest_fd, offset, SEEK_SET) == offset) {
                                                        if (write(dest_fd, piece_data, piece_size) == piece_size) {
                                                            downloaded_pieces++;
                                                            long long transferred = (long long)(downloaded_pieces) * PIECE_SIZE;
                                                            if (piece_idx == total_pieces - 1) {
                                                                transferred = file_size; // Last piece
                                                            }
                                                            display_progress_bar("Download", transferred, file_size);
                                                        } else {
                                                            printf("%s❌ Failed to write piece %d%s\n", RED, piece_idx, RESET);
                                                            failed_pieces++;
                                                        }
                                                    } else {
                                                        printf("%s❌ Failed to seek to piece %d%s\n", RED, piece_idx, RESET);
                                                        failed_pieces++;
                                                    }
                                                } else {
                                                    printf("%s❌ Piece %d hash verification failed%s\n", RED, piece_idx, RESET);
                                                    failed_pieces++;
                                                }
                                            } else {
                                                printf("%s❌ Invalid piece response format%s\n", RED, RESET);
                                                failed_pieces++;
                                            }
                                        } else {
                                            printf("%s❌ Failed to receive piece %d%s\n", RED, piece_idx, RESET);
                                            failed_pieces++;
                                        }
                                    } else {
                                        printf("%s❌ Failed to request piece %d%s\n", RED, piece_idx, RESET);
                                        failed_pieces++;
                                    }
                                    
                                    close_socket(peer_fd);
                                    
                                    if (failed_pieces > 0) {
                                        break; // Stop on first failure
                                    }
                                }
                                
                                // Step 4: Verify final file hash
                                if (failed_pieces == 0 && downloaded_pieces == total_pieces) {
                                    close(dest_fd);
                                    
                                    // Compute hash of downloaded file
                                    unsigned char downloaded_file_hash[SHA1_DIGEST_LENGTH];
                                    compute_file_sha1(dest_path, downloaded_file_hash);
                                    
                                    if (memcmp(final_file_hash, downloaded_file_hash, SHA1_DIGEST_LENGTH) == 0) {
                                        printf("%s✅ Download completed successfully!%s\n", GREEN, RESET);
                                        printf("%s📁 File saved to: %s%s%s\n", CYAN, YELLOW, dest_path, RESET);
                                        printf("%s🔒 File integrity verified with SHA1%s\n", GREEN, RESET);
                                    } else {
                                        printf("%s❌ File hash verification failed! File may be corrupted.%s\n", RED, RESET);
                                        // Remove corrupted file
                                        unlink(dest_path);
                                    }
                                } else {
                                    close(dest_fd);
                                    printf("%s❌ Download failed: %d pieces failed%s\n", RED, failed_pieces, RESET);
                                    // Remove incomplete file
                                    unlink(dest_path);
                                }
                            } else {
                                close(dest_fd);
                                printf("%s📝 File %s is empty (0 bytes)%s\n", YELLOW, filename, RESET);
                            }
                        } else {
                            printf("%s❌ Error: Invalid file info format from tracker%s\n", RED, RESET);
                        }
                    } else {
                        printf("%s❌ Error: %s%s\n", RED, response.data, RESET);
                    }
                } else {
                    printf("%s❌ Error: Failed to get file info from tracker%s\n", RED, RESET);
                }
            } else {
                printf("%s❌ Error: Failed to connect to tracker%s\n", RED, RESET);
            }
        } else {
            printf("%sUsage:%s download_file <group_id> <file_name> <destination_path>\n", YELLOW, RESET);
        }
    } else if (strcmp(cmd, "show_downloads") == 0) {
        printf("\n=== DOWNLOAD STATUS ===\n");
        pthread_mutex_lock(&client->client_mutex);
        for (int i = 0; i < client->download_count; i++) {
            download_info_t* dl = &client->downloads[i];
            char status = dl->is_complete ? 'C' : (dl->is_downloading ? 'D' : 'P');
            printf("[%c] %s (%d/%d pieces)\n", status, dl->filename, 
                   dl->downloaded_pieces, dl->total_pieces);
        }
        pthread_mutex_unlock(&client->client_mutex);
        if (client->download_count == 0) {
            printf("No active downloads\n");
        }
        printf("\n");
    } else if (strncmp(cmd, "list_requests ", 14) == 0) {
        if (!client->is_logged_in) {
            printf("Please login first\n");
            return;
        }
        
        char group_id[MAX_GROUP_ID_SIZE];
        if (sscanf(cmd + 14, "%63s", group_id) == 1) {
            message_t msg;
            msg.type = MSG_LIST_REQUESTS;
            snprintf(msg.data, MAX_BUFFER_SIZE, "%s %s", group_id, client->user_id);
            msg.data_length = strlen(msg.data);
            
            if (send_message(client->tracker_socket, &msg) == 0) {
                message_t response;
                if (receive_message(client->tracker_socket, &response) > 0) {
                    if (response.type == MSG_SUCCESS) {
                        printf("\n=== PENDING REQUESTS FOR GROUP %s ===\n", group_id);
                        if (strlen(response.data) > 0) {
                            char* line = strtok(response.data, "\n");
                            while (line != NULL) {
                                printf("Request from: %s\n", line);
                                line = strtok(NULL, "\n");
                            }
                        } else {
                            printf("No pending requests\n");
                        }
                        printf("\n");
                    } else {
                        printf("%s\n", response.data);
                    }
                }
            }
        } else {
            printf("Usage: list_requests <group_id>\n");
        }
    } else if (strncmp(cmd, "accept_request ", 15) == 0) {
        if (!client->is_logged_in) {
            printf("Please login first\n");
            return;
        }
        
        char group_id[MAX_GROUP_ID_SIZE], user_id[MAX_USERNAME_SIZE];
        if (sscanf(cmd + 15, "%63s %63s", group_id, user_id) == 2) {
            message_t msg;
            msg.type = MSG_ACCEPT_REQUEST;
            snprintf(msg.data, MAX_BUFFER_SIZE, "%s %s %s", group_id, user_id, client->user_id);
            msg.data_length = strlen(msg.data);
            
            if (send_message(client->tracker_socket, &msg) == 0) {
                message_t response;
                if (receive_message(client->tracker_socket, &response) > 0) {
                    printf("%s\n", response.data);
                }
            }
        } else {
            printf("Usage: accept_request <group_id> <user_id>\n");
        }
    } else if (strncmp(cmd, "leave_group ", 12) == 0) {
        if (!client->is_logged_in) {
            printf("Please login first\n");
            return;
        }
        
        char group_id[MAX_GROUP_ID_SIZE];
        if (sscanf(cmd + 12, "%63s", group_id) == 1) {
            message_t msg;
            msg.type = MSG_LEAVE_GROUP;
            snprintf(msg.data, MAX_BUFFER_SIZE, "%s %s", group_id, client->user_id);
            msg.data_length = strlen(msg.data);
            
            if (send_message(client->tracker_socket, &msg) == 0) {
                message_t response;
                if (receive_message(client->tracker_socket, &response) > 0) {
                    printf("%s\n", response.data);
                }
            }
        } else {
            printf("Usage: leave_group <group_id>\n");
        }
    } else if (strncmp(cmd, "stop_share ", 11) == 0) {
        if (!client->is_logged_in) {
            printf("Please login first\n");
            return;
        }
        
        char group_id[MAX_GROUP_ID_SIZE], filename[MAX_FILENAME_SIZE];
        if (sscanf(cmd + 11, "%63s %255s", group_id, filename) == 2) {
            message_t msg;
            msg.type = MSG_STOP_SHARE;
            snprintf(msg.data, MAX_BUFFER_SIZE, "%s %s %s", group_id, filename, client->user_id);
            msg.data_length = strlen(msg.data);
            
            if (send_message(client->tracker_socket, &msg) == 0) {
                message_t response;
                if (receive_message(client->tracker_socket, &response) > 0) {
                    printf("%s\n", response.data);
                    
                    // Remove from local shared files
                    pthread_mutex_lock(&client->client_mutex);
                    for (int i = 0; i < client->shared_file_count; i++) {
                        if (strcmp(client->shared_files[i].filename, filename) == 0 &&
                            strcmp(client->shared_files[i].group_id, group_id) == 0) {
                            // Remove by shifting array
                            for (int j = i; j < client->shared_file_count - 1; j++) {
                                client->shared_files[j] = client->shared_files[j + 1];
                            }
                            client->shared_file_count--;
                            break;
                        }
                    }
                    pthread_mutex_unlock(&client->client_mutex);
                }
            }
        } else {
            printf("Usage: stop_share <group_id> <file_name>\n");
        }
    } else if (strncmp(cmd, "list_peers ", 11) == 0) {
        char filename[MAX_FILENAME_SIZE];
        if (sscanf(cmd + 11, "%255s", filename) == 1) {
            printf("Listing peers for file: %s\n", filename);
            printf("(Peer discovery functionality would be implemented here)\n");
        } else {
            printf("Usage: list_peers <file_name>\n");
        }
    } else if (strncmp(cmd, "download_progress ", 18) == 0) {
        char filename[MAX_FILENAME_SIZE];
        if (sscanf(cmd + 18, "%255s", filename) == 1) {
            printf("\n=== DOWNLOAD PROGRESS FOR %s ===\n", filename);
            pthread_mutex_lock(&client->client_mutex);
            int found = 0;
            for (int i = 0; i < client->download_count; i++) {
                if (strcmp(client->downloads[i].filename, filename) == 0) {
                    download_info_t* dl = &client->downloads[i];
                    printf("Status: %s\n", dl->is_complete ? "Complete" : 
                           (dl->is_downloading ? "Downloading" : "Paused"));
                    printf("Progress: %d/%d pieces (%.1f%%)\n", 
                           dl->downloaded_pieces, dl->total_pieces,
                           (float)dl->downloaded_pieces / dl->total_pieces * 100);
                    found = 1;
                    break;
                }
            }
            pthread_mutex_unlock(&client->client_mutex);
            if (!found) {
                printf("File not found in downloads\n");
            }
            printf("\n");
        } else {
            printf("Usage: download_progress <file_name>\n");
        }
    } else if (strcmp(cmd, "list_shared_files") == 0) {
        printf("\n=== SHARED FILES ===\n");
        pthread_mutex_lock(&client->client_mutex);
        for (int i = 0; i < client->shared_file_count; i++) {
            file_info_t* file = &client->shared_files[i];
            printf("%s (Group: %s, Size: %lld bytes)\n", 
                   file->filename, file->group_id, (long long)file->file_size);
        }
        pthread_mutex_unlock(&client->client_mutex);
        if (client->shared_file_count == 0) {
            printf("No files being shared\n");
        }
        printf("\n");
    } else if (strcmp(cmd, "logout") == 0) {
        if (client->is_logged_in) {
            message_t msg;
            msg.type = MSG_LOGOUT;
            snprintf(msg.data, MAX_BUFFER_SIZE, "%s", client->user_id);
            msg.data_length = strlen(msg.data);
            
            send_message(client->tracker_socket, &msg);
            
            client->is_logged_in = 0;
            memset(client->user_id, 0, sizeof(client->user_id));
            printf("Logged out successfully\n");
        } else {
            printf("Not logged in\n");
        }
    } else if (strcmp(cmd, "verbose") == 0) {
        client->verbose_mode = !client->verbose_mode;
        printf("Verbose mode: %s\n", client->verbose_mode ? "ON" : "OFF");
    } else if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
        printf("Shutting down client...\n");
        client->is_running = 0;
    } else {
        printf("Unknown command: %s\nType 'help' for available commands.\n", cmd);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <IP:PORT> <tracker_info.txt>\n", argv[0]);
        return 1;
    }
    
    // Initialize client state
    memset(&client_state, 0, sizeof(client_state));
    client_state.is_running = 1;
    client_state.verbose_mode = 1;
    client_state.tracker_socket = -1;
    client_state.peer_socket = -1;
    
    // Initialize mutex
    if (pthread_mutex_init(&client_state.client_mutex, NULL) != 0) {
        perror("Failed to initialize mutex");
        return 1;
    }
    
    // Open log file
    client_state.log_file = fopen("client.log", "a");
    if (client_state.log_file == NULL) {
        perror("Failed to open log file");
    }
    
    // Parse tracker address
    char* colon = strchr(argv[1], ':');
    if (colon == NULL) {
        fprintf(stderr, "Invalid address format. Use IP:PORT\n");
        return 1;
    }
    
    *colon = '\0';
    strncpy(client_state.tracker_ip, argv[1], INET_ADDRSTRLEN - 1);
    client_state.tracker_ip[INET_ADDRSTRLEN - 1] = '\0';
    client_state.tracker_port = atoi(colon + 1);
    
    // Parse tracker info file
    if (parse_tracker_info(argv[2], client_state.trackers, &client_state.tracker_count) < 0) {
        fprintf(stderr, "Failed to parse tracker_info.txt\n");
        return 1;
    }
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Start peer server
    if (start_peer_server(&client_state) < 0) {
        fprintf(stderr, "Failed to start peer server\n");
        return 1;
    }
    
    // Start peer server thread
    pthread_t peer_thread;
    if (pthread_create(&peer_thread, NULL, peer_server_thread, &client_state) != 0) {
        perror("Failed to create peer server thread");
        return 1;
    }
    
    printf("P2P Client started\n");
    printf("Peer server listening on port %d\n", client_state.peer_port);
    printf("Tracker: %s:%d\n", client_state.tracker_ip, client_state.tracker_port);
    printf("Type 'help' for available commands.\n\n");
    
    log_message(client_state.log_file, client_state.verbose_mode, 
                "Client started, peer server on port %d", client_state.peer_port);
    
    // Main command loop with readline for history navigation
    char* command;
    while (client_state.is_running) {
        // Step 4: Use readline for terminal history navigation  
        command = readline(BLUE "p2p> " RESET);
        
        if (command == NULL) {
            // EOF (Ctrl+D)
            printf("\n");
            break;
        }
        
        // Step 4: Add non-empty commands to history
        if (*command) {
            add_history(command);
            handle_client_command(&client_state, command);
        }
        
        // Free the command string allocated by readline
        free(command);
    }
    
    // Cleanup
    client_state.is_running = 0;
    
    if (client_state.tracker_socket >= 0) {
        close_socket(client_state.tracker_socket);
    }
    
    if (client_state.peer_socket >= 0) {
        close_socket(client_state.peer_socket);
    }
    
    pthread_join(peer_thread, NULL);
    
    if (client_state.log_file != NULL) {
        fclose(client_state.log_file);
    }
    
    pthread_mutex_destroy(&client_state.client_mutex);
    
    printf("Client stopped.\n");
    return 0;
} 