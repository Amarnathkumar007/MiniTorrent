#include "common.h"

int upload_file_metadata(const char* filepath, const char* group_id, file_info_t* file_info) {
    // Get file stats
    struct stat file_stat;
    if (stat(filepath, &file_stat) < 0) {
        perror("Failed to get file statistics");
        return -1;
    }
    
    // Fill in basic file information
    const char* filename = strrchr(filepath, '/');
    if (filename == NULL) {
        filename = filepath;
    } else {
        filename++; // Skip the '/'
    }
    
    strncpy(file_info->filename, filename, MAX_FILENAME_SIZE - 1);
    file_info->filename[MAX_FILENAME_SIZE - 1] = '\0';
    
    strncpy(file_info->filepath, filepath, MAX_PATH_SIZE - 1);
    file_info->filepath[MAX_PATH_SIZE - 1] = '\0';
    
    strncpy(file_info->group_id, group_id, MAX_GROUP_ID_SIZE - 1);
    file_info->group_id[MAX_GROUP_ID_SIZE - 1] = '\0';
    
    file_info->file_size = file_stat.st_size;
    file_info->upload_time = time(NULL);
    
    // Compute file SHA1
    compute_file_sha1(filepath, file_info->file_sha1);
    
    // Calculate number of pieces
    file_info->total_pieces = (file_info->file_size + PIECE_SIZE - 1) / PIECE_SIZE;
    
    // Compute SHA1 for each piece
    for (int i = 0; i < file_info->total_pieces; i++) {
        file_info->pieces[i].piece_index = i;
        compute_piece_sha1(filepath, i, file_info->pieces[i].sha1);
        
        // Calculate piece size
        if (i == file_info->total_pieces - 1) {
            // Last piece might be smaller
            file_info->pieces[i].size = file_info->file_size - (i * PIECE_SIZE);
        } else {
            file_info->pieces[i].size = PIECE_SIZE;
        }
        
        file_info->pieces[i].is_downloaded = 1; // We have the full file
    }
    
    return 0;
}

int download_file_piece(const char* ip, int port, const char* filename, int piece_index, char* buffer, size_t* size) {
    int socket_fd = connect_to_server(ip, port);
    if (socket_fd < 0) {
        return -1;
    }
    
    // Send piece request
    message_t request;
    request.type = MSG_PIECE_REQUEST;
    snprintf(request.data, MAX_BUFFER_SIZE, "%s:%d", filename, piece_index);
    request.data_length = strlen(request.data);
    
    if (send_message(socket_fd, &request) < 0) {
        close_socket(socket_fd);
        return -1;
    }
    
    // Receive piece response
    message_t response;
    if (receive_message(socket_fd, &response) <= 0) {
        close_socket(socket_fd);
        return -1;
    }
    
    if (response.type != MSG_PIECE_RESPONSE) {
        close_socket(socket_fd);
        return -1;
    }
    
    // Copy piece data
    memcpy(buffer, response.data, response.data_length);
    *size = response.data_length;
    
    close_socket(socket_fd);
    return 0;
}

int verify_piece(const char* data, size_t size, const unsigned char* expected_hash) {
    unsigned char computed_hash[SHA1_DIGEST_LENGTH];
    compute_sha1(data, size, computed_hash);
    
    return memcmp(computed_hash, expected_hash, SHA1_DIGEST_LENGTH) == 0;
}

typedef struct {
    download_info_t* download;
    int piece_index;
    int peer_index;
} download_thread_arg_t;

void* download_thread_function(void* arg) {
    download_thread_arg_t* thread_arg = (download_thread_arg_t*)arg;
    download_info_t* download = thread_arg->download;
    int piece_index = thread_arg->piece_index;
    int peer_index = thread_arg->peer_index;
    
    char buffer[PIECE_SIZE];
    size_t piece_size;
    
    // Try to download the piece from the peer
    peer_info_t* peer = &download->peers[peer_index];
    
    if (download_file_piece(peer->ip, peer->port, download->filename, piece_index, buffer, &piece_size) == 0) {
        // Verify the piece
        if (verify_piece(buffer, piece_size, download->file_info.pieces[piece_index].sha1)) {
            // Write the piece to the file
            pthread_mutex_lock(&download->download_mutex);
            
            if (download->output_file != NULL) {
                fseek(download->output_file, piece_index * PIECE_SIZE, SEEK_SET);
                fwrite(buffer, 1, piece_size, download->output_file);
                fflush(download->output_file);
                
                download->file_info.pieces[piece_index].is_downloaded = 1;
                download->downloaded_pieces++;
                
                printf("Downloaded piece %d of %s (%d/%d completed)\n", 
                       piece_index, download->filename, 
                       download->downloaded_pieces, download->total_pieces);
            }
            
            pthread_mutex_unlock(&download->download_mutex);
        } else {
            printf("Piece %d verification failed, retrying with another peer\n", piece_index);
        }
    }
    
    free(thread_arg);
    return NULL;
}

int start_peer_server(client_state_t* client) {
    int socket_fd = create_socket();
    if (socket_fd < 0) {
        return -1;
    }
    
    // Bind to any available port
    if (bind_socket(socket_fd, "0.0.0.0", 0) < 0) {
        close_socket(socket_fd);
        return -1;
    }
    
    // Get the assigned port
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);
    if (getsockname(socket_fd, (struct sockaddr*)&addr, &addr_len) < 0) {
        perror("Failed to get socket name");
        close_socket(socket_fd);
        return -1;
    }
    
    client->peer_port = ntohs(addr.sin_port);
    client->peer_socket = socket_fd;
    
    if (listen_socket(socket_fd, 10) < 0) {
        close_socket(socket_fd);
        return -1;
    }
    
    printf("Peer server started on port %d\n", client->peer_port);
    return 0;
}

void* download_manager_thread(void* arg) {
    download_info_t* download = (download_info_t*)arg;
    
    // Open output file for writing
    download->output_file = fopen(download->destination, "wb");
    if (download->output_file == NULL) {
        perror("Failed to open output file");
        download->is_downloading = 0;
        return NULL;
    }
    
    // Pre-allocate the file
    if (fseek(download->output_file, download->file_info.file_size - 1, SEEK_SET) == 0) {
        fputc(0, download->output_file);
        fseek(download->output_file, 0, SEEK_SET);
    }
    
    // Implement rarest-first piece selection
    int* piece_availability = calloc(download->total_pieces, sizeof(int));
    
    // Count availability of each piece across peers
    for (int i = 0; i < download->peer_count; i++) {
        for (int j = 0; j < download->peers[i].piece_count; j++) {
            int piece_idx = download->peers[i].available_pieces[j];
            if (piece_idx < download->total_pieces) {
                piece_availability[piece_idx]++;
            }
        }
    }
    
    // Download pieces in rarest-first order
    while (download->downloaded_pieces < download->total_pieces && download->is_downloading) {
        int rarest_piece = -1;
        int min_availability = INT_MAX;
        
        // Find the rarest piece that we don't have yet
        for (int i = 0; i < download->total_pieces; i++) {
            if (!download->file_info.pieces[i].is_downloaded && 
                piece_availability[i] > 0 && 
                piece_availability[i] < min_availability) {
                min_availability = piece_availability[i];
                rarest_piece = i;
            }
        }
        
        if (rarest_piece == -1) {
            break; // No more pieces available
        }
        
        // Find a peer that has this piece
        for (int i = 0; i < download->peer_count; i++) {
            for (int j = 0; j < download->peers[i].piece_count; j++) {
                if (download->peers[i].available_pieces[j] == rarest_piece) {
                    // Start download thread for this piece
                    download_thread_arg_t* thread_arg = malloc(sizeof(download_thread_arg_t));
                    thread_arg->download = download;
                    thread_arg->piece_index = rarest_piece;
                    thread_arg->peer_index = i;
                    
                    pthread_t thread;
                    if (pthread_create(&thread, NULL, download_thread_function, thread_arg) == 0) {
                        pthread_detach(thread);
                        piece_availability[rarest_piece] = 0; // Mark as being downloaded
                    } else {
                        free(thread_arg);
                    }
                    break;
                }
            }
            if (piece_availability[rarest_piece] == 0) break;
        }
        
        usleep(100000); // Sleep for 100ms
    }
    
    free(piece_availability);
    
    if (download->downloaded_pieces == download->total_pieces) {
        download->is_complete = 1;
        printf("Download of %s completed successfully!\n", download->filename);
        
        // Verify the complete file
        unsigned char file_hash[SHA1_DIGEST_LENGTH];
        compute_file_sha1(download->destination, file_hash);
        
        if (memcmp(file_hash, download->file_info.file_sha1, SHA1_DIGEST_LENGTH) == 0) {
            printf("File integrity verified.\n");
        } else {
            printf("Warning: File integrity check failed!\n");
        }
    }
    
    download->is_downloading = 0;
    fclose(download->output_file);
    download->output_file = NULL;
    
    return NULL;
} 