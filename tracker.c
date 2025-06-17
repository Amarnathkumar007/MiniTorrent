#include "common.h"

// Global tracker state
static tracker_state_t tracker_state;

// Signal handler for clean shutdown
void signal_handler(int signal) {
    printf("\nReceived signal %d, shutting down tracker...\n", signal);
    tracker_state.is_running = 0;
}

// Thread argument for client connection handler
typedef struct {
    int client_fd;
    char client_ip[INET_ADDRSTRLEN];
    int client_port;
} client_connection_arg_t;

int find_user_by_id(const tracker_state_t* tracker, const char* user_id) {
    for (int i = 0; i < tracker->user_count; i++) {
        if (strcmp(tracker->users[i].user_id, user_id) == 0) {
            return i;
        }
    }
    return -1;
}

int find_group_by_id(const tracker_state_t* tracker, const char* group_id) {
    for (int i = 0; i < tracker->group_count; i++) {
        if (strcmp(tracker->groups[i].group_id, group_id) == 0) {
            return i;
        }
    }
    return -1;
}

int add_user_to_group(tracker_state_t* tracker, const char* group_id, const char* user_id) {
    int group_idx = find_group_by_id(tracker, group_id);
    if (group_idx < 0) return -1;
    
    group_info_t* group = &tracker->groups[group_idx];
    
    // Check if user is already a member
    for (int i = 0; i < group->member_count; i++) {
        if (strcmp(group->members[i].user_id, user_id) == 0) {
            group->members[i].is_pending = 0; // Accept the user
            return 0;
        }
    }
    
    // Add new member
    if (group->member_count < MAX_CLIENTS) {
        strncpy(group->members[group->member_count].user_id, user_id, MAX_USERNAME_SIZE - 1);
        group->members[group->member_count].user_id[MAX_USERNAME_SIZE - 1] = '\0';
        group->members[group->member_count].is_pending = 0;
        group->member_count++;
        return 0;
    }
    
    return -1;
}

int remove_user_from_group(tracker_state_t* tracker, const char* group_id, const char* user_id) {
    int group_idx = find_group_by_id(tracker, group_id);
    if (group_idx < 0) return -1;
    
    group_info_t* group = &tracker->groups[group_idx];
    
    for (int i = 0; i < group->member_count; i++) {
        if (strcmp(group->members[i].user_id, user_id) == 0) {
            // Remove member by shifting array
            for (int j = i; j < group->member_count - 1; j++) {
                group->members[j] = group->members[j + 1];
            }
            group->member_count--;
            return 0;
        }
    }
    
    return -1;
}

void process_client_message(tracker_state_t* tracker, int client_fd, const message_t* msg) {
    message_t response;
    memset(&response, 0, sizeof(response));
    
    pthread_mutex_lock(&tracker->state_mutex);
    
    switch (msg->type) {
        case MSG_CREATE_USER: {
            char user_id[MAX_USERNAME_SIZE], password[MAX_PASSWORD_SIZE];
            if (sscanf(msg->data, "%63s %63s", user_id, password) == 2) {
                if (validate_user_id(user_id)) {
                    int user_idx = find_user_by_id(tracker, user_id);
                    if (user_idx < 0 && tracker->user_count < MAX_CLIENTS) {
                        // Create new user
                        strncpy(tracker->users[tracker->user_count].user_id, user_id, MAX_USERNAME_SIZE - 1);
                        strncpy(tracker->users[tracker->user_count].password_hash, password, 64);
                        tracker->users[tracker->user_count].is_online = 0;
                        tracker->users[tracker->user_count].socket_fd = -1;
                        tracker->user_count++;
                        
                        response.type = MSG_SUCCESS;
                        snprintf(response.data, MAX_BUFFER_SIZE, "User %s created successfully", user_id);
                        log_message(tracker->log_file, tracker->verbose_mode, "User %s created", user_id);
                    } else {
                        response.type = MSG_ERROR;
                        snprintf(response.data, MAX_BUFFER_SIZE, "User %s already exists or limit reached", user_id);
                    }
                } else {
                    response.type = MSG_ERROR;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Invalid user ID format");
                }
            } else {
                response.type = MSG_ERROR;
                snprintf(response.data, MAX_BUFFER_SIZE, "Invalid create_user format");
            }
            break;
        }
        
        case MSG_LOGIN: {
            char user_id[MAX_USERNAME_SIZE], password[MAX_PASSWORD_SIZE];
            if (sscanf(msg->data, "%63s %63s", user_id, password) == 2) {
                int user_idx = find_user_by_id(tracker, user_id);
                if (user_idx >= 0 && strcmp(tracker->users[user_idx].password_hash, password) == 0) {
                    tracker->users[user_idx].is_online = 1;
                    tracker->users[user_idx].socket_fd = client_fd;
                    tracker->users[user_idx].last_activity = time(NULL);
                    
                    response.type = MSG_SUCCESS;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Login successful");
                    log_message(tracker->log_file, tracker->verbose_mode, "User %s logged in", user_id);
                } else {
                    response.type = MSG_ERROR;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Invalid credentials");
                }
            } else {
                response.type = MSG_ERROR;
                snprintf(response.data, MAX_BUFFER_SIZE, "Invalid login format");
            }
            break;
        }
        
        case MSG_CREATE_GROUP: {
            char group_id[MAX_GROUP_ID_SIZE], user_id[MAX_USERNAME_SIZE];
            if (sscanf(msg->data, "%63s %63s", group_id, user_id) == 2) {
                if (validate_group_id(group_id)) {
                    int group_idx = find_group_by_id(tracker, group_id);
                    if (group_idx < 0 && tracker->group_count < MAX_GROUPS) {
                        // Create new group
                        strncpy(tracker->groups[tracker->group_count].group_id, group_id, MAX_GROUP_ID_SIZE - 1);
                        strncpy(tracker->groups[tracker->group_count].owner, user_id, MAX_USERNAME_SIZE - 1);
                        tracker->groups[tracker->group_count].member_count = 1;
                        strncpy(tracker->groups[tracker->group_count].members[0].user_id, user_id, MAX_USERNAME_SIZE - 1);
                        tracker->groups[tracker->group_count].members[0].is_pending = 0;
                        tracker->groups[tracker->group_count].file_count = 0;
                        tracker->groups[tracker->group_count].created_time = time(NULL);
                        tracker->group_count++;
                        
                        response.type = MSG_SUCCESS;
                        snprintf(response.data, MAX_BUFFER_SIZE, "Group %s created successfully", group_id);
                        log_message(tracker->log_file, tracker->verbose_mode, "Group %s created by %s", group_id, user_id);
                    } else {
                        response.type = MSG_ERROR;
                        snprintf(response.data, MAX_BUFFER_SIZE, "Group %s already exists or limit reached", group_id);
                    }
                } else {
                    response.type = MSG_ERROR;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Invalid group ID format");
                }
            } else {
                response.type = MSG_ERROR;
                snprintf(response.data, MAX_BUFFER_SIZE, "Invalid create_group format");
            }
            break;
        }
        
        case MSG_JOIN_GROUP: {
            char group_id[MAX_GROUP_ID_SIZE], user_id[MAX_USERNAME_SIZE];
            if (sscanf(msg->data, "%63s %63s", group_id, user_id) == 2) {
                int group_idx = find_group_by_id(tracker, group_id);
                if (group_idx >= 0) {
                    group_info_t* group = &tracker->groups[group_idx];
                    // Add user as pending member
                    if (group->member_count < MAX_CLIENTS) {
                        strncpy(group->members[group->member_count].user_id, user_id, MAX_USERNAME_SIZE - 1);
                        group->members[group->member_count].is_pending = 1;
                        group->member_count++;
                        
                        response.type = MSG_SUCCESS;
                        snprintf(response.data, MAX_BUFFER_SIZE, "Join request sent to group %s", group_id);
                        log_message(tracker->log_file, tracker->verbose_mode, "Join request from %s to group %s", user_id, group_id);
                    } else {
                        response.type = MSG_ERROR;
                        snprintf(response.data, MAX_BUFFER_SIZE, "Group %s is full", group_id);
                    }
                } else {
                    response.type = MSG_ERROR;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Group %s not found", group_id);
                }
            } else {
                response.type = MSG_ERROR;
                snprintf(response.data, MAX_BUFFER_SIZE, "Invalid join_group format");
            }
            break;
        }
        
        case MSG_LIST_GROUPS: {
            response.type = MSG_SUCCESS;
            char* ptr = response.data;
            int remaining = MAX_BUFFER_SIZE - 1;
            
            for (int i = 0; i < tracker->group_count && remaining > 0; i++) {
                int written = snprintf(ptr, remaining, "%s:%s\n", 
                                     tracker->groups[i].group_id, 
                                     tracker->groups[i].owner);
                if (written > 0 && written < remaining) {
                    ptr += written;
                    remaining -= written;
                }
            }
            break;
        }
        
        case MSG_LIST_FILES: {
            char group_id[MAX_GROUP_ID_SIZE];
            if (sscanf(msg->data, "%63s", group_id) == 1) {
                int group_idx = find_group_by_id(tracker, group_id);
                if (group_idx >= 0) {
                    response.type = MSG_SUCCESS;
                    char* ptr = response.data;
                    int remaining = MAX_BUFFER_SIZE - 1;
                    
                    group_info_t* group = &tracker->groups[group_idx];
                    for (int i = 0; i < group->file_count && remaining > 0; i++) {
                        int written = snprintf(ptr, remaining, "%s:%lld:%s\n",
                                             group->files[i].filename,
                                             (long long)group->files[i].file_size,
                                             sha1_to_string(group->files[i].file_sha1));
                        if (written > 0 && written < remaining) {
                            ptr += written;
                            remaining -= written;
                        }
                    }
                } else {
                    response.type = MSG_ERROR;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Group %s not found", group_id);
                }
            } else {
                response.type = MSG_ERROR;
                snprintf(response.data, MAX_BUFFER_SIZE, "Invalid list_files format");
            }
            break;
        }
        
        case MSG_GET_FILE_INFO: {
            // Handle request for detailed file info including peer details
            char group_id[MAX_GROUP_ID_SIZE], filename[MAX_FILENAME_SIZE];
            if (sscanf(msg->data, "%63[^:]:%255s", group_id, filename) == 2) {
                int group_idx = find_group_by_id(tracker, group_id);
                if (group_idx >= 0) {
                    group_info_t* group = &tracker->groups[group_idx];
                    int found = 0;
                    
                    for (int i = 0; i < group->file_count; i++) {
                        if (strcmp(group->files[i].filename, filename) == 0) {
                            file_info_t* file = &group->files[i];
                            response.type = MSG_SUCCESS;
                            
                            // Send complete file info: filename:size:sha1:uploader:ip:port:total_pieces
                            snprintf(response.data, MAX_BUFFER_SIZE, 
                                   "%s:%lld:%s:%s:%s:%d:%d",
                                   file->filename,
                                   (long long)file->file_size,
                                   sha1_to_string(file->file_sha1),
                                   file->uploader,
                                   file->uploader_ip,
                                   file->uploader_port,
                                   file->total_pieces);
                            found = 1;
                            break;
                        }
                    }
                    
                    if (!found) {
                        response.type = MSG_ERROR;
                        snprintf(response.data, MAX_BUFFER_SIZE, "File %s not found in group %s", filename, group_id);
                    }
                } else {
                    response.type = MSG_ERROR;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Group %s not found", group_id);
                }
            } else {
                response.type = MSG_ERROR;
                snprintf(response.data, MAX_BUFFER_SIZE, "Invalid get_file_info format");
            }
            break;
        }
        
        case MSG_UPLOAD_FILE: {
            // Handle file upload metadata
            char filename[MAX_FILENAME_SIZE], group_id[MAX_GROUP_ID_SIZE], uploader[MAX_USERNAME_SIZE];
            char sha1_str[41], uploader_ip[INET_ADDRSTRLEN];
            long long file_size;
            int uploader_port, total_pieces;
            
            if (sscanf(msg->data, "%255[^:]:%63[^:]:%lld:%40[^:]:%63[^:]:%15[^:]:%d:%d", 
                      filename, group_id, &file_size, sha1_str, uploader, uploader_ip, &uploader_port, &total_pieces) == 8) {
                
                int group_idx = find_group_by_id(tracker, group_id);
                if (group_idx >= 0) {
                    group_info_t* group = &tracker->groups[group_idx];
                    if (group->file_count < MAX_FILES_PER_GROUP) {
                        file_info_t* file_info = &group->files[group->file_count];
                        strncpy(file_info->filename, filename, MAX_FILENAME_SIZE - 1);
                        file_info->filename[MAX_FILENAME_SIZE - 1] = '\0';
                        strncpy(file_info->group_id, group_id, MAX_GROUP_ID_SIZE - 1);
                        file_info->group_id[MAX_GROUP_ID_SIZE - 1] = '\0';
                        strncpy(file_info->uploader, uploader, MAX_USERNAME_SIZE - 1);
                        file_info->uploader[MAX_USERNAME_SIZE - 1] = '\0';
                        file_info->file_size = file_size;
                        string_to_sha1(sha1_str, file_info->file_sha1);
                        strncpy(file_info->uploader_ip, uploader_ip, INET_ADDRSTRLEN - 1);
                        file_info->uploader_ip[INET_ADDRSTRLEN - 1] = '\0';
                        file_info->uploader_port = uploader_port;
                        file_info->total_pieces = total_pieces;
                        file_info->upload_time = time(NULL);
                        group->file_count++;
                        
                        response.type = MSG_SUCCESS;
                        snprintf(response.data, MAX_BUFFER_SIZE, "File %s uploaded to group %s", 
                               filename, group_id);
                        log_message(tracker->log_file, tracker->verbose_mode, 
                                  "File %s uploaded by %s to group %s", 
                                  filename, uploader, group_id);
                    } else {
                        response.type = MSG_ERROR;
                        snprintf(response.data, MAX_BUFFER_SIZE, "Group %s file limit reached", group_id);
                    }
                } else {
                    response.type = MSG_ERROR;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Group %s not found", group_id);
                }
            } else {
                response.type = MSG_ERROR;
                snprintf(response.data, MAX_BUFFER_SIZE, "Invalid upload file format");
            }
            break;
        }
        
        case MSG_LIST_REQUESTS: {
            char group_id[MAX_GROUP_ID_SIZE], requesting_user[MAX_USERNAME_SIZE];
            if (sscanf(msg->data, "%63s %63s", group_id, requesting_user) == 2) {
                int group_idx = find_group_by_id(tracker, group_id);
                if (group_idx >= 0) {
                    group_info_t* group = &tracker->groups[group_idx];
                    // Check if user is the group owner
                    if (strcmp(group->owner, requesting_user) == 0) {
                        response.type = MSG_SUCCESS;
                        char* ptr = response.data;
                        int remaining = MAX_BUFFER_SIZE - 1;
                        
                        for (int i = 0; i < group->member_count && remaining > 0; i++) {
                            if (group->members[i].is_pending) {
                                int written = snprintf(ptr, remaining, "%s\n", 
                                                     group->members[i].user_id);
                                if (written > 0 && written < remaining) {
                                    ptr += written;
                                    remaining -= written;
                                }
                            }
                        }
                        log_message(tracker->log_file, tracker->verbose_mode, 
                                  "Listed pending requests for group %s to owner %s", 
                                  group_id, requesting_user);
                    } else {
                        response.type = MSG_ERROR;
                        snprintf(response.data, MAX_BUFFER_SIZE, "You are not the owner of group %s", group_id);
                    }
                } else {
                    response.type = MSG_ERROR;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Group %s not found", group_id);
                }
            } else {
                response.type = MSG_ERROR;
                snprintf(response.data, MAX_BUFFER_SIZE, "Invalid list_requests format");
            }
            break;
        }
        
        case MSG_ACCEPT_REQUEST: {
            char group_id[MAX_GROUP_ID_SIZE], user_to_accept[MAX_USERNAME_SIZE], owner[MAX_USERNAME_SIZE];
            if (sscanf(msg->data, "%63s %63s %63s", group_id, user_to_accept, owner) == 3) {
                int group_idx = find_group_by_id(tracker, group_id);
                if (group_idx >= 0) {
                    group_info_t* group = &tracker->groups[group_idx];
                    // Check if user is the group owner
                    if (strcmp(group->owner, owner) == 0) {
                        // Find and accept the pending user
                        int found = 0;
                        for (int i = 0; i < group->member_count; i++) {
                            if (strcmp(group->members[i].user_id, user_to_accept) == 0 && 
                                group->members[i].is_pending) {
                                group->members[i].is_pending = 0; // Accept the user
                                found = 1;
                                break;
                            }
                        }
                        
                        if (found) {
                            response.type = MSG_SUCCESS;
                            snprintf(response.data, MAX_BUFFER_SIZE, 
                                   "User %s accepted into group %s", user_to_accept, group_id);
                            log_message(tracker->log_file, tracker->verbose_mode, 
                                      "User %s accepted into group %s by owner %s", 
                                      user_to_accept, group_id, owner);
                        } else {
                            response.type = MSG_ERROR;
                            snprintf(response.data, MAX_BUFFER_SIZE, 
                                   "No pending request from user %s for group %s", user_to_accept, group_id);
                        }
                    } else {
                        response.type = MSG_ERROR;
                        snprintf(response.data, MAX_BUFFER_SIZE, "You are not the owner of group %s", group_id);
                    }
                } else {
                    response.type = MSG_ERROR;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Group %s not found", group_id);
                }
            } else {
                response.type = MSG_ERROR;
                snprintf(response.data, MAX_BUFFER_SIZE, "Invalid accept_request format");
            }
            break;
        }
        
        case MSG_LEAVE_GROUP: {
            char group_id[MAX_GROUP_ID_SIZE], user_id[MAX_USERNAME_SIZE];
            if (sscanf(msg->data, "%63s %63s", group_id, user_id) == 2) {
                if (remove_user_from_group(tracker, group_id, user_id) == 0) {
                    response.type = MSG_SUCCESS;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Left group %s successfully", group_id);
                    log_message(tracker->log_file, tracker->verbose_mode, "User %s left group %s", user_id, group_id);
                } else {
                    response.type = MSG_ERROR;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Failed to leave group %s or not a member", group_id);
                }
            } else {
                response.type = MSG_ERROR;
                snprintf(response.data, MAX_BUFFER_SIZE, "Invalid leave_group format");
            }
            break;
        }
        
        case MSG_STOP_SHARE: {
            char group_id[MAX_GROUP_ID_SIZE], filename[MAX_FILENAME_SIZE], user_id[MAX_USERNAME_SIZE];
            if (sscanf(msg->data, "%63s %255s %63s", group_id, filename, user_id) == 3) {
                int group_idx = find_group_by_id(tracker, group_id);
                if (group_idx >= 0) {
                    group_info_t* group = &tracker->groups[group_idx];
                    // Find and remove the file
                    int found = 0;
                    for (int i = 0; i < group->file_count; i++) {
                        if (strcmp(group->files[i].filename, filename) == 0 &&
                            strcmp(group->files[i].uploader, user_id) == 0) {
                            // Remove file by shifting array
                            for (int j = i; j < group->file_count - 1; j++) {
                                group->files[j] = group->files[j + 1];
                            }
                            group->file_count--;
                            found = 1;
                            break;
                        }
                    }
                    
                    if (found) {
                        response.type = MSG_SUCCESS;
                        snprintf(response.data, MAX_BUFFER_SIZE, 
                               "Stopped sharing file %s from group %s", filename, group_id);
                        log_message(tracker->log_file, tracker->verbose_mode, 
                                  "User %s stopped sharing file %s from group %s", 
                                  user_id, filename, group_id);
                    } else {
                        response.type = MSG_ERROR;
                        snprintf(response.data, MAX_BUFFER_SIZE, 
                               "File %s not found or you are not the uploader", filename);
                    }
                } else {
                    response.type = MSG_ERROR;
                    snprintf(response.data, MAX_BUFFER_SIZE, "Group %s not found", group_id);
                }
            } else {
                response.type = MSG_ERROR;
                snprintf(response.data, MAX_BUFFER_SIZE, "Invalid stop_share format");
            }
            break;
        }
        
        case MSG_DEBUG_LIST_CLIENTS: {
            response.type = MSG_SUCCESS;
            char* ptr = response.data;
            int remaining = MAX_BUFFER_SIZE - 1;
            
            for (int i = 0; i < tracker->user_count && remaining > 0; i++) {
                int written = snprintf(ptr, remaining, "%s:%s\n", 
                                     tracker->users[i].user_id,
                                     tracker->users[i].is_online ? "ONLINE" : "OFFLINE");
                if (written > 0 && written < remaining) {
                    ptr += written;
                    remaining -= written;
                }
            }
            break;
        }
        
        default:
            response.type = MSG_ERROR;
            snprintf(response.data, MAX_BUFFER_SIZE, "Unknown message type");
            break;
    }
    
    pthread_mutex_unlock(&tracker->state_mutex);
    
    response.data_length = strlen(response.data);
    send_message(client_fd, &response);
}

void* handle_client_connection(void* arg) {
    client_connection_arg_t* conn_arg = (client_connection_arg_t*)arg;
    int client_fd = conn_arg->client_fd;
    char client_ip[INET_ADDRSTRLEN];
    strcpy(client_ip, conn_arg->client_ip);
    int client_port = conn_arg->client_port;
    free(conn_arg);
    
    log_message(tracker_state.log_file, tracker_state.verbose_mode, 
                "Client connected from %s:%d", client_ip, client_port);
    
    message_t msg;
    while (tracker_state.is_running) {
        int result = receive_message(client_fd, &msg);
        if (result <= 0) {
            break; // Connection closed or error
        }
        
        process_client_message(&tracker_state, client_fd, &msg);
    }
    
    log_message(tracker_state.log_file, tracker_state.verbose_mode, 
                "Client disconnected from %s:%d", client_ip, client_port);
    
    close_socket(client_fd);
    return NULL;
}

void handle_tracker_command(tracker_state_t* tracker, const char* command) {
    char cmd[256];
    strncpy(cmd, command, sizeof(cmd) - 1);
    cmd[sizeof(cmd) - 1] = '\0';
    trim_string(cmd);
    
    if (strcmp(cmd, "help") == 0) {
        print_help(1);
    } else if (strcmp(cmd, "quit") == 0) {
        printf("Shutting down tracker...\n");
        tracker->is_running = 0;
    } else if (strcmp(cmd, "list_clients") == 0) {
        printf("\n=== REGISTERED CLIENTS ===\n");
        for (int i = 0; i < tracker->user_count; i++) {
            printf("%s - %s\n", tracker->users[i].user_id, 
                   tracker->users[i].is_online ? "ONLINE" : "OFFLINE");
        }
        printf("Total: %d clients\n\n", tracker->user_count);
    } else if (strcmp(cmd, "list_groups") == 0) {
        printf("\n=== GROUPS ===\n");
        for (int i = 0; i < tracker->group_count; i++) {
            printf("Group: %s (Owner: %s, Members: %d)\n", 
                   tracker->groups[i].group_id, 
                   tracker->groups[i].owner,
                   tracker->groups[i].member_count);
        }
        printf("Total: %d groups\n\n", tracker->group_count);
    } else if (strncmp(cmd, "list_files ", 11) == 0) {
        char group_id[MAX_GROUP_ID_SIZE];
        if (sscanf(cmd + 11, "%63s", group_id) == 1) {
            int group_idx = find_group_by_id(tracker, group_id);
            if (group_idx >= 0) {
                printf("\n=== FILES IN GROUP %s ===\n", group_id);
                group_info_t* group = &tracker->groups[group_idx];
                for (int i = 0; i < group->file_count; i++) {
                    printf("%s (Size: %lld bytes, SHA1: %s)\n",
                           group->files[i].filename,
                           (long long)group->files[i].file_size,
                           sha1_to_string(group->files[i].file_sha1));
                }
                printf("Total: %d files\n\n", group->file_count);
            } else {
                printf("Group %s not found\n", group_id);
            }
        } else {
            printf("Usage: list_files <group_id>\n");
        }
    } else if (strcmp(cmd, "sync_status") == 0) {
        printf("\n=== SYNCHRONIZATION STATUS ===\n");
        printf("Tracker is running independently\n");
        printf("Last activity: %s", ctime(&tracker->users[0].last_activity));
        printf("\n");
    } else if (strcmp(cmd, "verbose") == 0) {
        tracker->verbose_mode = !tracker->verbose_mode;
        printf("Verbose mode: %s\n", tracker->verbose_mode ? "ON" : "OFF");
    } else {
        printf("Unknown command: %s\nType 'help' for available commands.\n", cmd);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: %s <tracker_info.txt> <tracker_no>\n", argv[0]);
        return 1;
    }
    
    // Initialize tracker state
    memset(&tracker_state, 0, sizeof(tracker_state));
    tracker_state.is_running = 1;
    tracker_state.verbose_mode = 1;
    
    // Initialize mutex
    if (pthread_mutex_init(&tracker_state.state_mutex, NULL) != 0) {
        perror("Failed to initialize mutex");
        return 1;
    }
    
    // Open log file
    tracker_state.log_file = fopen("tracker.log", "a");
    if (tracker_state.log_file == NULL) {
        perror("Failed to open log file");
    }
    
    // Parse tracker info
    int tracker_count;
    if (parse_tracker_info(argv[1], tracker_state.trackers, &tracker_count) < 0) {
        fprintf(stderr, "Failed to parse tracker_info.txt\n");
        return 1;
    }
    
    tracker_state.tracker_count = tracker_count;
    int tracker_no = atoi(argv[2]);
    
    if (tracker_no < 1 || tracker_no > tracker_count) {
        fprintf(stderr, "Invalid tracker number: %d\n", tracker_no);
        return 1;
    }
    
    tracker_info_t* my_tracker = &tracker_state.trackers[tracker_no - 1];
    
    // Set up signal handlers
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    // Create and bind socket
    int server_socket = create_socket();
    if (server_socket < 0) {
        return 1;
    }
    
    if (bind_socket(server_socket, my_tracker->ip, my_tracker->port) < 0) {
        close_socket(server_socket);
        return 1;
    }
    
    if (listen_socket(server_socket, 10) < 0) {
        close_socket(server_socket);
        return 1;
    }
    
    printf("Tracker started on %s:%d\n", my_tracker->ip, my_tracker->port);
    printf("Type 'help' for available commands.\n");
    
    log_message(tracker_state.log_file, tracker_state.verbose_mode, 
                "Tracker started on %s:%d", my_tracker->ip, my_tracker->port);
    
    // Set up select for handling both client connections and stdin
    fd_set master_fds, read_fds;
    FD_ZERO(&master_fds);
    FD_SET(server_socket, &master_fds);
    FD_SET(STDIN_FILENO, &master_fds);
    
    int max_fd = server_socket;
    
    while (tracker_state.is_running) {
        read_fds = master_fds;
        
        struct timeval timeout = {1, 0}; // 1 second timeout
        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        
        if (activity < 0) {
            if (errno != EINTR) {
                perror("select error");
                break;
            }
            continue;
        }
        
        // Check for new client connections
        if (FD_ISSET(server_socket, &read_fds)) {
            char client_ip[INET_ADDRSTRLEN];
            int client_port;
            int client_fd = accept_connection(server_socket, client_ip, &client_port);
            
            if (client_fd >= 0) {
                client_connection_arg_t* conn_arg = malloc(sizeof(client_connection_arg_t));
                conn_arg->client_fd = client_fd;
                strcpy(conn_arg->client_ip, client_ip);
                conn_arg->client_port = client_port;
                
                pthread_t client_thread;
                if (pthread_create(&client_thread, NULL, handle_client_connection, conn_arg) == 0) {
                    pthread_detach(client_thread);
                } else {
                    free(conn_arg);
                    close_socket(client_fd);
                }
            }
        }
        
        // Check for commands from stdin
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            char command[256];
            if (fgets(command, sizeof(command), stdin) != NULL) {
                command[strcspn(command, "\n")] = '\0'; // Remove newline
                handle_tracker_command(&tracker_state, command);
            }
        }
    }
    
    // Cleanup
    close_socket(server_socket);
    
    if (tracker_state.log_file != NULL) {
        fclose(tracker_state.log_file);
    }
    
    pthread_mutex_destroy(&tracker_state.state_mutex);
    
    printf("Tracker stopped.\n");
    return 0;
} 