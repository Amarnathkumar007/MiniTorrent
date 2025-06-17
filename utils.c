#include "common.h"
#include <stdarg.h>
#include <ctype.h>

void compute_sha1(const char* data, size_t length, unsigned char* hash) {
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, data, length);
    SHA1_Final(hash, &ctx);
}

void compute_file_sha1(const char* filepath, unsigned char* hash) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file for SHA1 computation");
        memset(hash, 0, SHA1_DIGEST_LENGTH);
        return;
    }
    
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    
    char buffer[8192];
    ssize_t bytes_read;
    
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
        SHA1_Update(&ctx, buffer, bytes_read);
    }
    
    SHA1_Final(hash, &ctx);
    close(fd);
}

void compute_piece_sha1(const char* filepath, int piece_index, unsigned char* hash) {
    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file for piece SHA1 computation");
        memset(hash, 0, SHA1_DIGEST_LENGTH);
        return;
    }
    
    // Seek to the piece position
    off_t offset = (off_t)piece_index * PIECE_SIZE;
    if (lseek(fd, offset, SEEK_SET) < 0) {
        perror("Failed to seek to piece position");
        memset(hash, 0, SHA1_DIGEST_LENGTH);
        close(fd);
        return;
    }
    
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    
    char buffer[8192];
    ssize_t bytes_read;
    size_t total_read = 0;
    
    while (total_read < PIECE_SIZE && (bytes_read = read(fd, buffer, 
          (PIECE_SIZE - total_read < sizeof(buffer)) ? PIECE_SIZE - total_read : sizeof(buffer))) > 0) {
        SHA1_Update(&ctx, buffer, bytes_read);
        total_read += bytes_read;
    }
    
    SHA1_Final(hash, &ctx);
    close(fd);
}

char* sha1_to_string(const unsigned char* hash) {
    static char hex_string[41];
    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        sprintf(hex_string + i * 2, "%02x", hash[i]);
    }
    hex_string[40] = '\0';
    return hex_string;
}

void string_to_sha1(const char* str, unsigned char* hash) {
    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++) {
        sscanf(str + i * 2, "%2hhx", &hash[i]);
    }
}

void log_message(FILE* log_file, int verbose, const char* format, ...) {
    va_list args;
    char timestamp[64];
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    if (verbose) {
        printf("[%s] ", timestamp);
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
        printf("\n");
        fflush(stdout);
    }
    
    if (log_file != NULL) {
        fprintf(log_file, "[%s] ", timestamp);
        va_start(args, format);
        vfprintf(log_file, format, args);
        va_end(args);
        fprintf(log_file, "\n");
        fflush(log_file);
    }
}

void print_help(int is_tracker) {
    if (is_tracker) {
        printf("\n%s=== TRACKER COMMANDS ===%s\n", CYAN, RESET);
        printf("%shelp%s                           - Show this help message\n", YELLOW, RESET);
        printf("%squit%s                           - Stop the tracker and exit\n", YELLOW, RESET);
        printf("%slist_clients%s                   - List all registered clients\n", YELLOW, RESET);
        printf("%slist_groups%s                    - List all groups\n", YELLOW, RESET);
        printf("%slist_files%s <group_id>          - List files in a group\n", YELLOW, RESET);
        printf("%ssync_status%s                    - Show tracker synchronization status\n", YELLOW, RESET);
        printf("%sverbose%s                        - Toggle verbose mode\n", YELLOW, RESET);
        printf("\n%sExample usage:%s\n", GREEN, RESET);
        printf("./tracker tracker_info.txt 1\n");
        printf("\n");
    } else {
        printf("\n%s=== CLIENT COMMANDS ===%s\n", CYAN, RESET);
        printf("%shelp%s                                              - Show this help message\n", YELLOW, RESET);
        printf("%screate_user%s <user_id> <passwd>                    - Register a new user\n", YELLOW, RESET);
        printf("%slogin%s <user_id> <passwd>                          - Login to the system\n", YELLOW, RESET);
        printf("%screate_group%s <group_id>                           - Create a new group\n", YELLOW, RESET);
        printf("%sjoin_group%s <group_id>                             - Request to join a group\n", YELLOW, RESET);
        printf("%sleave_group%s <group_id>                            - Leave a group\n", YELLOW, RESET);
        printf("%slist_requests%s <group_id>                          - List pending join requests (owner only)\n", YELLOW, RESET);
        printf("%saccept_request%s <group_id> <user_id>               - Accept a join request (owner only)\n", YELLOW, RESET);
        printf("%slist_groups%s                                       - List all groups\n", YELLOW, RESET);
        printf("%slist_files%s <group_id>                             - List files in a group\n", YELLOW, RESET);
        printf("%supload_file%s <file_path> <group_id>                - Share a file with a group\n", YELLOW, RESET);
        printf("%sdownload_file%s <group_id> <file_name> <dest_path>  - Download a file\n", YELLOW, RESET);
        printf("%sshow_downloads%s                                    - Show download status\n", YELLOW, RESET);
        printf("%sstop_share%s <group_id> <file_name>                 - Stop sharing a file\n", YELLOW, RESET);
        printf("%slogout%s                                            - Logout from the system\n", YELLOW, RESET);
        printf("%slist_shared_files%s                                 - List files being shared\n", YELLOW, RESET);
        printf("%slist_peers%s <file_name>                            - List peers sharing a file\n", YELLOW, RESET);
        printf("%sdownload_progress%s <file_name>                     - Show download progress\n", YELLOW, RESET);
        printf("%sverbose%s                                           - Toggle verbose mode\n", YELLOW, RESET);
        printf("\n%sExample usage:%s\n", GREEN, RESET);
        printf("./client 127.0.0.1:8080 tracker_info.txt\n");
        printf("\n");
    }
}

int parse_tracker_info(const char* filename, tracker_info_t* trackers, int* count) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open tracker_info.txt");
        return -1;
    }
    
    char buffer[4096];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    close(fd);
    
    if (bytes_read <= 0) {
        fprintf(stderr, "Failed to read tracker_info.txt\n");
        return -1;
    }
    
    buffer[bytes_read] = '\0';
    *count = 0;
    
    char* line = strtok(buffer, "\n\r");
    while (line != NULL && *count < MAX_TRACKERS) {
        trim_string(line);
        if (strlen(line) > 0 && line[0] != '#') {
            char* colon = strchr(line, ':');
            if (colon != NULL) {
                *colon = '\0';
                strncpy(trackers[*count].ip, line, INET_ADDRSTRLEN - 1);
                trackers[*count].ip[INET_ADDRSTRLEN - 1] = '\0';
                trackers[*count].port = atoi(colon + 1);
                trackers[*count].is_active = 1;
                (*count)++;
            }
        }
        line = strtok(NULL, "\n\r");
    }
    
    return *count > 0 ? 0 : -1;
}

void trim_string(char* str) {
    if (str == NULL) return;
    
    // Trim leading whitespace
    char* start = str;
    while (isspace(*start)) start++;
    
    // Trim trailing whitespace
    char* end = str + strlen(str) - 1;
    while (end > start && isspace(*end)) end--;
    
    // Move trimmed string to beginning and null terminate
    size_t len = end - start + 1;
    memmove(str, start, len);
    str[len] = '\0';
}

int validate_user_id(const char* user_id) {
    if (user_id == NULL || strlen(user_id) == 0 || strlen(user_id) >= MAX_USERNAME_SIZE) {
        return 0;
    }
    
    // Check for valid characters (alphanumeric and underscore only)
    for (int i = 0; user_id[i] != '\0'; i++) {
        if (!isalnum(user_id[i]) && user_id[i] != '_') {
            return 0;
        }
    }
    
    return 1;
}

int validate_group_id(const char* group_id) {
    if (group_id == NULL || strlen(group_id) == 0 || strlen(group_id) >= MAX_GROUP_ID_SIZE) {
        return 0;
    }
    
    // Check for valid characters (alphanumeric and underscore only)
    for (int i = 0; group_id[i] != '\0'; i++) {
        if (!isalnum(group_id[i]) && group_id[i] != '_') {
            return 0;
        }
    }
    
    return 1;
}

// Enhanced utility functions
void display_progress_bar(const char* operation, long long transferred, long long total) {
    if (total <= 0) return;
    
    int percentage = (int)((transferred * 100) / total);
    int bar_width = 40;
    int filled = (percentage * bar_width) / 100;
    
    printf("\r%s%s%s: [", CYAN, operation, RESET);
    for (int i = 0; i < bar_width; i++) {
        if (i < filled) {
            printf("%s#%s", GREEN, RESET);
        } else {
            printf(" ");
        }
    }
    printf("] %s%d%%%s (%lld/%lld bytes)", 
           YELLOW, percentage, RESET, transferred, total);
    fflush(stdout);
    
    if (percentage >= 100) {
        printf("\n");
    }
}

int check_file_exists(const char* filepath) {
    if (access(filepath, F_OK) != 0) {
        printf("%sError: No such file or directory: %s%s\n", RED, filepath, RESET);
        return 0;
    }
    return 1;
} 