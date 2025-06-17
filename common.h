#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>
#include <openssl/sha.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <readline/readline.h>
#include <readline/history.h>

// ANSI Color Codes for Terminal Aesthetics
#define RESET "\033[0m"
#define RED "\033[0;31m"
#define GREEN "\033[0;32m"
#define YELLOW "\033[0;33m"
#define BLUE "\033[0;34m"
#define MAGENTA "\033[0;35m"
#define CYAN "\033[0;36m"
#define WHITE "\033[0;37m"
#define BOLD "\033[1m"

// Constants
#define MAX_CLIENTS 100
#define MAX_GROUPS 50
#define MAX_FILES_PER_GROUP 100
#define MAX_PEERS_PER_FILE 50
#define MAX_TRACKERS 5
#define MAX_BUFFER_SIZE 4096
#define MAX_FILENAME_SIZE 256
#define MAX_PATH_SIZE 512
#define MAX_USERNAME_SIZE 64
#define MAX_PASSWORD_SIZE 64
#define MAX_GROUP_ID_SIZE 64
#define SHA1_DIGEST_LENGTH 20
#define PIECE_SIZE (512 * 1024) // 512KB pieces
#define MAX_PIECES 10000

// Message types
typedef enum {
    MSG_CREATE_USER = 1,
    MSG_LOGIN,
    MSG_CREATE_GROUP,
    MSG_JOIN_GROUP,
    MSG_LEAVE_GROUP,
    MSG_LIST_REQUESTS,
    MSG_ACCEPT_REQUEST,
    MSG_LIST_GROUPS,
    MSG_LIST_FILES,
    MSG_UPLOAD_FILE,
    MSG_DOWNLOAD_FILE,
    MSG_STOP_SHARE,
    MSG_LOGOUT,
    MSG_GET_PEERS,
    MSG_GET_FILE_INFO,
    MSG_PIECE_REQUEST,
    MSG_PIECE_RESPONSE,
    MSG_SUCCESS,
    MSG_ERROR,
    MSG_DEBUG_LIST_CLIENTS,
    MSG_DEBUG_LIST_GROUPS,
    MSG_DEBUG_LIST_FILES,
    MSG_DEBUG_SYNC_STATUS
} message_type_t;

// File piece information
typedef struct {
    int piece_index;
    unsigned char sha1[SHA1_DIGEST_LENGTH];
    size_t size;
    int is_downloaded;
} piece_info_t;

// File metadata
typedef struct {
    char filename[MAX_FILENAME_SIZE];
    char filepath[MAX_PATH_SIZE];
    off_t file_size;
    unsigned char file_sha1[SHA1_DIGEST_LENGTH];
    int total_pieces;
    piece_info_t pieces[MAX_PIECES];
    char group_id[MAX_GROUP_ID_SIZE];
    char uploader[MAX_USERNAME_SIZE];
    char uploader_ip[INET_ADDRSTRLEN];
    int uploader_port;
    time_t upload_time;
} file_info_t;

// User information
typedef struct {
    char user_id[MAX_USERNAME_SIZE];
    char password_hash[65]; // SHA256 hash string
    int is_online;
    char ip[INET_ADDRSTRLEN];
    int port;
    int socket_fd;
    time_t last_activity;
} user_info_t;

// Group member information
typedef struct {
    char user_id[MAX_USERNAME_SIZE];
    int is_pending;
} group_member_t;

// Group information
typedef struct {
    char group_id[MAX_GROUP_ID_SIZE];
    char owner[MAX_USERNAME_SIZE];
    group_member_t members[MAX_CLIENTS];
    int member_count;
    file_info_t files[MAX_FILES_PER_GROUP];
    int file_count;
    time_t created_time;
} group_info_t;

// Peer information
typedef struct {
    char user_id[MAX_USERNAME_SIZE];
    char ip[INET_ADDRSTRLEN];
    int port;
    int available_pieces[MAX_PIECES];
    int piece_count;
} peer_info_t;

// Download information
typedef struct {
    char filename[MAX_FILENAME_SIZE];
    char destination[MAX_PATH_SIZE];
    char group_id[MAX_GROUP_ID_SIZE];
    file_info_t file_info;
    peer_info_t peers[MAX_PEERS_PER_FILE];
    int peer_count;
    int downloaded_pieces;
    int total_pieces;
    int is_complete;
    int is_downloading;
    pthread_t download_threads[MAX_PEERS_PER_FILE];
    int active_threads;
    FILE* output_file;
    pthread_mutex_t download_mutex;
} download_info_t;

// Tracker information
typedef struct {
    char ip[INET_ADDRSTRLEN];
    int port;
    int is_active;
} tracker_info_t;

// Message structure
typedef struct {
    message_type_t type;
    char data[MAX_BUFFER_SIZE];
    int data_length;
} message_t;

// Global state structures
typedef struct {
    user_info_t users[MAX_CLIENTS];
    int user_count;
    group_info_t groups[MAX_GROUPS];
    int group_count;
    tracker_info_t trackers[MAX_TRACKERS];
    int tracker_count;
    int is_running;
    int verbose_mode;
    FILE* log_file;
    pthread_mutex_t state_mutex;
} tracker_state_t;

typedef struct {
    char user_id[MAX_USERNAME_SIZE];
    int is_logged_in;
    int tracker_socket;
    char tracker_ip[INET_ADDRSTRLEN];
    int tracker_port;
    tracker_info_t trackers[MAX_TRACKERS];
    int tracker_count;
    download_info_t downloads[MAX_FILES_PER_GROUP];
    int download_count;
    file_info_t shared_files[MAX_FILES_PER_GROUP];
    int shared_file_count;
    int is_running;
    int verbose_mode;
    FILE* log_file;
    pthread_mutex_t client_mutex;
    int peer_socket;
    int peer_port;
} client_state_t;

// Function declarations

// Networking functions
int create_socket();
int bind_socket(int socket_fd, const char* ip, int port);
int listen_socket(int socket_fd, int backlog);
int accept_connection(int socket_fd, char* client_ip, int* client_port);
int connect_to_server(const char* ip, int port);
int send_message(int socket_fd, const message_t* msg);
int receive_message(int socket_fd, message_t* msg);
void close_socket(int socket_fd);

// Utility functions
void compute_sha1(const char* data, size_t length, unsigned char* hash);
void compute_file_sha1(const char* filepath, unsigned char* hash);
void compute_piece_sha1(const char* filepath, int piece_index, unsigned char* hash);
char* sha1_to_string(const unsigned char* hash);
void string_to_sha1(const char* str, unsigned char* hash);
void log_message(FILE* log_file, int verbose, const char* format, ...);
void print_help(int is_tracker);
int parse_tracker_info(const char* filename, tracker_info_t* trackers, int* count);
void trim_string(char* str);
int validate_user_id(const char* user_id);
int validate_group_id(const char* group_id);

// Enhanced utility functions
void display_progress_bar(const char* operation, long long transferred, long long total);
int check_file_exists(const char* filepath);

// File handling functions
int upload_file_metadata(const char* filepath, const char* group_id, file_info_t* file_info);
int download_file_piece(const char* ip, int port, const char* filename, int piece_index, char* buffer, size_t* size);
int verify_piece(const char* data, size_t size, const unsigned char* expected_hash);
void* download_thread_function(void* arg);
int start_peer_server(client_state_t* client);

// Tracker functions
void handle_tracker_command(tracker_state_t* tracker, const char* command);
void* handle_client_connection(void* arg);
void process_client_message(tracker_state_t* tracker, int client_fd, const message_t* msg);
int find_user_by_id(const tracker_state_t* tracker, const char* user_id);
int find_group_by_id(const tracker_state_t* tracker, const char* group_id);
int add_user_to_group(tracker_state_t* tracker, const char* group_id, const char* user_id);
int remove_user_from_group(tracker_state_t* tracker, const char* group_id, const char* user_id);

// Client functions
void handle_client_command(client_state_t* client, const char* command);
int connect_to_tracker(client_state_t* client);
void* peer_server_thread(void* arg);
void handle_peer_connection(client_state_t* client, int peer_fd);

#endif // COMMON_H 