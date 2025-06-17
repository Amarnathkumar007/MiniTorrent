#include "common.h"

int create_socket() {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("socket() failed");
        return -1;
    }
    
    // Set socket options to reuse address
    int opt = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt() failed");
        close(socket_fd);
        return -1;
    }
    
    return socket_fd;
}

int bind_socket(int socket_fd, const char* ip, int port) {
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    if (ip == NULL || strcmp(ip, "0.0.0.0") == 0) {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
            fprintf(stderr, "Invalid IP address: %s\n", ip);
            return -1;
        }
    }
    
    if (bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind() failed");
        return -1;
    }
    
    return 0;
}

int listen_socket(int socket_fd, int backlog) {
    if (listen(socket_fd, backlog) < 0) {
        perror("listen() failed");
        return -1;
    }
    return 0;
}

int accept_connection(int socket_fd, char* client_ip, int* client_port) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    int client_fd = accept(socket_fd, (struct sockaddr*)&client_addr, &addr_len);
    if (client_fd < 0) {
        perror("accept() failed");
        return -1;
    }
    
    if (client_ip != NULL) {
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    }
    
    if (client_port != NULL) {
        *client_port = ntohs(client_addr.sin_port);
    }
    
    return client_fd;
}

int connect_to_server(const char* ip, int port) {
    int socket_fd = create_socket();
    if (socket_fd < 0) {
        return -1;
    }
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, ip, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Invalid IP address: %s\n", ip);
        close(socket_fd);
        return -1;
    }
    
    if (connect(socket_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect() failed");
        close(socket_fd);
        return -1;
    }
    
    return socket_fd;
}

int send_message(int socket_fd, const message_t* msg) {
    if (msg == NULL) {
        return -1;
    }
    
    // Send message type first
    ssize_t bytes_sent = write(socket_fd, &msg->type, sizeof(msg->type));
    if (bytes_sent != sizeof(msg->type)) {
        perror("Failed to send message type");
        return -1;
    }
    
    // Send data length
    bytes_sent = write(socket_fd, &msg->data_length, sizeof(msg->data_length));
    if (bytes_sent != sizeof(msg->data_length)) {
        perror("Failed to send data length");
        return -1;
    }
    
    // Send data if present
    if (msg->data_length > 0) {
        bytes_sent = write(socket_fd, msg->data, msg->data_length);
        if (bytes_sent != msg->data_length) {
            perror("Failed to send message data");
            return -1;
        }
    }
    
    return 0;
}

int receive_message(int socket_fd, message_t* msg) {
    if (msg == NULL) {
        return -1;
    }
    
    // Receive message type
    ssize_t bytes_received = read(socket_fd, &msg->type, sizeof(msg->type));
    if (bytes_received != sizeof(msg->type)) {
        if (bytes_received == 0) {
            return 0; // Connection closed
        }
        perror("Failed to receive message type");
        return -1;
    }
    
    // Receive data length
    bytes_received = read(socket_fd, &msg->data_length, sizeof(msg->data_length));
    if (bytes_received != sizeof(msg->data_length)) {
        perror("Failed to receive data length");
        return -1;
    }
    
    // Validate data length
    if (msg->data_length < 0 || msg->data_length > MAX_BUFFER_SIZE) {
        fprintf(stderr, "Invalid data length: %d\n", msg->data_length);
        return -1;
    }
    
    // Receive data if present
    if (msg->data_length > 0) {
        bytes_received = read(socket_fd, msg->data, msg->data_length);
        if (bytes_received != msg->data_length) {
            perror("Failed to receive message data");
            return -1;
        }
    }
    
    // Null-terminate the data for safety
    if (msg->data_length < MAX_BUFFER_SIZE) {
        msg->data[msg->data_length] = '\0';
    }
    
    return 1;
}

void close_socket(int socket_fd) {
    if (socket_fd >= 0) {
        close(socket_fd);
    }
} 