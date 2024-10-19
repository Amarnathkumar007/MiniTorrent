#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <bits/stdc++.h>
#include <filesystem>
#include <openssl/sha.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <thread>
#include <mutex>

#define CHUNK_SIZE (512 * 1024) // 512 KB

using namespace std;

string client_IP;
string client_PORT;
int client_fd;
int status, valread;
char cwd[1024];

mutex cout_mutex; // Mutex for synchronized console output
/**
 * @brief sends the message to client or the given socket
 *
 * @param message
 * @param print_statement
 * @param new_socket
 */
void send_message_to_client(string message, string print_statement, int new_socket)
{
    lock_guard<mutex> lock(cout_mutex);
    cout << print_statement << endl;
    send(new_socket, message.c_str(), message.size(), 0);
}
/**
 * @brief Get the command object breaks the string command wherer spaces
 *
 * @param command_vec
 * @param command
 */
void get_command(vector<string> &command_vec, string command)
{
    istringstream iss(command);
    string word;
    while (iss >> word)
    {
        command_vec.push_back(word);
    }
}
/**
 * @brief This function takes string as input and returns hash of the input in hexadecimal
 *
 * @param str
 * @return string
 */
string hash_function(const string &str)
{
    const unsigned char *unsigned_str = reinterpret_cast<const unsigned char *>(str.c_str());

    unsigned char hash[SHA_DIGEST_LENGTH]; // SHA_DIGEST_LENGTH is 20
    SHA1(unsigned_str, str.size(), hash);

    // Convert hash to a readable hexadecimal string
    string hash_string;
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
    {
        char buffer[3];
        snprintf(buffer, sizeof(buffer), "%02x", hash[i]);
        hash_string += buffer;
    }

    return hash_string.substr(0, 40); // Return the resulting hash as a hex string
}
/**
 * @param file_path
 * @return string hash of the given file path at ones i.e done by readin in chunks
 */
string get_hash(string file_path)
{
    int fd_read = open(file_path.c_str(), O_RDONLY);
    if (fd_read == -1)
    {
        perror("Error opening file");
        return "";
    }

    string hash_string = "";
    char data[CHUNK_SIZE];
    ssize_t bytesRead;

    while ((bytesRead = read(fd_read, data, CHUNK_SIZE)) > 0)
    {
        string str(data, bytesRead);
        hash_string += hash_function(str);
    }

    if (bytesRead == -1)
    {
        perror("Error reading file");
    }

    close(fd_read);
    return hash_string;
}
/**
 * @brief splits the command whereever whitespace encountered in command string
 *
 * @param command
 * @param command_vec
 */
void split(string command, vector<string> &command_vec)
{
    istringstream iss(command);
    string word;
    while (iss >> word)
    {
        command_vec.push_back(word);
    }
}
/**
 * @brief Get the file size object return the size of file
 *
 * @param path
 * @return long long
 */
long long get_file_size(string path)
{
    namespace fs = std::filesystem;
    fs::path filePath = path;
    if (!fs::exists(path))
    {
        // Path does not exist
        cout << "Path does not exist\n";
        return 0;
    }

    return filesystem::file_size(filePath);
}
/**
 * @brief checks if the file exist or not
 *
 * @param file_name
 * @return true
 * @return false
 */
bool is_file_exist(string file_name)
{
    namespace fs = std::filesystem;
    string path(cwd);
    path += "/";
    path += file_name;

    fs::path filePath = path;
    return fs::exists(path);
}
/**
 * @brief setup the listener for the client
 *
 * @param new_socket
 */
void downloads_others_listener(int new_socket)
{
    char buffer[1024];
    memset(buffer, 0, sizeof(buffer));

    // Read the initial message from the client
    ssize_t valread = read(new_socket, buffer, 1024 - 1);
    if (valread <= 0)
    {
        cout << "Peer disconnected.\n";
        close(new_socket);
        return;
    }
    cout << "Received initial message from client: " << buffer << endl;

    // Send initial response to client
    string initial_response = "Hello from peer";
    send(new_socket, initial_response.c_str(), initial_response.size(), 0);

    while (true)
    {
        memset(buffer, 0, sizeof(buffer));
        valread = read(new_socket, buffer, 1024 - 1);
        if (valread <= 0)
        {
            cout << "Peer disconnected.\n";
            break;
        }

        vector<string> command;
        split(buffer, command);

        if (command[0] == "file_size")
        {
            string file_name = command[1];
            string path(cwd);
            path += "/";
            path += file_name;

            if (!is_file_exist(file_name))
            {
                send_message_to_client("N:requested_file_not_exist", "N:requested_file_not_exist", new_socket);
                continue;
            }

            long long file_size = get_file_size(path);
            string file_size_str = to_string(file_size);
            send_message_to_client(file_size_str, "Sent file size to peer", new_socket);
        }
        else if (command[0] == "chunk_request")
        {
            string file_name = command[1];
            int chunk_num = stoi(command[2]);

            string path(cwd);
            path += "/";
            path += file_name;

            if (!is_file_exist(file_name))
            {
                send_message_to_client("N:file_not_exist", "file not exist", new_socket);
                continue;
            }

            int fd_read = open(path.c_str(), O_RDONLY);
            if (fd_read == -1)
            {
                perror("Error opening file");
                continue;
            }

            off_t offset = chunk_num * CHUNK_SIZE;
            off_t file_size = get_file_size(path);
            off_t bytes_to_read = min((off_t)CHUNK_SIZE, file_size - offset);

            if (lseek(fd_read, offset, SEEK_SET) == -1)
            {
                perror("Error seeking in file");
                close(fd_read);
                continue;
            }

            char *chunk_data = new char[bytes_to_read];
            ssize_t bytes_read = 0;
            while (bytes_read < bytes_to_read)
            {
                ssize_t n = read(fd_read, chunk_data + bytes_read, bytes_to_read - bytes_read);
                if (n <= 0)
                {
                    perror("Error reading chunk data");
                    break;
                }
                bytes_read += n;
            }

            // Send chunk data
            ssize_t bytes_sent = 0;
            while (bytes_sent < bytes_read)
            {
                ssize_t n = send(new_socket, chunk_data + bytes_sent, bytes_read - bytes_sent, 0);
                if (n == -1)
                {
                    perror("Error sending chunk data");
                    break;
                }
                bytes_sent += n;
            }

            close(fd_read);
            delete[] chunk_data;
        }
        else
        {
            send_message_to_client("Invalid command", "Invalid command received", new_socket);
        }
    }

    close(new_socket);
}
/**
 * @brief establish listner for the other clients to donwload
 *
 * @param IP
 * @param S_PORT
 * @return true
 * @return false
 */
bool establish_listen(string IP, string S_PORT)
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    socklen_t addrlen = sizeof(address);

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) // SOCK_STREAM for TCP
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Attaching socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt)))
    {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;         // for ipv4
    address.sin_addr.s_addr = INADDR_ANY; // get connection to any
    address.sin_port = htons(stoi(S_PORT));

    // Binding the socket
    if (bind(server_fd, (struct sockaddr *)&address,
             sizeof(address)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    while (true)
    {
        if (listen(server_fd, 3) < 0)
        {
            perror("listen");
            exit(EXIT_FAILURE);
        }

        cout << "Client listening on port " << S_PORT << endl;

        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen)) < 0)
        {
            perror("accept");
            exit(EXIT_FAILURE);
        }

        // Start a new thread for each client
        thread th(downloads_others_listener, new_socket);
        th.detach(); // Detach the thread so it can run independently
    }

    close(server_fd);
    return true;
}
/**
 * @brief Get the tracker info object from the given file
 *
 * @param file_path
 * @return vector<pair<string, string>>
 */
vector<pair<string, string>> get_tracker_info(string file_path)
{
    vector<pair<string, string>> tracker_info;

    ifstream infile(file_path);
    if (!infile)
    {
        perror("Error opening tracker info file");
        return tracker_info;
    }

    string line;
    while (getline(infile, line))
    {
        istringstream iss(line);
        string ip_port;
        while (iss >> ip_port)
        {
            size_t pos = ip_port.find(":");
            if (pos != string::npos)
            {
                string ip = ip_port.substr(0, pos);
                string port = ip_port.substr(pos + 1);
                tracker_info.push_back(make_pair(ip, port));
            }
        }
    }

    return tracker_info;
}
/**
 * @brief To establish connedtion with tracker
 *
 * @param tracker_info
 * @return true
 * @return false
 */
bool establish_tracker_connection(vector<pair<string, string>> tracker_info)
{
    bool connection = false;
    for (const auto &tracker : tracker_info)
    {
        struct sockaddr_in serv_addr;
        string IP = tracker.first; // IP address
        string PORT = tracker.second;

        char *hello = "Hello from client";
        char buffer[1024] = {0};
        if ((client_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            printf("\n Socket creation error \n");
            continue;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(stoi(PORT));

        // Convert IPv4 and IPv6 addresses from text to binary
        // form
        if (inet_pton(AF_INET, IP.c_str(), &serv_addr.sin_addr) <= 0)
        {
            printf("\nInvalid address/ Address not supported \n");
            close(client_fd);
            continue;
        }

        if ((status = connect(client_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0)
        {
            printf("\nConnection Failed \n");
            close(client_fd);
            continue;
        }
        connection = true;

        // action
        send(client_fd, hello, strlen(hello), 0);
        printf("Hello message sent to tracker\n");
        valread = read(client_fd, buffer, 1024 - 1);
        printf("Received from tracker: %s\n", buffer);
        break;
    }
    return connection;
}
/**
 * @brief To download the file from other client
 *
 * @param vec_file_detail
 */

void get_file(vector<string> vec_file_detail)
{
    // Extract details from vec_file_detail
    string file_name = vec_file_detail[0];
    string file_hash = vec_file_detail[1];
    string destination_path = vec_file_detail[2];
    int number_of_chunks = stoi(vec_file_detail[3]);
    int number_of_peers = stoi(vec_file_detail[4]);

    vector<pair<string, string>> vec_ip_port;

    int i = 5;
    while (i < vec_file_detail.size())
    {
        if (i + 1 >= vec_file_detail.size())
            break;
        string ip_port = vec_file_detail[i++];
        string addr = vec_file_detail[i++]; // File path on peer, not used here
        string ip = ip_port.substr(0, ip_port.find(':'));
        string port = ip_port.substr(ip_port.find(':') + 1);
        vec_ip_port.push_back({ip, port});
    }

    // Create the output file with the correct size filled with zeros
    int fd_write = open(destination_path.c_str(), O_CREAT | O_WRONLY, 0744);
    if (fd_write == -1)
    {
        perror("Error opening output file");
        return;
    }

    // Get the file size from one of the peers
    long long file_size = 0;

    // Use the first available peer to get the file size
    for (const auto &peer : vec_ip_port)
    {
        struct sockaddr_in serv_addr;
        string IP = peer.first;
        string PORT = peer.second;

        char buffer[1024] = {0};
        int peer_fd;
        if ((peer_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            printf("\n Socket creation error \n");
            continue;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(stoi(PORT));

        if (inet_pton(AF_INET, IP.c_str(), &serv_addr.sin_addr) <= 0)
        {
            printf("\nInvalid address/ Address not supported \n");
            close(peer_fd);
            continue;
        }

        if ((status = connect(peer_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0)
        {
            printf("\nConnection Failed to peer %s:%s\n", IP.c_str(), PORT.c_str());
            close(peer_fd);
            continue;
        }

        // Send initial greeting
        string hello = "Hello from client";
        send(peer_fd, hello.c_str(), hello.size(), 0);
        valread = read(peer_fd, buffer, 1024 - 1);

        // Request file size
        string command = "file_size " + file_name;
        send(peer_fd, command.c_str(), command.size(), 0);
        memset(buffer, 0, sizeof(buffer));
        valread = read(peer_fd, buffer, 1024 - 1);
        if (valread > 0)
        {
            if (buffer[0] != 'N')
            {
                file_size = atoll(buffer);
                close(peer_fd);
                break;
            }
        }
        close(peer_fd);
    }

    if (file_size == 0)
    {
        cout << "Failed to get file size from peers.\n";
        close(fd_write);
        return;
    }

    // Set the file size
    if (lseek(fd_write, file_size - 1, SEEK_SET) == -1)
    {
        perror("Error setting file size");
        close(fd_write);
        return;
    }
    // Write a zero byte at the last position
    if (write(fd_write, "", 1) != 1)
    {
        perror("Error writing last byte");
        close(fd_write);
        return;
    }
    close(fd_write);

    // Now, for each chunk, download from assigned peer using round robin
    int num_peers = vec_ip_port.size();

    // Open the output file for writing
    fd_write = open(destination_path.c_str(), O_WRONLY);
    if (fd_write == -1)
    {
        perror("Error opening output file for writing");
        return;
    }

    // For each chunk
    for (int chunk_num = 0; chunk_num < number_of_chunks; ++chunk_num)
    {
        int peer_index = chunk_num % num_peers;
        string peer_ip = vec_ip_port[peer_index].first;
        string peer_port = vec_ip_port[peer_index].second;

        // Connect to peer
        int peer_fd;
        struct sockaddr_in serv_addr;
        if ((peer_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        {
            printf("\n Socket creation error \n");
            continue;
        }

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(stoi(peer_port));

        if (inet_pton(AF_INET, peer_ip.c_str(), &serv_addr.sin_addr) <= 0)
        {
            printf("\nInvalid address/ Address not supported \n");
            close(peer_fd);
            continue;
        }

        if ((status = connect(peer_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0)
        {
            printf("\nConnection Failed to peer %s:%s\n", peer_ip.c_str(), peer_port.c_str());
            close(peer_fd);
            continue;
        }

        // Send initial greeting
        string hello = "Hello from client";
        send(peer_fd, hello.c_str(), hello.size(), 0);
        char buffer[1024];
        memset(buffer, 0, sizeof(buffer));
        valread = read(peer_fd, buffer, 1024 - 1);

        // Send chunk_request
        string chunk_command = "chunk_request " + file_name + " " + to_string(chunk_num);
        send(peer_fd, chunk_command.c_str(), chunk_command.size(), 0);

        // Receive chunk data
        off_t offset = chunk_num * CHUNK_SIZE;
        ssize_t bytes_to_read = min((long long)CHUNK_SIZE, file_size - offset);
        char *chunk_data = new char[bytes_to_read];
        ssize_t bytes_received = 0;
        while (bytes_received < bytes_to_read)
        {
            ssize_t n = read(peer_fd, chunk_data + bytes_received, bytes_to_read - bytes_received);
            if (n <= 0)
            {
                perror("Error receiving chunk data from peer");
                break;
            }
            bytes_received += n;
        }

        // Write chunk data to file at correct offset
        lseek(fd_write, offset, SEEK_SET);
        ssize_t bytes_written = write(fd_write, chunk_data, bytes_received);
        if (bytes_written == -1)
        {
            perror("Error writing chunk data to file");
            delete[] chunk_data;
            close(peer_fd);
            break;
        }

        delete[] chunk_data;
        close(peer_fd);
    }

    // Close the file
    close(fd_write);

    // Verify file integrity
    string downloaded_file_hash = get_hash(destination_path);
    if (downloaded_file_hash == file_hash)
    {
        cout << "File downloaded and verified successfully.\n";
    }
    else
    {
        cout << "File integrity verification failed.\n";
    }
}

int main(int argc, char const *argv[])
{

    // to compile g++ c1.cpp -lssl -lcrypto
    if (argc != 3)
    {
        cout << "Usage: ./client <IP>:<PORT> <tracker_info_file>\n";
        return 0;
    }

    // Parse client IP and port
    string client_ip_and_port = argv[1];
    size_t pos = client_ip_and_port.find(":");
    if (pos == string::npos)
    {
        cout << "Invalid IP and port format.\n";
        return 0;
    }
    client_IP = client_ip_and_port.substr(0, pos);
    client_PORT = client_ip_and_port.substr(pos + 1);

    // Get current working directory
    if (getcwd(cwd, sizeof(cwd)) == NULL)
    {
        perror("getcwd() error");
        return 1;
    }

    // Start listener thread
    thread listener_thread(establish_listen, client_IP, client_PORT);

    // Get tracker info
    vector<pair<string, string>> tracker_info = get_tracker_info(argv[2]);

    // Establish connection to tracker
    if (!establish_tracker_connection(tracker_info))
    {
        cout << "Failed to connect to tracker.\n";
        return 0;
    }

    char buffer[1024] = {0};

    cout << "Start talking to tracker\n";
    while (true)
    {
        cout << "Command: ";
        vector<string> command;
        string command_entered;
        getline(cin, command_entered);

        get_command(command, command_entered);

        if (command.empty())
        {
            continue;
        }

        if (command[0] == "exit")
        {
            cout << "Exiting...\n";
            break;
        }
        else if (command[0] == "create_user")
        {
            // create_user <user_id> <passwd>
            if (command.size() < 3 || command.size() > 3)
            {
                cout << "wrong syntax\nUsage: create_user <user_id> <passwd>\n";
                continue;
            }
            send(client_fd, command_entered.c_str(), command_entered.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
        }
        else if (command[0] == "login")
        {
            // login <user_id> <passwd>
            if (command.size() < 3 || command.size() > 3)
            {
                cout << "wrong syntax\nUsage: login <user_id> <passwd>\n";
                continue;
            }
            send(client_fd, command_entered.c_str(), command_entered.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
            if (buffer[0] == 'Y')
            {
                string ip_port = client_IP + ":" + client_PORT;
                send(client_fd, ip_port.c_str(), ip_port.size(), 0);
                sleep(1);
            }
        }
        else if (command[0] == "create_group")
        {
            // create_group <group_id>
            if (command.size() < 2 || command.size() > 2)
            {
                cout << "wrong syntax\nUsage: create_group <group_id>\n";
                continue;
            }
            send(client_fd, command_entered.c_str(), command_entered.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
        }
        else if (command[0] == "list_groups")
        {
            // list_groups
            if (command.size() < 1 || command.size() > 1)
            {
                cout << "wrong syntax\nUsage: list_groups\n";
                continue;
            }
            send(client_fd, command_entered.c_str(), command_entered.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
        }
        else if (command[0] == "join_group")
        {
            // join_group <group_id>
            if (command.size() < 2 || command.size() > 2)
            {
                cout << "wrong syntax\nUsage: join_group <group_id>\n";
                continue;
            }
            send(client_fd, command_entered.c_str(), command_entered.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
        }
        else if (command[0] == "leave_group")
        {
            // leave_group <group_id>
            if (command.size() < 2 || command.size() > 2)
            {
                cout << "wrong syntax\nUsage: leave_group <group_id>\n";
                continue;
            }
            send(client_fd, command_entered.c_str(), command_entered.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
        }
        else if (command[0] == "list_requests")
        {
            // list_requests <group_id>
            if (command.size() < 2 || command.size() > 2)
            {
                cout << "wrong syntax\nUsage: list_requests <group_id>\n";
                continue;
            }
            send(client_fd, command_entered.c_str(), command_entered.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
        }
        else if (command[0] == "accept_request")
        {
            // accept_request <group_id> <user_id>
            if (command.size() < 3 || command.size() > 3)
            {
                cout << "wrong syntax\nUsage: accept_request <group_id> <user_id>\n";
                continue;
            }
            send(client_fd, command_entered.c_str(), command_entered.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
        }
        else if (command[0] == "upload_file")
        {
            // upload_file <file_path> <group_id>
            if (command.size() < 3 || command.size() > 3)
            {
                cout << "wrong syntax\nUsage: upload_file <file_path> <group_id>\n";
                continue;
            }
            string file_path = command[1];
            string group_id = command[2];

            namespace fs = std::filesystem;
            if (!fs::exists(file_path))
            {
                cout << "File does not exist.\n";
                continue;
            }

            string file_name = fs::path(file_path).filename();
            string hash_string = get_hash(file_path);
            long long file_size = get_file_size(file_path);
            long long number_of_chunks = (file_size + CHUNK_SIZE - 1) / CHUNK_SIZE;

            string upload_command = command[0] + " " + file_name + " " + file_path + " " + group_id + " " + hash_string + " " + to_string(number_of_chunks);

            send(client_fd, upload_command.c_str(), upload_command.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
        }
        else if (command[0] == "list_files")
        {
            // list_files <group_id>
            if (command.size() < 2 || command.size() > 2)
            {
                cout << "wrong syntax\n Usage: list_files <group_id>\n";
                continue;
            }
            send(client_fd, command_entered.c_str(), command_entered.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
        }
        else if (command[0] == "download_file")
        {
            // download_file <group_id> <file_name> <destination_path>
            if (command.size() < 4 || command.size() > 4)
            {
                cout << "wrong syntax\nUsage: download_file <group_id> <file_name> <destination_path>\n";
                continue;
            }
            send(client_fd, command_entered.c_str(), command_entered.size(), 0);

            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1); // read from server

            string file_details(buffer);

            vector<string> file_detail;
            split(file_details, file_detail);

            get_file(file_detail);
            cout << "operation completed\n"; // print to console
        }
        else if (command[0] == "logout")
        {
            // logout
            if (command.size() < 1 || command.size() > 1)
            {
                cout << "wrong syntax\nUsage: logout\n";
                continue;
            }
            send(client_fd, command_entered.c_str(), command_entered.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
            break;
        }
        else if (command[0] == "stop_sharing")
        {
            if (command.size() < 3 || command.size() > 3)
            {
                cout << "wrong syntax\nUsage: stop_share <group_id> <file_name>\n";
                continue;
            }

            send(client_fd, command_entered.c_str(), command_entered.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
        }
        else if (command[0] == "show_downloads")
        {
            // show_downloads
            if (command.size() < 1 || command.size() > 1)
            {
                cout << "wrong syntax\nUsage: stop_share <group_id> <file_name>\n";
                continue;
            }
            send(client_fd, command_entered.c_str(), command_entered.size(), 0);
            memset(buffer, 0, sizeof(buffer));
            valread = read(client_fd, buffer, 1024 - 1);
            cout << buffer << endl;
        }
        else
        {
            cout << "Invalid command.\n";
        }
    }

    close(client_fd);

    if (listener_thread.joinable())
    {
        listener_thread.join();
    }

    return 0;
}
