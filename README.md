## **README.md**

```markdown
# Peer-to-Peer Distributed File Sharing System

## Table of Contents

- [Introduction](#introduction)
- [Features Implemented](#features-implemented)
- [Assumptions](#assumptions)
- [Prerequisites](#prerequisites)
- [Compilation and Execution Instructions](#compilation-and-execution-instructions)
- [Working Procedure](#working-procedure)
- [Commands](#commands)
- [Implementation Details](#implementation-details)
- [Error Handling](#error-handling)

## Introduction

This is a Peer-to-Peer Distributed File Sharing System implemented in C++. Users can share and download files within groups they belong to. The system supports parallel downloading from multiple peers, synchronized trackers, and a custom piece selection algorithm.

## Features Implemented

- **User Account Management**: Create accounts, login, and maintain sessions.
- **Group Management**: Create groups, join/leave groups, accept/reject join requests.
- **File Sharing**: Upload and download files within groups.
- **Parallel Downloading**: Download files by fetching chunks from multiple peers.
- **Custom Piece Selection Algorithm**: Uses round-robin to distribute chunk requests among peers.
- **File Integrity Verification**: Ensures downloaded files are intact using SHA1 hashes.
- **Multithreading**: Handles multiple clients and peer connections concurrently.
- **Error Handling**: Robust error checking for socket operations and file I/O.

## Assumptions

- At least one tracker is always online.
- Users have read permissions for the files they share.
- Network connections are reliable.
- The environment supports C++17 or later.

## Prerequisites

- **Compiler**: GCC with C++17 support.
- **Libraries**:
  - OpenSSL (`-lssl -lcrypto`)
  - POSIX threads (`-lpthread`)

## Compilation and Execution Instructions

### Compile the Tracker

```bash
g++ tracker.cpp -o tracker -std=c++17 -lpthread
```

### Compile the Client

```bash
g++ client.cpp -o client -std=c++17 -lpthread -lssl -lcrypto
```

### Run the Tracker

```bash
./tracker tracker_info.txt <tracker_no>
```

- `tracker_info.txt`: File containing IP and port details of all trackers.
- `<tracker_no>`: Tracker number (e.g., 1, 2).

### Run the Client

```bash
./client <IP>:<PORT> tracker_info.txt
```

- `<IP>`: Client's IP address.
- `<PORT>`: Port number the client will listen on.
- `tracker_info.txt`: File containing IP and port details of all trackers.

## Working Procedure

1. **Start the Tracker(s)**: Run the tracker program with the appropriate tracker number.

2. **Start the Client**: Run the client program with the client's IP and port.

3. **Create a User Account**: Use the `create_user` command to create a new user account.

4. **Login**: Use the `login` command to authenticate.

5. **Group Operations**:
   - **Create Group**: `create_group <group_id>`
   - **Join Group**: `join_group <group_id>`
   - **Leave Group**: `leave_group <group_id>`
   - **List Groups**: `list_groups`
   - **List Requests**: `list_requests <group_id>`
   - **Accept Request**: `accept_request <group_id> <user_id>`

6. **File Sharing**:
   - **Upload File**: `upload_file <file_path> <group_id>`
   - **List Files**: `list_files <group_id>`
   - **Download File**: `download_file <group_id> <file_name> <destination_path>`
   - **Show Downloads**: `show_downloads`

7. **Logout**: Use the `logout` command to end the session.

## Commands

### Tracker Commands

- **Run Tracker**: `./tracker tracker_info.txt <tracker_no>`
- **Close Tracker**: Type `quit` in the tracker console.

### Client Commands

- **Run Client**: `./client <IP>:<PORT> tracker_info.txt`
- **Create User Account**: `create_user <user_id> <passwd>`
- **Login**: `login <user_id> <passwd>`
- **Create Group**: `create_group <group_id>`
- **Join Group**: `join_group <group_id>`
- **Leave Group**: `leave_group <group_id>`
- **List Pending Join Requests**: `list_requests <group_id>`
- **Accept Group Joining Request**: `accept_request <group_id> <user_id>`
- **List All Groups**: `list_groups`
- **List All Sharable Files**: `list_files <group_id>`
- **Upload File**: `upload_file <file_path> <group_id>`
- **Download File**: `download_file <group_id> <file_name> <destination_path>`
- **Logout**: `logout`
- **Show Downloads**: `show_downloads`
- **Exit Client**: Type `exit` in the client console.

## Implementation Details

### Multithreading

- Used the `<thread>` library to handle multiple connections concurrently.
- Each client connection to the tracker and peer connections between clients are handled in separate threads.

### Networking

- Socket programming is used for communication between clients and trackers/peers.
- Both TCP sockets and multithreading ensure reliable data transfer and concurrent handling.

### File Handling

- Files are divided into chunks of 512 KB.
- `lseek()` is used to write chunks to the correct position in the file.
- The file is initially created with the correct size filled with zeros.

### Hashing

- SHA1 hashes are computed for file integrity verification.
- The OpenSSL library is used for hashing functions.

### Piece Selection Algorithm

- Implemented a round-robin algorithm to assign chunks to different peers.
- This ensures balanced network utilization and efficient downloading.

## Error Handling

- **Socket Operations**: Checked return values of `socket()`, `bind()`, `listen()`, `accept()`, `connect()`, `send()`, and `recv()`.
- **File I/O**: Verified successful opening, reading, writing, and closing of files.
- **Input Validation**: Ensured correct number of arguments and valid command formats.
- **Exception Safety**: Used try-catch blocks where appropriate to handle exceptions.

---

**Note**: Ensure that all peers and trackers are running and properly configured before starting file transfers. The system relies on active participation from clients for sharing and downloading files.

```
