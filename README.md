# Peer-to-Peer Distributed File Sharing System

A complete P2P file sharing system implementation in C/C++ using system calls, featuring a tracker server for coordination and clients for file sharing with piece-based downloading.

## Features

- **Tracker Server**: Manages clients, groups, and file metadata
- **P2P Client**: Handles user interactions, group management, and file transfers
- **Piece-based File Sharing**: Files split into 512KB pieces with SHA1 verification
- **Multi-threaded Downloads**: Parallel downloading from multiple peers
- **Rarest-first Algorithm**: Efficient piece selection strategy
- **Group Management**: Create groups, manage members, handle join requests
- **User Authentication**: Secure login system with password hashing
- **File Integrity**: SHA1 verification for both pieces and complete files
- **Debugging Tools**: Comprehensive logging and status commands

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Tracker                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  • User Management                                  │    │
│  │  • Group Management                                 │    │
│  │  • File Metadata Storage                           │    │
│  │  • Peer Coordination                               │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────┬───────────────────────────────────────┘
                      │
         ┌────────────┼────────────┐
         │            │            │
    ┌────▼───┐   ┌────▼───┐   ┌────▼───┐
    │Client 1│   │Client 2│   │Client 3│
    │        │◄──┤        │──►│        │
    │  P2P   │   │  P2P   │   │  P2P   │
    │ Server │   │ Server │   │ Server │
    └────────┘   └────────┘   └────────┘
         │            │            │
         └────────────┼────────────┘
                      │
              Direct P2P File Transfer
```

## Building the System

### Prerequisites

Install required dependencies:
```bash
make install
```

### Compilation

Build both tracker and client:
```bash
make
```

Or build individually:
```bash
make tracker
make client
```

### Clean Build

```bash
make clean
```

## Running the System

### 1. Start the Tracker

```bash
./tracker tracker_info.txt 1
```

- `tracker_info.txt`: Configuration file containing tracker IP:PORT pairs
- `1`: Tracker number (1-based index into the configuration file)

### 2. Start Clients

```bash
./client 127.0.0.1:8080 tracker_info.txt
```

- `127.0.0.1:8080`: Tracker address to connect to
- `tracker_info.txt`: Tracker configuration file for fallback connections

## Usage Guide

### Tracker Commands

| Command | Description | Example |
|---------|-------------|---------|
| `help` | Show available commands | `help` |
| `quit` | Stop the tracker | `quit` |
| `list_clients` | List all registered clients | `list_clients` |
| `list_groups` | List all groups | `list_groups` |
| `list_files <group_id>` | List files in a group | `list_files group1` |
| `sync_status` | Show synchronization status | `sync_status` |
| `verbose` | Toggle verbose mode | `verbose` |

### Client Commands

#### User Management
| Command | Description | Example |
|---------|-------------|---------|
| `create_user <user_id> <passwd>` | Register a new user | `create_user alice mypass123` |
| `login <user_id> <passwd>` | Login to the system | `login alice mypass123` |
| `logout` | Logout from the system | `logout` |

#### Group Management
| Command | Description | Example |
|---------|-------------|---------|
| `create_group <group_id>` | Create a new group | `create_group study_group` |
| `join_group <group_id>` | Request to join a group | `join_group study_group` |
| `leave_group <group_id>` | Leave a group | `leave_group study_group` |
| `list_requests <group_id>` | List pending requests (owner only) | `list_requests study_group` |
| `accept_request <group_id> <user_id>` | Accept a join request (owner only) | `accept_request study_group bob` |
| `list_groups` | List all groups | `list_groups` |

#### File Sharing
| Command | Description | Example |
|---------|-------------|---------|
| `upload_file <file_path> <group_id>` | Share a file with a group | `upload_file document.pdf study_group` |
| `download_file <group_id> <file_name> <dest_path>` | Download a file | `download_file study_group document.pdf ./downloads/` |
| `list_files <group_id>` | List files in a group | `list_files study_group` |
| `stop_share <group_id> <file_name>` | Stop sharing a file | `stop_share study_group document.pdf` |

#### Status and Debugging
| Command | Description | Example |
|---------|-------------|---------|
| `show_downloads` | Show download status | `show_downloads` |
| `list_shared_files` | List files being shared | `list_shared_files` |
| `list_peers <file_name>` | List peers sharing a file | `list_peers document.pdf` |
| `download_progress <file_name>` | Show download progress | `download_progress document.pdf` |
| `verbose` | Toggle verbose mode | `verbose` |
| `help` | Show available commands | `help` |

## Example Workflow

### 1. Setup and User Registration

**Terminal 1 (Tracker):**
```bash
./tracker tracker_info.txt 1
help
```

**Terminal 2 (Client 1):**
```bash
./client 127.0.0.1:8080 tracker_info.txt
create_user alice password123
login alice password123
```

**Terminal 3 (Client 2):**
```bash
./client 127.0.0.1:8080 tracker_info.txt
create_user bob password456
login bob password456
```

### 2. Group Creation and Management

**Client 1 (Alice):**
```bash
create_group study_materials
list_groups
```

**Client 2 (Bob):**
```bash
join_group study_materials
```

**Client 1 (Alice):**
```bash
list_requests study_materials
accept_request study_materials bob
```

### 3. File Sharing

**Client 1 (Alice):**
```bash
upload_file /path/to/textbook.pdf study_materials
list_files study_materials
```

**Client 2 (Bob):**
```bash
list_files study_materials
download_file study_materials textbook.pdf ./downloads/textbook.pdf
show_downloads
```

### 4. Monitoring (Tracker)

```bash
list_clients
list_groups
list_files study_materials
```

## File Structure

```
├── Makefile              # Build configuration
├── README.md             # This documentation
├── tracker_info.txt      # Tracker configuration
├── common.h              # Common headers and structures
├── tracker.c             # Tracker server implementation
├── client.c              # Client implementation
├── networking.c          # Socket and network functions
├── utils.c               # Utility functions (SHA1, logging, etc.)
└── file_handler.c        # File operations and P2P transfer
```

## Technical Details

### Network Protocol

The system uses a custom message-based protocol over TCP:

```c
typedef struct {
    message_type_t type;      // Message type (CREATE_USER, LOGIN, etc.)
    char data[MAX_BUFFER_SIZE]; // Message payload
    int data_length;          // Length of payload
} message_t;
```

### File Piece Management

- **Piece Size**: 512KB chunks
- **Hash Algorithm**: SHA1 for integrity verification
- **Piece Selection**: Rarest-first algorithm for efficient distribution
- **Parallel Downloads**: Multi-threaded downloading from multiple peers

### Data Structures

- **Users**: Authentication, online status, connection info
- **Groups**: Members, files, permissions
- **Files**: Metadata, piece information, SHA1 hashes
- **Downloads**: Progress tracking, peer management

### Threading Model

- **Tracker**: Main thread + client connection threads
- **Client**: Main thread + peer server thread + download threads

## Logging and Debugging

- **Tracker Log**: `tracker.log`
- **Client Log**: `client.log`
- **Verbose Mode**: Real-time operation logging
- **Debug Commands**: System state inspection

## Error Handling

- Connection failure recovery
- File integrity verification
- Piece download retry mechanism
- Graceful shutdown handling

## Security Considerations

- Password hashing for user authentication
- File integrity verification with SHA1
- Input validation and sanitization
- Buffer overflow protection

## Limitations and Future Enhancements

### Current Limitations
- Single tracker (no tracker redundancy)
- Basic authentication (plaintext passwords)
- No encryption for file transfers
- Limited scalability testing

### Potential Enhancements
- Multiple tracker synchronization
- Encrypted file transfers (TLS/SSL)
- Advanced authentication (tokens, certificates)
- NAT traversal support
- Web-based management interface
- Bandwidth throttling
- File compression
- Resume interrupted downloads

## Troubleshooting

### Common Issues

1. **Connection Refused**
   - Check if tracker is running
   - Verify IP and port in tracker_info.txt
   - Check firewall settings

2. **File Upload Fails**
   - Verify file exists and is readable
   - Check group membership
   - Ensure sufficient disk space

3. **Download Stalls**
   - Check peer availability
   - Verify network connectivity
   - Monitor verbose logs for errors

4. **Permission Denied**
   - Ensure user is logged in
   - Verify group membership
   - Check file permissions

### Debug Commands

Use the debug commands to inspect system state:

```bash
# Tracker debugging
list_clients
list_groups
list_files <group_id>
sync_status

# Client debugging
list_shared_files
show_downloads
download_progress <file_name>
verbose
```

## Contributing

This implementation serves as a foundation for P2P file sharing systems. Contributions are welcome for:

- Performance optimizations
- Security enhancements
- Feature additions
- Bug fixes
- Documentation improvements

## License

This project is provided as an educational implementation of P2P file sharing concepts. 