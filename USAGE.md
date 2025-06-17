# Quick Usage Guide - P2P File Sharing System

## Immediate Testing Instructions

### 1. Build the System
```bash
make clean && make
```

### 2. Start the Tracker (Terminal 1)
```bash
./tracker tracker_info.txt 1
```
Available commands:
- `help` - Show commands
- `list_clients` - List users
- `list_groups` - List groups
- `list_files <group_id>` - List files in group
- `quit` - Exit

### 3. Start Client 1 - Alice (Terminal 2)
```bash
./client 127.0.0.1:8080 tracker_info.txt
```
```bash
create_user alice pass123
login alice pass123
create_group demo_group
upload_file test_files/sample.txt demo_group
upload_file test_files/document.md demo_group
list_files demo_group
list_shared_files
```

### 4. Start Client 2 - Bob (Terminal 3)
```bash
./client 127.0.0.1:8080 tracker_info.txt
```
```bash
create_user bob pass456
login bob pass456
join_group demo_group
```

### 5. Accept Bob's Request (Back to Alice - Terminal 2)
```bash
list_requests demo_group
accept_request demo_group bob
```

### 6. Download Files (Bob - Terminal 3)
```bash
list_files demo_group
download_file demo_group sample.txt downloads/sample.txt
show_downloads
```

### 7. Monitor System (Tracker - Terminal 1)
```bash
list_clients
list_groups
list_files demo_group
```

## Demo Files Created
- `test_files/sample.txt` - Small text file
- `test_files/document.md` - Markdown document  
- `test_files/largefile.bin` - 2MB binary file for testing large file transfers

## System Features Demonstrated
✅ User registration and authentication  
✅ Group creation and management  
✅ File uploading with metadata  
✅ File listing and discovery  
✅ P2P file downloading  
✅ SHA1 integrity verification  
✅ Multi-threaded operations  
✅ Real-time logging  
✅ Command-line interface  

## Log Files
- `tracker.log` - Tracker operations log
- `client.log` - Client operations log

## Test Scripts
- `./run_demo.sh` - Setup demo environment
- `./test_system.sh` - Automated system testing

## Configuration
- `tracker_info.txt` - Tracker IP:PORT configuration
- Supports multiple trackers for redundancy

## How It Works

1. **Tracker** maintains user accounts, groups, and file metadata
2. **Clients** connect to tracker for coordination
3. **Files** are split into 512KB pieces with SHA1 hashes
4. **Downloads** happen directly between peers (P2P)
5. **Integrity** is verified using SHA1 checksums
6. **Parallel downloads** from multiple peers for efficiency

## Key Commands Summary

### Tracker Commands
- `help`, `quit`, `list_clients`, `list_groups`, `list_files <group>`

### Client Commands  
- `create_user <id> <pass>`, `login <id> <pass>`, `logout`
- `create_group <id>`, `join_group <id>`, `leave_group <id>`
- `list_groups`, `list_files <group>`, `list_shared_files`
- `upload_file <path> <group>`, `download_file <group> <file> <dest>`
- `show_downloads`, `verbose`, `help`

## Quick Demo
```bash
# Terminal 1
./tracker tracker_info.txt 1

# Terminal 2  
./client 127.0.0.1:8080 tracker_info.txt
create_user alice pass123
login alice pass123
create_group test
upload_file test_files/sample.txt test

# Terminal 3
./client 127.0.0.1:8080 tracker_info.txt  
create_user bob pass456
login bob pass456
join_group test

# Back to Terminal 2
accept_request test bob

# Back to Terminal 3
download_file test sample.txt downloads/sample.txt
```

🎉 **The P2P File Sharing System is ready to use!** 