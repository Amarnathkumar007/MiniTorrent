# P2P File Transfer Implementation

## Overview

This document describes the implementation of real peer-to-peer (P2P) file transfer functionality in the distributed file sharing system. The system now supports actual file content transfer between peers with hash verification for data integrity.

## Architecture

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Tracker   │    │  Uploader   │    │ Downloader  │
│   Server    │    │   Peer      │    │    Peer     │
└─────────────┘    └─────────────┘    └─────────────┘
       │                   │                   │
       │◄──file metadata───┤                   │
       │   + peer info      │                   │
       │                   │                   │
       │                   │◄──get file info───┤
       │───file info +─────┤                   │
       │   peer details    │                   │
       │                   │                   │
       │                   │◄──piece requests──┤
       │                   │───piece data──────►│
       │                   │   + hash          │
```

## Key Components

### 1. Enhanced File Metadata Storage

The `file_info_t` structure now includes peer information:

```c
typedef struct {
    char filename[MAX_FILENAME_SIZE];
    char filepath[MAX_PATH_SIZE];
    off_t file_size;
    unsigned char file_sha1[SHA1_DIGEST_LENGTH];
    int total_pieces;
    piece_info_t pieces[MAX_PIECES];
    char group_id[MAX_GROUP_ID_SIZE];
    char uploader[MAX_USERNAME_SIZE];
    char uploader_ip[INET_ADDRSTRLEN];  // NEW: Peer IP
    int uploader_port;                  // NEW: Peer port
    time_t upload_time;
} file_info_t;
```

### 2. New Message Types

- `MSG_GET_FILE_INFO`: Request detailed file info including peer details
- `MSG_PIECE_REQUEST`: Request specific file piece from peer
- `MSG_PIECE_RESPONSE`: Response containing piece data with hash

### 3. Tracker Enhancements

#### File Upload Processing
- Stores uploader's IP and port with file metadata
- Enhanced upload message format: `filename:group_id:size:sha1:uploader:ip:port`

#### File Info Retrieval
- New `MSG_GET_FILE_INFO` handler provides complete file metadata
- Returns: `filename:size:sha1:uploader:ip:port:total_pieces`

### 4. Peer Server Enhancement

The peer server now handles piece requests:

```c
case MSG_PIECE_REQUEST:
    // Parse request: filename:piece_index
    // Read piece from file at correct offset
    // Compute piece SHA1 hash
    // Send response: size:hash:data
```

**Key Features:**
- ✅ Validates piece index bounds
- ✅ Handles variable-sized last piece
- ✅ Computes and sends piece hash
- ✅ Proper error handling and logging

### 5. Download Process Rewrite

The download process now implements true P2P transfer:

#### Step 1: Get File Metadata
```c
// Request detailed file info from tracker
msg.type = MSG_GET_FILE_INFO;
snprintf(msg.data, MAX_BUFFER_SIZE, "%s:%s", group_id, filename);
```

#### Step 2: Parse Peer Information
```c
// Parse: filename:size:sha1:uploader:ip:port:total_pieces
sscanf(response.data, "%255[^:]:%lld:%40[^:]:%63[^:]:%15[^:]:%d:%d",
       file_filename, &file_size, file_sha1, uploader, uploader_ip, 
       &uploader_port, &total_pieces);
```

#### Step 3: Piece-by-Piece Transfer
```c
for (int piece_idx = 0; piece_idx < total_pieces; piece_idx++) {
    // Connect to peer
    int peer_fd = connect_to_server(uploader_ip, uploader_port);
    
    // Request piece
    message_t piece_request;
    piece_request.type = MSG_PIECE_REQUEST;
    snprintf(piece_request.data, MAX_BUFFER_SIZE, "%s:%d", filename, piece_idx);
    
    // Receive and verify piece
    // Parse: size:hash:data
    // Verify piece hash
    // Write to file at correct offset
}
```

#### Step 4: Final File Verification
```c
// Compute hash of assembled file
compute_file_sha1(dest_path, downloaded_file_hash);

// Compare with original file hash
if (memcmp(final_file_hash, downloaded_file_hash, SHA1_DIGEST_LENGTH) == 0) {
    // Success - file integrity verified
} else {
    // Failed - remove corrupted file
}
```

## Hash Verification System

### Two-Level Verification

1. **Piece-Level Verification**
   - Each piece is hashed individually during transfer
   - Piece hash computed by uploader and sent with data
   - Downloader verifies piece hash before accepting

2. **File-Level Verification**
   - Complete file hash verified after assembly
   - Original file SHA1 stored in tracker metadata
   - Downloaded file SHA1 computed and compared

### Hash Functions

```c
// Compute SHA1 of data buffer
void compute_sha1(const char* data, size_t data_size, unsigned char* hash);

// Compute SHA1 of entire file
void compute_file_sha1(const char* filepath, unsigned char* hash);

// Compute SHA1 of specific piece
void compute_piece_sha1(const char* filepath, int piece_index, unsigned char* hash);

// Convert between hex string and binary
char* sha1_to_string(const unsigned char* sha1);
void string_to_sha1(const char* hex_string, unsigned char* sha1);
```

## Error Handling

### Connection Failures
- If peer connection fails, download stops immediately
- User notified of connection failure with peer details

### Piece Verification Failures
- If piece hash doesn't match, download stops
- Error message indicates which piece failed verification

### File Assembly Failures
- If final file hash doesn't match, file is deleted
- Prevents corrupted files from being saved

## Visual Enhancements

### Progress Tracking
- Real-time progress bar during piece downloads
- Shows current piece being downloaded
- Updates with each successful piece transfer

### Enhanced UI
- Emoji-enhanced status messages (🚀 📋 🔄 ✅ ❌)
- Color-coded output for different message types
- Detailed file information display before download

### Logging
- Comprehensive logging of P2P activities
- Peer connection events logged
- Piece serving activities tracked

## Protocol Messages

### GET_FILE_INFO Request
```
MSG_GET_FILE_INFO
Data: "group_id:filename"
```

### GET_FILE_INFO Response
```
MSG_SUCCESS
Data: "filename:size:sha1:uploader:ip:port:total_pieces"
```

### PIECE_REQUEST
```
MSG_PIECE_REQUEST
Data: "filename:piece_index"
```

### PIECE_RESPONSE
```
MSG_PIECE_RESPONSE
Data: "size:hash:piece_data"
```

## Testing

### Test Script: `test_p2p_simple.sh`

The test script verifies:
- ✅ File upload with peer registration
- ✅ File download via P2P transfer
- ✅ Content integrity verification
- ✅ SHA1 hash verification
- ✅ Peer serving functionality

### Test Scenarios
1. **Small File Transfer**: Tests basic P2P functionality
2. **Large File Transfer**: Tests multi-piece transfer
3. **Hash Verification**: Ensures data integrity
4. **Peer Discovery**: Verifies tracker-mediated peer discovery

## Key Benefits

### 🎯 **True P2P Transfer**
- No more placeholder files
- Actual content transferred between peers
- Direct peer-to-peer connections

### 🔒 **Data Integrity**
- Dual-level hash verification
- Piece-by-piece validation
- Automatic corruption detection

### 🚀 **Enhanced User Experience**
- Progress bars with real-time updates
- Detailed status information
- Professional terminal interface

### 🛡️ **Robust Error Handling**
- Graceful failure recovery
- Detailed error messages
- Automatic cleanup of failed downloads

## Usage Example

```bash
# Start tracker
./tracker tracker_info.txt 1 &

# Start uploader client
./client 127.0.0.1:8080 tracker_info.txt

# Upload file
upload_file myfile.txt mygroup

# Start downloader client  
./client 127.0.0.1:8081 tracker_info.txt

# Download file via P2P
download_file mygroup myfile.txt downloaded_file.txt
```

## Implementation Status

✅ **COMPLETED**
- Enhanced tracker with peer info storage
- Real P2P file transfer implementation
- Piece-by-piece hash verification
- Final file integrity verification
- Enhanced peer server functionality
- Comprehensive error handling
- Visual progress indicators
- Professional UI enhancements

The P2P file transfer system now provides actual file content transfer with full integrity verification, replacing the previous placeholder file system with a robust, hash-verified peer-to-peer protocol. 