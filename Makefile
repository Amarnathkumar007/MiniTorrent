CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -pthread -O2 -D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE
LDFLAGS = -lssl -lcrypto -lpthread -lreadline

# Source files
TRACKER_SOURCES = tracker.c networking.c utils.c
CLIENT_SOURCES = client.c networking.c utils.c file_handler.c

# Object files
TRACKER_OBJECTS = $(TRACKER_SOURCES:.c=.o)
CLIENT_OBJECTS = $(CLIENT_SOURCES:.c=.o)

# Executables
TRACKER = tracker
CLIENT = client

.PHONY: all clean

all: $(TRACKER) $(CLIENT)

$(TRACKER): $(TRACKER_OBJECTS)
	$(CC) $(TRACKER_OBJECTS) -o $(TRACKER) $(LDFLAGS)

$(CLIENT): $(CLIENT_OBJECTS)
	$(CC) $(CLIENT_OBJECTS) -o $(CLIENT) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o $(TRACKER) $(CLIENT) *.log

install:
	sudo apt-get update
	sudo apt-get install libssl-dev

.PHONY: install clean all 