CC = gcc
CFLAGS = -Wall -Wextra -g $(shell pkg-config --cflags openssl)
LDFLAGS = $(shell pkg-config --libs openssl)

SRC_DIR = src
BIN_DIR = bin

SRC = $(SRC_DIR)/myproxy.c
HEADER = $(SRC_DIR)/myproxy.h
OBJ = $(SRC_DIR)/myproxy.o
EXECUTABLE = $(BIN_DIR)/myproxy

$(shell mkdir -p $(BIN_DIR))

all: $(EXECUTABLE)
$(OBJ): $(SRC) $(HEADER)
	$(CC) $(CFLAGS) -c $(SRC) -o $(OBJ)

$(EXECUTABLE): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) -o $(EXECUTABLE)

clean:
	rm -rf $(OBJ) $(EXECUTABLE)

.PHONY: all clean
