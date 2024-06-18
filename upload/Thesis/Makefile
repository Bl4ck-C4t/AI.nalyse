# Makefile to compile each .c file in the sources folder into its own executable in the out folder,
# and then compress each executable into a separate zip file in the compressed_out folder

# Compiler
CC = gcc

# Compiler flags
CFLAGS = -Wall -Werror -g

# Source and output directories
SRC_DIR = sources
OUT_DIR = out
COMPRESSED_DIR = compressed_out

# Source files
SRCS = $(wildcard $(SRC_DIR)/*.c)

# Executable files
EXES = $(patsubst $(SRC_DIR)/%.c, $(OUT_DIR)/%, $(SRCS))

# Compressed files
COMPRESSED = $(patsubst $(SRC_DIR)/%.c, $(COMPRESSED_DIR)/%.zip, $(SRCS))

# Default target
all: $(COMPRESSED)

# Rule to compile each .c file into its own executable
$(OUT_DIR)/%: $(SRC_DIR)/%.c
	@mkdir -p $(OUT_DIR)
	$(CC) -o $@ $<

# Rule to compress each executable into a zip file
$(COMPRESSED_DIR)/%.zip: $(OUT_DIR)/%
	@mkdir -p $(COMPRESSED_DIR)
	zip -j $@ $<

# Clean up
clean:
	rm -f $(OUT_DIR)/*
	rm -f $(COMPRESSED_DIR)/*

# Phony targets
.PHONY: all clean
