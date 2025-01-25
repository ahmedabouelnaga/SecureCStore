CC=g++
CFLAGS=-Wall -g -Werror
OUTPUT_DIR=$(shell pwd)
export CC
export CFLAGS
export OUTPUT_DIR

PART1_DIR=part1_hmac
PART1_FILES=$(PART1_DIR)/hmac.cpp $(PART1_DIR)/hmac_lib.cpp $(PART1_DIR)/hmac_args.cpp crypto_lib/sha256.c

PART2_DIR=part2_aes
PART2_FILES=$(PART2_DIR)/aes_lib.cpp $(PART2_DIR)/aes_args.cpp crypto_lib/sha256.c crypto_lib/aes.c $(PART1_DIR)/hmac_lib.cpp

PART3_DIR=part3_cstore
PART3_FILES=$(PART2_DIR)/aes_lib.cpp crypto_lib/sha256.c crypto_lib/aes.c $(PART1_DIR)/hmac_lib.cpp $(PART3_DIR)/cstore_args.cpp $(PART3_DIR)/cstore.cpp $(PART3_DIR)/cstore_object.cpp

.PHONY: all part1 part2 part3 test_part1 test_part2 test_part3 build clean
default: build



hmac: $(PART1_FILES)
	$(CC) $(CFLAGS) $(PART1_FILES) -o $(OUTPUT_DIR)/hmac

aes-encrypt: $(PART2_FILES) $(PART2_DIR)/aes_encrypt.cpp
	$(CC) $(CFLAGS) $(PART2_FILES) $(PART2_DIR)/aes_encrypt.cpp -o $(OUTPUT_DIR)/aes-encrypt

aes-decrypt: $(PART2_FILES) $(PART2_DIR)/aes_decrypt.cpp
	$(CC) $(CFLAGS) $(PART2_FILES) $(PART2_DIR)/aes_decrypt.cpp -o $(OUTPUT_DIR)/aes-decrypt

part1: hmac

part2: aes-encrypt aes-decrypt

cstore: $(PART3_FILES) 
	$(CC) $(CFLAGS) $(PART3_FILES) -o $(OUTPUT_DIR)/cstore

part3: cstore


build: part1 part2 part3


test_part1: part1
	python3 -m tests part1
	
test_part2: part2
	python3 -m tests part2 

test_part3: part3
	python3 -m tests part3 
	

test: test_part1 test_part2 test_part3

clean:
	(rm hmac aes-encrypt aes-decrypt cstore 2>/dev/null|| true)

all: build test

