#ifndef HMAC_LIB_H
#define HMAC_LIB_H

#include "../crypto_lib/sha256.h"
#include <stdio.h>
#include <vector>
#include <string.h>
#include <iostream>
#include <fstream>
#include <string.h>

#define SHA256_SIZE_IN_BYTES 32

void hash_sha256(const BYTE * input, BYTE * output, int in_len);
void print_hex(const char* byte_arr, int len);
void print_vector_as_hex(std::vector<char> bytes);
bool generate_hmac(const char * filename, const char * password, 
        unsigned int password_length, char * dest);
void write_data_to_file(std::string filename, std::vector<char> data);
char *sprint_hex(const char* byte_arr, uint32_t len);

#endif
