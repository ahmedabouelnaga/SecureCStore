#include "hmac_lib.h"


/**
 * @brief generates a sha256 hash of some input
 *  note that this version handles all of the input
 *  at once. for large files you may want to chunk
 *
 * @param input a byte array of data
 * @param output a byte array to store the hash; should be 32 bytes
 * @param in_len the size of the input data
 */
void hash_sha256(const BYTE * input, BYTE * output, int in_len)
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, in_len);
    sha256_final(&ctx, output);
}

/**
 * @brief returns a buf of a hexidecimal representation of a string
 *
 * @param byte_arr - byte array to print
 * @param len - length of byte array
 */
char *sprint_hex(const char* byte_arr, uint32_t len)
{
    uint64_t buff_len = len*2+1;
    char * buf = (char *) malloc(buff_len);

    if(buf == NULL)
        return buf;

    memset(buf, 0, buff_len);

    char *buffer_ptr = buf;

    for(uint32_t index = 0; index < len; index++) {
        sprintf(buffer_ptr, "%02X", (unsigned char) byte_arr[index]);
        buffer_ptr += 2;
    }
    return buf;
}

/**
 * @brief print a byte string as its hexidecimal representation
 *
 * @param byte_arr - byte array to print
 * @param len - length of byte array
 */
void print_hex(const char* byte_arr, int len)
{
    char * buff = sprint_hex(byte_arr,len);
    if (buff != NULL) {
        printf("%s\n", buff);
    }
    free(buff);
}

/**
 * @brief print a byte vector as its hexidecimal representation
 *  provided as a brief demonstration for how to interface
 *  between vectors and C arrays
 *
 * @param bytes a vector of bytes
 */
void print_vector_as_hex(std::vector<char> bytes)
{
        print_hex(bytes.data(), bytes.size());
}

/**
 * @brief writes a binary file to disk
 *
 * @param filename name of file to write
 * @param data vector of data to write
 */
void write_data_to_file(std::string filename, std::vector<char> data)
{
        std::ofstream outfile;
        outfile.open(filename,std::ios::binary|std::ios::out);
        outfile.write(data.data(),data.size());
        outfile.close();
}


/**
 * @brief Reads a file and generate a hmac of its contents, given a password
 *
 * @param filename - name of file to generate hmac
 * @param password - password to use when generating secret
 * @param dest - buf to store the final hash; should be size of a sha256
 * @return true - successfully completed actions
 * @return false - an error occurred
 */
const int blockSize = 64;
const int hashSize = 32;
bool generate_hmac(const char * filename, const char * password,
        unsigned int passwordLen, char * dest)
{
    // TODO: rewrite this function to be correct

    BYTE keyBlock[blockSize];
    memset(keyBlock, 0, blockSize);

    // Step 1: Key Preparation
    if (passwordLen > blockSize) {
        // If key is longer than block size, hash it first
        hash_sha256((const BYTE*)password, keyBlock, passwordLen);
    } else {
        // If key is shorter than block size, copy it and pad with zeros
        memcpy(keyBlock, password, passwordLen);
    }

    BYTE opad[blockSize];
    BYTE ipad[blockSize];
    for (int k = 0; k < blockSize; k++) {
        ipad[k] = keyBlock[k] ^ 0x36;
        opad[k] = keyBlock[k] ^ 0x5c;
    }
    SHA256_CTX innerContxt;
    sha256_init(&innerContxt);
    sha256_update(&innerContxt, ipad, blockSize);
    std::ifstream currentFile(filename, std::ios::in | std::ios::binary);
    if (!currentFile.is_open()) {
        return false;
    }
    const size_t bufferSize = 4096;
    BYTE buf[bufferSize];
    while (currentFile.good()) {
        currentFile.read((char*)buf, bufferSize);
        std::streamsize bytes_read = currentFile.gcount();
        if (bytes_read > 0) {
            sha256_update(&innerContxt, buf, bytes_read);
        }
    }
    currentFile.close();
    BYTE innerHash[hashSize];
    sha256_final(&innerContxt, innerHash);

    // Step 3: Compute the outer hash
    SHA256_CTX outerContxt;
    sha256_init(&outerContxt);
    sha256_update(&outerContxt, opad, blockSize);
    sha256_update(&outerContxt, innerHash, hashSize);
    sha256_final(&outerContxt, (BYTE*)dest);
    return true;
}
