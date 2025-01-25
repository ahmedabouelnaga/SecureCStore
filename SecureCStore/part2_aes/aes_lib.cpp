#include "aes_lib.h"
#include <fcntl.h>

/**
 * @brief encrypts plaintext using AES CBC using key. 
 * buffer allocated input ciphertext must be freed. 
 * Note the current prototype allocates a buffer locally;
 * 
 * @param plaintext - pointer to plaintext buffer; if this ends input a null byte, add
 * a non-null character to the end and then strip it during decryption (or just always
 * do this for deterministic behavior)
 * @param plaintext_length - length input bytes of plaintext
 * @param IV - IV to use 
 * @param ciphertext - should pass a pointer to a pointer. This pointer 
 * will be updated with a heap-based pointer to the final ciphertext. Must be freed by caller.
 * @param ciphertext_length - pointer to int. updated with final length after padding
 * @param key - pointer to key. size is AES_BLOCK_SIZE
 * @return int - returns -1 on error, 0 otherwise.
 */
int encrypt_cbc(const char * plaintext, uint64_t plaintext_length, 
    const char * IV, char ** ciphertext,
    uint64_t * ciphertext_length, char* key )
{
    *ciphertext_length = plaintext_length + 1;
    //uint64_t padding_length = 0;
    if (*ciphertext_length % AES_BLOCK_SIZE != 0) {
        *ciphertext_length = (plaintext_length/AES_BLOCK_SIZE)*AES_BLOCK_SIZE + AES_BLOCK_SIZE;
        //padding_length = *ciphertext_length - plaintext_length;
    }
    *ciphertext = (char *) malloc(*ciphertext_length); 
    if(*ciphertext == NULL) {
        perror("error");
        return -1;
    }
    memset(*ciphertext, 0, *ciphertext_length);
    memcpy(*ciphertext, plaintext, plaintext_length);
    BYTE currentIV[AES_BLOCK_SIZE];
    BYTE input[AES_BLOCK_SIZE];
    BYTE keyBytes[SHA256_BLOCK_SIZE];
    int totalBlocks = *ciphertext_length / AES_BLOCK_SIZE;
    BYTE output[AES_BLOCK_SIZE];
    WORD keyScheduler[60];
    memcpy(keyBytes, key, SHA256_BLOCK_SIZE);
    memcpy(currentIV, IV, AES_BLOCK_SIZE);
    aes_key_setup(keyBytes, keyScheduler, 256);
    for (int i = 0; i < totalBlocks; i++) {
        memcpy(input, *ciphertext + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        for (int p = 0; p < AES_BLOCK_SIZE; p++) {
            input[p] ^= currentIV[p];
        }
        aes_encrypt(input, output, keyScheduler, 256);
        memcpy(currentIV, output, AES_BLOCK_SIZE);
        memcpy(*ciphertext + i * AES_BLOCK_SIZE, output, AES_BLOCK_SIZE);
    }
    return 0;
}
/**
 * @brief read file from disk
 * note that this may fail on very big files
 * 
 * @param filename - file to be read
 * @return std::vector<char> - on fail, this will be empty
 */
std::vector<char> get_data_from_file(std::string filename)
{
    std::ifstream urandom;
    std::streampos fileSize;
    urandom.open(filename, std::ios::in | std::ios::binary |std::ios::ate );
    std::vector<char> content;
    if (urandom.is_open())
    {
        fileSize = urandom.tellg();
        content.resize(fileSize);
        urandom.seekg (0, std::ios::beg);
        urandom.read( (char *) content.data(), fileSize);
        urandom.close();
    }       
    return content;
}
/**
 * @brief decrypts ciphertext using key and IV stores result input buffer and updates 
 * plaintext with pointer to buffer. Note that decrypt will remove null byte padding. 
 * assumes plaintext does not end input null bytes. If your plaintext will, add a non-null
 * character before encrypting and then strip it after.
 * 
 * @param ciphertext - pointer to buffer with ciphertext
 * @param ciphertext_length - length of ciphertext. should be a multiple of AES_BLOCKSIZE
 * @param IV - IV used to decrypt first block.
 * @param plaintext - double pointer to plaintext buffer. This should be a pointer to a pointer. Once the ciphertext has been decrypted, the first-depth pointer will be updated with a new heap-based buffer containing plaintext
 * @param plaintext_length length of plaintext. Should be ciphertext_length - padding. 
 * @param key - key used for AES 
 * @return int - 0 on success, -1 on error.
 */
int decrypt_cbc(const char* ciphertext, uint64_t ciphertext_length, 
    const char * IV, char ** plaintext, uint64_t * plaintext_length, 
    char* key)
{
    *plaintext_length = ciphertext_length;
    *plaintext = (char *)  malloc(*plaintext_length);
    if(*plaintext == NULL) {
        perror("error");
        return -1;
    }
    memcpy(*plaintext, ciphertext, *plaintext_length);
    BYTE currentIV[AES_BLOCK_SIZE];
    BYTE input[AES_BLOCK_SIZE];
    BYTE keyBytes[SHA256_BLOCK_SIZE];
    int totalBlocks = *plaintext_length / AES_BLOCK_SIZE;
    BYTE output[AES_BLOCK_SIZE];
    WORD keyScheduler[60];
    BYTE outputXor[AES_BLOCK_SIZE];
    memcpy(keyBytes, key, SHA256_BLOCK_SIZE); 
    aes_key_setup(keyBytes, keyScheduler, 256);
    memcpy(currentIV, IV, AES_BLOCK_SIZE); 
    for (int i = 0; i < totalBlocks; i++) {
        memcpy(input, *plaintext + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
        aes_decrypt(input, output, keyScheduler, 256);
        memcpy(*plaintext + i * AES_BLOCK_SIZE, output, AES_BLOCK_SIZE);
        memcpy(outputXor, output, AES_BLOCK_SIZE);
        for (int p = 0; p < AES_BLOCK_SIZE; p++) {
            outputXor[p] ^= currentIV[p]; 
        }
        memcpy(*plaintext + i * AES_BLOCK_SIZE, outputXor, AES_BLOCK_SIZE);
        memcpy(currentIV, ciphertext + i * AES_BLOCK_SIZE, AES_BLOCK_SIZE);
    }
    char * plaintext_ptr = *plaintext;
    for(uint64_t index = ciphertext_length - 1; 
        index > (ciphertext_length - AES_BLOCK_SIZE); index--) {
            if(plaintext_ptr[index] != '\0') {
                break;
            }
            *plaintext_length = index;
    }
    return 0;
}
encrypted_blob encrypt_file(std::string filename, std::string password)
{
    char IV[AES_BLOCK_SIZE];
    memset(IV,0,AES_BLOCK_SIZE);
    std::ifstream urandom;
    urandom.open("/dev/urandom", std::ios::binary);
    if (!urandom.is_open()) {
        perror("It has failed to open /dev/urandom\n");
    } else {
        urandom.read(IV, AES_BLOCK_SIZE);
    }
    urandom.close();
    BYTE keyBytes[SHA256_BLOCK_SIZE];
    char key[SHA256_BLOCK_SIZE];
    int passwordLen = password.length();
    BYTE bytesPass[passwordLen];
    std::copy( password.begin(), password.end(), bytesPass );
    hash_sha256(bytesPass, keyBytes, passwordLen);
    for (int i = 1; i < 10000; i++) { 
        hash_sha256(keyBytes, keyBytes, SHA256_BLOCK_SIZE);
    }
    memcpy(key, keyBytes, SHA256_BLOCK_SIZE);
    std::vector<char> plaintext = get_data_from_file(filename);
    char * ciphertext = NULL;
    uint64_t ciphertext_length = 0;
    plaintext.push_back(PAD_CHAR); // ensure padding doesn't consume a null byte input plaintext
    int encrypt_success = encrypt_cbc(plaintext.data(), plaintext.size(), IV, &ciphertext, 
    &ciphertext_length, key);
    std::vector<char> returnVector;
    if(encrypt_success == 0) {
        returnVector.resize(ciphertext_length);
        memcpy(returnVector.data(), ciphertext, ciphertext_length);
    }
    free(ciphertext);
    encrypted_blob retValue;
    retValue.ciphertext = returnVector;
    memcpy(retValue.IV, IV, AES_BLOCK_SIZE);
    return retValue;
}
std::vector<char> decrypt_file(std::string filename, std::string password)
{
    std::vector<char> returnVector;
    char IV[AES_BLOCK_SIZE];
    char key[SHA256_BLOCK_SIZE];
    BYTE keyBytes[SHA256_BLOCK_SIZE];
    int passwordLen = password.length();
    BYTE bytesPass[passwordLen];
    std::copy( password.begin(), password.end(), bytesPass );
    hash_sha256(bytesPass, keyBytes, passwordLen);
    for (int i = 1; i < 10000; i++) { 
        hash_sha256(keyBytes, keyBytes, SHA256_BLOCK_SIZE);
    }
    memcpy(key, keyBytes, SHA256_BLOCK_SIZE);
    std::vector<char> ciphertext = get_data_from_file(filename);
    if (ciphertext.size() > 16) {
        memcpy(IV,ciphertext.data(),AES_BLOCK_SIZE);
        char * plaintext = NULL;
        uint64_t plaintext_length = 0;
        char * ciphertext_data = ciphertext.data()+16;
        uint64_t ciphertext_size = ciphertext.size()-16;
        int decrypt_success = decrypt_cbc(ciphertext_data, ciphertext_size, IV, 
            &plaintext, &plaintext_length, key);
        if(decrypt_success == 0) {
            returnVector.resize(plaintext_length -1); 
            memcpy(returnVector.data(), plaintext, plaintext_length - 1);
        }
        free(plaintext);
    }
    return returnVector;
}
