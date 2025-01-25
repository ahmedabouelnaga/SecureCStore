#include "aes_args.h"
#include "aes_lib.h"

int main(int argc, char* argv[])
{
        AESArgs args = AESArgs(argc,argv,MODE_ENCRYPT);
        
        auto encrypted = encrypt_file(args.get_plaintext_file(), args.get_password());
        
        if(encrypted.ciphertext.size() == 0) {
                perror("error opening infile");
                return -1; 
        }

        //sorry I don't know how to use vectors except as C arrays. 
        std::vector<char> data_to_write;
        data_to_write.resize(AES_BLOCK_SIZE + encrypted.ciphertext.size());
        memcpy((char *) data_to_write.data(), encrypted.IV, AES_BLOCK_SIZE);
        memcpy((char *) data_to_write.data()+AES_BLOCK_SIZE, 
                encrypted.ciphertext.data(), encrypted.ciphertext.size());


        write_data_to_file(args.get_encrypted_file(), data_to_write);
        
        return 0;
}