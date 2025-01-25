
#include "aes_args.h"
#include "aes_lib.h"

int main(int argc, char* argv[])
{
        AESArgs args = AESArgs(argc,argv,MODE_DECRYPT);
        
        std::vector<char> decrypted_content;
        
        decrypted_content = decrypt_file(args.get_encrypted_file(),args.get_password());

        if(decrypted_content.size() != 0) {
                write_data_to_file(args.get_plaintext_file(), decrypted_content);
        } else {
                std::cerr << "Error decrypting file." << std::endl;
                return -1;
        }

        return 0;
}