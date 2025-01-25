
#include "hmac.h"

void create_hmac(HMACArgs args) 
{
        std::vector<char> final_hash;
        final_hash.resize(SHA256_BLOCK_SIZE);
        std::string password = args.get_password();

        bool success = generate_hmac(
                args.get_sourcefile().data(),
                password.data(),
                password.size(),
                (char *) final_hash.data()
                );
        if (success) {
                if (args.get_outfile() == "STDOUT") {
                        print_vector_as_hex(final_hash);
                } else {
                        write_data_to_file(args.get_outfile(), final_hash);
                }
        } else {
                std::cerr << "There was an error." << std::endl;
                // you should have a more verbose error!
        }

}

void verify_hmac(HMACArgs args)
{
        std::vector<char> final_hash;
        final_hash.resize(SHA256_BLOCK_SIZE);
        std::string password = args.get_password();

        bool success = generate_hmac(
                args.get_sourcefile().data(),
                password.data(),
                password.size(),
                (char *) final_hash.data()
                );
        if (success) {
                char * buff_hash = sprint_hex(final_hash.data(), final_hash.size());
                std::string calculated_hash = buff_hash;
                free(buff_hash);
                buff_hash = NULL;

                if(calculated_hash == args.get_verify_hash()) {
                        std::cout << "Hashes match." << std::endl;
                } else {
                        std::cerr << "Hashes do not match." << "\n"
                        << "Calculated: "<< calculated_hash << "\n" 
                        << "Expected: " << args.get_verify_hash() << std::endl;
                        exit(1);
                }
        }
}

int main(int argc, char* argv[])
{
        HMACArgs args = HMACArgs(argc,argv);

        if (args.get_mode() == "create") {
                create_hmac(args);
        } else if (args.get_mode() == "verify") {
                verify_hmac(args);
        }
      
        return 0;
}