#ifndef HMAC_ARGS_H
#define HMAC_ARGS_H

#include <argp.h>
#include <vector>
#include <iostream>
#include <string>
#include <unistd.h> // reference: https://www.gnu.org/software/libc/manual/html_node/getpass.html


typedef struct {
    std::string password;
    std::string outfile;
    std::string source_file;
    std::string verify_hash;
    std::string mode;
} arguments;



class HMACArgs 
{
    private:
        arguments args;
        

    public: 
        std::string get_password();
        std::string get_outfile();
        std::string get_sourcefile();
        std::string get_verify_hash();
        std::string get_mode();

        HMACArgs(int argc, char ** argv);
};


#endif