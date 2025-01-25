#ifndef CSTORE_ARGS_H
#include <unistd.h>
#define CSTORE_ARGS_H
#include <string.h>
#include <argp.h>
#include <vector>
#include <iostream>
#include <string>
#define MAX_FILENAME_LENGTH 20
class CStoreArgs
{
    private:
        std::string password;
        std::string archive_name;
        std::vector<std::string> files;
        std::string action;
        bool valid;
    public:
        std::string get_archive_name();
        std::string get_action();
        std::vector<std::string> get_files();
        std::string get_password();
        CStoreArgs(int argc, char ** argv);
};
#endif
