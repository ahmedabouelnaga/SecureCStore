    #include "cstore_args.h"
    #include <iostream>
    CStoreArgs::CStoreArgs(int argc, char* argv[]) {
        // Parse command line arguments
        if (argc < 4) {
            std::cerr << "Usage: cstore <action> -p <password> <archive_name> [files...]" << std::endl;
            exit(1);
        }
        action = argv[1];
        password = argv[3];
        archive_name = argv[4];
        if (std::string(argv[2]) != "-p") {
            std::cerr << "ERROR: Password flag (-p) missing." << std::endl;
            exit(1);
        }
        // Collect file arguments if provided
        for (int i = 5; i < argc; ++i) {
            files.push_back(argv[i]);
        }
    }
    std::string CStoreArgs::get_archive_name() {
        return archive_name;
    }

    std::string CStoreArgs::get_password() {
        return password;
    }
    std::string CStoreArgs::get_action() {
        return action;
    }

    std::vector<std::string> CStoreArgs::get_files() {
        return files;
    }


