#include "cstore_args.h"
#include "cstore_object.h"
#include <algorithm>
void create_archive(CStoreObject cstore) {
    char* signature = cstore.get_signature();
    char null_char = '\0';
    const char* archive_name_ptr = cstore.get_archive_name().c_str();
    unsigned int num_files = cstore.get_num_files();
    std::vector<unsigned long long int> file_sizes = cstore.get_file_sizes();
    std::vector<std::string> file_names = cstore.get_file_names();
    std::vector<std::string> encrypted_file_datas = cstore.get_encrypted_file_datas();
    remove(archive_name_ptr);
    FILE* archive = fopen(archive_name_ptr, "wb");
    if (archive == NULL) {
        cstore.print_error_and_quit("ERROR: Couldn't create archive file.");
    }
    if (fwrite(MAGIC, sizeof(char), 8, archive) != 8) {
        fclose(archive);
        cstore.print_error_and_quit("ERROR: Couldn't write MAGIC (./cstore) to archive.");
    }
    if (fwrite(signature, sizeof(char), SHA256_BLOCK_SIZE, archive) != SHA256_BLOCK_SIZE) {
        fclose(archive);
        cstore.print_error_and_quit("ERROR: Couldn't write signature to archive.");
    }
    if (fwrite(&num_files, sizeof(unsigned int), 1, archive) != 1) {
        fclose(archive);
        cstore.print_error_and_quit("ERROR: Couldn't write num_files to archive.");
    }
    for (unsigned int i = 0; i < num_files; i++) {
        const char* curr_file_name = file_names[i].c_str();
        unsigned int curr_file_name_length = strlen(curr_file_name);
        unsigned long long int curr_file_size = file_sizes[i];
        const char* curr_file_data = encrypted_file_datas[i].c_str();
        if (fwrite(curr_file_name, sizeof(char), curr_file_name_length, archive) != curr_file_name_length) {
            fclose(archive);
            cstore.print_error_and_quit("ERROR: couldn't write file_name to thearchive.");
        }
        for (unsigned int i = 0; i < 20 - curr_file_name_length; i++) {
            if (fwrite(&null_char, sizeof(char), 1, archive) != 1) {
                fclose(archive);
                cstore.print_error_and_quit("ERROR: couldn't pad file_name while writing to the archive.");
            }
        }
        if (fwrite(&curr_file_size, sizeof(unsigned long long int), 1, archive) != 1) {
            fclose(archive);
            cstore.print_error_and_quit("ERROR: Wasn't able tp write curr_file_size(file size) to archive.");
        }
        if (fwrite(curr_file_data, sizeof(char), curr_file_size, archive) != curr_file_size) {
            fclose(archive);
            cstore.print_error_and_quit("ERROR: couldn't write ciphertext to archive.");
        }
    }
    fclose(archive);
}
int main(int argc, char* argv[]) {
    CStoreArgs args = CStoreArgs(argc, argv);
    bool archive_exists = (access(args.get_archive_name().c_str(), F_OK) != -1);
    if (args.get_action() == "list") {
        if (archive_exists) {
            CStoreObject cstore(args, archive_exists);
            std::cout << "Here is the list of the files that are in the archive:" << std::endl;
            std::vector<std::string> file_names = cstore.get_file_names();
            std::sort(file_names.begin(), file_names.end());
            for (const std::string& file_name : file_names) {
                std::cout << file_name << std::endl;
            }
        } else {
            std::cerr << "Archive doesn't exist." << std::endl;
            return 1;
        }
    } else if (args.get_action() == "add") {
        if (archive_exists) {
            std::cout << "Do you want to overwrite the existing archive (yes/no)? ";
            std::string response;
            std::cin >> response;
            if (response != "yes" && response != "Yes" && response != "YES" && response != "Y" && response != "y") {
                std::cout << "Enter a different archive name:" << std::endl;
                return 1;
            }
        }
        CStoreObject cstore(args, archive_exists);
        create_archive(cstore);
        std::cout << "Files is successfully added to archive." << std::endl;
    } else if (args.get_action() == "extract") {
        if (!archive_exists) {
            std::cerr << "Archive doesn't exist." << std::endl;
            return 1;
        } else {
            CStoreObject cstore(args, archive_exists);
            std::vector<std::string> file_names_to_extract = args.get_files();
            std::vector<std::string> file_names = cstore.get_file_names();
            std::vector<unsigned int> file_name_idxs;
            for (const std::string& file_name_to_extract : file_names_to_extract) {
                unsigned int idx = 0;
                bool found_file = false;
                for (const std::string& file_name : file_names) {
                    if (file_name == file_name_to_extract) {
                        found_file = true;
                        file_name_idxs.push_back(idx);
                        break;
                    }
                    idx++;
                }
                if (!found_file) {
                    cstore.print_error_and_quit("Error: Cannot find file to extract from.");
                }
            }
            for (unsigned int idx : file_name_idxs) {
                std::ofstream temp_file("temp_file");
                if (temp_file.is_open()) {
                    temp_file << cstore.get_encrypted_file_datas()[idx];
                    temp_file.close();
                    std::vector<char> decrypted_content = decrypt_file("temp_file", args.get_password());
                    remove("temp_file");
                    if (decrypted_content.size() != 0) {
                        write_data_to_file(file_names[idx], decrypted_content);
                    } else {
                        cstore.print_error_and_quit("ERROR: Couldn't decrypt the file.");
                    }
                } else {
                    cstore.print_error_and_quit("ERROR: Couldn't open temp_file(temporary file).");
                }
            }
            std::cout << "Files were successfully extracted." << std::endl;
        }
    } else {
        return 0;
    }
    return 1;
}
