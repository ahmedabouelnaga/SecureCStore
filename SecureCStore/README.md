[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/SGAfAlby)
[![Open in Visual Studio Code](https://classroom.github.com/assets/open-in-vscode-2e0aaae1b6195c2367325f4f02e2d04e9abb55f0b24a779b69b11b9e10269abc.svg)](https://classroom.github.com/online_ide?assignment_repo_id=16173943&assignment_repo_type=AssignmentRepo)
# HW1
 
## Reminder:

* Please remember to place your UNI in `UNI.txt`. Do not put anything else in this file

* Please remember to complete `references.txt`
 
    Argument Parsing (cstore_args.cpp and cstore_args.h):
        The class CStoreArgs is responsible for parsing the command-line arguments. This includes determining the action (add, list, extract), the password for encryption, the archive name, and the files to be operated on.
        Command-line arguments are parsed based on the assumption that the password follows the -p flag, and the remaining arguments represent files or archive names.
    File Handling and Archive Operations (cstore.cpp):
        The program has three main actions:
            add: Adds files to the archive.
            list: Lists the files inside the archive.
            extract: Extracts specific files from the archive.
        The logic in create_archive ensures that files are added to an archive, checking for the archive's existence before overwriting or creating a new one.
        The extract action reads the encrypted file data from the archive and decrypts it using the password provided by the user.
    Encryption and Integrity (cstore_object.cpp and cstore_object.h):
        The CStoreObject class handles encryption, decryption, and maintaining the archive's integrity.
        Files are encrypted using AES (Advanced Encryption Standard), and each file's ciphertext is stored in the archive.
        An HMAC (Hash-based Message Authentication Code) is generated to ensure the integrity of the archive. Any tampering with the archive will result in a signature mismatch, and the program will refuse to proceed with actions like extraction.
    Signature and Integrity Check:
        Each archive has a signature generated using SHA256, and the program verifies the archive's integrity by recalculating the signature when extracting files or listing files.
        If the signature check fails, the program prints an error message and stops execution to prevent file corruption or security breaches.
Edge Cases:
    File Does Not Exist:
        When trying to add a file to the archive, the program checks whether the file exists. If the file does not exist or cannot be opened, an error message is printed, and the operation is aborted.
    Empty File:
        If a file is empty (0 bytes), the program will recognize this and print an error message instead of adding the file to the archive. This prevents the storage of useless data.
    Invalid Archive Name:
        If the archive name is invalid or cannot be created/opened, the program prints an error and exits.
    Invalid Password:
        If the password provided for decrypting files is incorrect, the decryption will fail, and the program will terminate without extracting the files. This ensures that files cannot be accessed without the correct password.
    Signature Mismatch:
        The HMAC signature of the archive is recalculated during extraction or listing operations. If the signature doesn’t match (indicating potential tampering or corruption), the program halts to ensure that no tampered files are processed.
    User Aborts Archive Overwrite:
        If an archive already exists, the program asks the user for confirmation before overwriting it. If the user does not confirm the overwrite, the operation is aborted, and no files are added.
    Archive Does Not Exist for Extraction:
        If the user attempts to extract or list files from an archive that does not exist, the program prints an error and stops the operation.
Testing:
    Basic Functional Tests:
        cstore add -p password archive_name file1.txt file2.txt: This command tests adding multiple files to a new archive and checks that encryption is applied.
        cstore list archive_name: This lists the files in the archive without requiring the password, testing whether the list functionality works as intended.
        cstore extract -p password archive_name file1.txt: This command tests extracting a specific file from the archive, checking whether decryption works properly.
    Edge Case Testing:
        Testing what happens when trying to add a file that does not exist: The program should print an error and not modify the archive.
        Testing empty files: Ensures the program doesn't store empty files.
        Testing signature mismatch: Modify the archive manually and then attempt to list or extract files. The program should detect tampering and halt.
    Password Validation Testing:
        Providing an incorrect password during the extraction process should result in decryption failure and an appropriate error message.
