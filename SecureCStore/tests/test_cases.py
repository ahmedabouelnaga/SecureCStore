from tests.tester import HomeworkTestCase, HomeworkTestSuite
from tests.helper_functions import test_aes_decrypt, verify_aes_decrypt
from tests.helper_functions import test_aes_encrypt, verify_aes_encrypt
from tests.helper_functions import get_self_hmac, build_test_hash, build_test_hash_and_verify, build_test_hash_and_verify_wrong
from tests.helper_functions import make_new_cstore_with_single_file_and_setup_list, make_new_cstore_with_single_file_and_add_to_cmd_two_args, make_file_to_add, verify_extracted_file, list_files_and_ensure_test_file_is_gone, make_new_cstore_with_two_files_and_add_to_cmd_two_args
from tests.helper_functions import remove_test_files
HMAC_BIN = "hmac"

AES_ENCRYPT_BIN = "aes-encrypt"
AES_DECRYPT_BIN = "aes-decrypt"

CSTORE_BIN = "cstore"



hmac_tests = [
        HomeworkTestCase( # help message
            cmd = "./{} --help".format(HMAC_BIN),
            expected_output = [b'Usage: hmac [OPTION...] source_file\r\n', b'Make an HMAC of the file stored at source_file\r\n', b'\r\n', b'  -o, --outfile=filename     File to write hmac to as binary; otherwise prints\r\n', b'                             to stdout as hex\r\n', b'  -p, --password=password    The password to use; will prompt if not given\r\n', b'  -v, --verify=hash          Verify an existing hash, provided as a hex-encoded\r\n', b'                             ascii string\r\n', b'  -?, --help                 Give this help list\r\n', b'      --usage                Give a short usage message\r\n', b'\r\n', b'Mandatory or optional arguments to long options are also mandatory or optional\r\n', b'for any corresponding short options.\r\n'],
            summary = "get help statement"
        ),
        HomeworkTestCase( # internally consistent
            cmd = "./{} ".format(HMAC_BIN),
            cmd_input = "", 
            setup_fn = get_self_hmac,
            expected_output = [b"Hashes match.\r\n"],
            summary = "generate a hash and check it is internally validated"
        ),
        HomeworkTestCase( # correct hash
            cmd = "./{} ".format(HMAC_BIN),
            cmd_input = "", #dynamically updated by setup_fn
            expected_output = [b'\tPlease enter a password to use: \r\n'], #dynamically appended to by setup_fn
            setup_fn = build_test_hash,
            teardown_fn = remove_test_files,
            summary = "verify hmac correctness"
        ),
        HomeworkTestCase( # correct verify
            cmd = "./{} ".format(HMAC_BIN),
            cmd_input = "", #dynamically updated by setup_fn
            expected_output = [b'\tPlease enter a password to use: \r\n'], #dynamically appended to by setup_fn
            setup_fn = build_test_hash_and_verify,
            teardown_fn = remove_test_files,
            summary = "verify hmac verification - correct match"
        ),
        HomeworkTestCase( # detects wrong on verify
            cmd = "./{} ".format(HMAC_BIN),
            cmd_input = "", #dynamically updated by setup_fn
            expected_output = [b'\tPlease enter a password to use: \r\n'], #dynamically appended to by setup_fn
            setup_fn = build_test_hash_and_verify_wrong,
            teardown_fn = remove_test_files,
            summary = "verify hmac verification - incorrect match"
        )
]
aes_decrypt_tests = [
        HomeworkTestCase( # help message
            cmd = "./{} --help".format(AES_DECRYPT_BIN),
            expected_output = [b'Usage: aes-decrypt [OPTION...] encrypted_in plaintext_out\r\n', b'Decrypt a file using AES-CBC\r\n', b'\r\n', b'  -p, --password=password    The password to use; will prompt if not given\r\n', b'  -?, --help                 Give this help list\r\n', b'      --usage                Give a short usage message\r\n', b'\r\n', b'Mandatory or optional arguments to long options are also mandatory or optional\r\n', b'for any corresponding short options.\r\n'],
            summary = "get help statement"
        ),
        HomeworkTestCase( # decrypt a file
            cmd = "./{} ".format(AES_DECRYPT_BIN),
            expected_output = [b'\tPlease enter a password to use: \r\n'],
            summary = "decrypt file",
            setup_fn = test_aes_decrypt,
            teardown_fn = verify_aes_decrypt
        ),
]

aes_encrypt_tests = [
        HomeworkTestCase( # help message
            cmd = "./{} --help".format(AES_ENCRYPT_BIN),
            expected_output = [b'Usage: aes-encrypt [OPTION...] plaintext_in encrypted_out\r\n', b'Encrypt a file using AES-CBC\r\n', b'\r\n', b'  -p, --password=password    The password to use; will prompt if not given\r\n', b'  -?, --help                 Give this help list\r\n', b'      --usage                Give a short usage message\r\n', b'\r\n', b'Mandatory or optional arguments to long options are also mandatory or optional\r\n', b'for any corresponding short options.\r\n'],
            summary = "get help statement"
        ),
        HomeworkTestCase( # encrypt a file
            cmd = "./{} ".format(AES_ENCRYPT_BIN),
            expected_output = [b'\tPlease enter a password to use: \r\n'],
            summary = "encrypt file",
            setup_fn = test_aes_encrypt,
            teardown_fn = verify_aes_encrypt
        ),
]

cstore_tests = [
        HomeworkTestCase( # list
            cmd = "./{} list ".format(CSTORE_BIN),
            summary = "list files in cstore",
            setup_fn = make_new_cstore_with_single_file_and_setup_list,
            teardown_fn = remove_test_files
        ),
        HomeworkTestCase( # add
            cmd = "./{} add ".format(CSTORE_BIN),
            summary = "add file to cstore",
            setup_fn = make_file_to_add,
            teardown_fn = remove_test_files
        ),
        HomeworkTestCase( # extract
            cmd = "./{} extract ".format(CSTORE_BIN),
            summary = "extract file from cstore",
            setup_fn = make_new_cstore_with_single_file_and_add_to_cmd_two_args,
            teardown_fn = verify_extracted_file
        ),
        HomeworkTestCase( # delete
            cmd = "./{} delete ".format(CSTORE_BIN),
            summary = "delete file from cstore",
            setup_fn = make_new_cstore_with_two_files_and_add_to_cmd_two_args,
            teardown_fn = list_files_and_ensure_test_file_is_gone
        ),
]



def run_tests(tests):
    suite = HomeworkTestSuite(tests)
    suite.run_tests()