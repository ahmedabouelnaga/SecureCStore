from secrets import choice, token_bytes
from string import ascii_letters
from os.path import exists
from os import unlink
import hmac
from hashlib import sha256
from subprocess import check_output, CalledProcessError
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

TEST_FILE_PATH="test-case-infile"
TEST_OUTFILE_PATH="test-case-outfile"

AES_BLOCK_SIZE=16

def password_to_key(password):
    if type(password) == str:
        password = password.encode()
    for i in range(10000):
        password = sha256(password).digest()
    return password

def random_str(length=8):
    return ''.join((choice(ascii_letters) for i in range(length)))




### AES FUNCTIONS

def test_aes_decrypt(self):
    self._test_files = [TEST_FILE_PATH, TEST_OUTFILE_PATH]
    self._plaintext_size=16
    data = token_bytes(self._plaintext_size)
    self._test_plaintext = data
    self.debug("\tUsing plaintext:{}".format(str(data)))
    password = random_str(16)
    key = password_to_key(password)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data+b"\x80", AES.block_size))
    iv = cipher.iv
    self.debug("\tUsing IV:{}".format(str(iv)))
    self.debug("\tUsing Ciphertext:{}".format(str(ct_bytes)))
    with open(self._test_files[0],"wb") as f:
        f.write(iv+ct_bytes)
    self.cmd_input = password
    self.cmd += "{} {}".format(TEST_FILE_PATH,TEST_OUTFILE_PATH)

def verify_aes_decrypt(self):
    plaintext = b""
    try:
        with open(self._test_files[1],"rb") as f:
            plaintext = f.read()
    except:
        self.errors.append("Unable to find outfile:{}".format((self._test_files[1])))
    if plaintext[:self._plaintext_size] != self._test_plaintext:
        self.errors.append("Plaintext did not match what was expected during decrypt.\n\tExpected:\t{}\n\tActual:\t{}".format(self._test_plaintext,plaintext))
    remove_test_files(self)


def test_aes_encrypt(self):
    self._test_files = [TEST_FILE_PATH, TEST_OUTFILE_PATH]
    data = token_bytes(16)
    self._test_plaintext = data
    self.debug("\tUsing plaintext:{}".format(str(data)))
    password = random_str(16)
    self._test_key = password_to_key(password)
    with open(self._test_files[0],"wb") as f:
        f.write(data)
    self.cmd_input = password
    self.cmd += "{} {}".format(TEST_FILE_PATH,TEST_OUTFILE_PATH)

def verify_aes_encrypt(self):
    ciphertext = b""
    try:
        with open(self._test_files[1],"rb") as f:
            ciphertext = f.read()
    except:
        self.errors.append("Unable to find outfile:{}".format((self._test_files[1])))
    expected_min_len = len(self._test_plaintext) + AES_BLOCK_SIZE
    actual_len = len(ciphertext)
    if actual_len < expected_min_len:
        self.errors.append(
            "Ciphertext should be at least {} bytes but it is actually: {}"
            .format(expected_min_len,actual_len).encode())
    else:
        iv = ciphertext[:16]
        cipher = AES.new(self._test_key, AES.MODE_CBC,iv)
        plaintext = cipher.decrypt(ciphertext[16:])
        self.debug("Found IV:{}".format(str(iv)))
        if len(plaintext) < len(self._test_plaintext):
            self.errors.append("Plaintext len is too short. Expected length of {}; actual length is {}".format(len(plaintext),len(self._test_plaintext)))
        else:
            truncated_plaintext = plaintext[:len(self._test_plaintext)]
            if truncated_plaintext != self._test_plaintext:
                self.errors.append("Plaintext did not match what was expected.\n\tExpected:\t{}\n\tActual:\t\t{}".format(self._test_plaintext, truncated_plaintext))
    remove_test_files(self)


### HMAC FUNCTIONS

def get_self_hmac(self):
    password = random_str()
    generated_hmac = wrap_check_output(["./hmac", "-p", password, "hmac"]).replace(b"\n",b"")
    self.cmd += "-p {} -v {} hmac".format(password,generated_hmac.decode())
    

def build_test_hash(self):
    self._test_files = [TEST_FILE_PATH]
    data = token_bytes(16)
    self.debug("\tUsing data:{}".format(str(data)))
    with open(TEST_FILE_PATH, "wb") as f:
        f.write(data)
    password = random_str(16)
    self.debug("\tUsing password:{}".format(password))
    self.cmd_input = password
    self.cmd += self._test_files[0]
    hmac_hash = hmac.new(key=password.encode(), msg=data, digestmod=sha256)
    expected_hash = hmac_hash.hexdigest().upper()
    self.expected_output.append("{}\r\n".format(expected_hash).encode())

def build_test_hash_and_verify(self):
    self._test_files = [TEST_FILE_PATH]
    data = token_bytes(16)
    self.debug("\tUsing data:{}".format(str(data)))
    with open(TEST_FILE_PATH, "wb") as f:
        f.write(data)
    password = random_str(16)
    hmac_hash = hmac.new(key=password.encode(), msg=data, digestmod=sha256)
    expected_hash = hmac_hash.hexdigest().upper()
    self.debug("\tUsing password:{}".format(password))
    self.cmd_input = password
    self.cmd += "-v {} {}".format(expected_hash, self._test_files[0])
    self.expected_output.append("{}\r\n".format("Hashes match.").encode())

def build_test_hash_and_verify_wrong(self):
    self._test_files = [TEST_FILE_PATH]
    data = token_bytes(16)
    self.debug("\tUsing data:{}".format(str(data)))
    with open(TEST_FILE_PATH, "wb") as f:
        f.write(data)
    password = random_str(16)
    hmac_hash = hmac.new(key=password.encode(), msg=data, digestmod=sha256)
    expected_hash = hmac_hash.hexdigest().upper()
    wrong_hash = "00000000" + expected_hash[8:]
    self.debug("\tUsing password:{}".format(password))
    self.cmd_input = password
    self.cmd += "-v {} {}".format(wrong_hash, self._test_files[0])
    expected_output = [
        b'Hashes do not match.\r\n',
        'Calculated: {}\r\n'.format(expected_hash).encode(), 
        'Expected: {}\r\n'.format(wrong_hash).encode()
    ]
    self.expected_output += expected_output


def wrap_check_output(cmd):
    return_var = ""
    try:
        return_var = check_output(cmd)
    except CalledProcessError as err:
        return_var = str(err).encode()
        print(return_var)
    return return_var

### CSTORE Functions

def make_new_cstore_with_single_file(self,fn=TEST_FILE_PATH):
    if(not hasattr(self, '_password')):
        self._password = random_str(16)
    data = token_bytes(16)
    self._test_data = data
    with open(fn, "wb") as f:
        f.write(data)
    self._test_files = [TEST_OUTFILE_PATH, fn]
    cmd = [
        self.cmd.split(" ")[0], #argv0
        "add",
        "-p",
        self._password,
        TEST_OUTFILE_PATH,
        fn
    ]
    wrap_check_output(cmd)
    if exists(self._test_files[1]):
        unlink(self._test_files[1])

def make_file_to_add(self):
    clean_test_file_remnants
    self._password = random_str(16)
    data = token_bytes(16)
    with open(TEST_FILE_PATH, "wb") as f:
        f.write(data)
    self._test_files = [TEST_OUTFILE_PATH, TEST_FILE_PATH]

    self.cmd += "-p {} {} {}" \
        .format(self._password, TEST_OUTFILE_PATH, TEST_FILE_PATH)

    self.files[TEST_OUTFILE_PATH] = b".*"

def verify_extracted_file(self):
    file_contents = b""
    try:
        with open(self._test_files[1],"rb") as f:
            file_contents = f.read()
    except:
        self.errors.append("Unable to find outfile:{}".format((self._test_files[1])))
        remove_test_files(self)
        return
    if file_contents != self._test_data:
        self.errors.append(
            ("Output file contents mismatch expected data\n" +
            "Expected Contents:{}\n" +
            "Actual Contents: {}")
            .format(self._test_data,file_contents))
    remove_test_files(self)


def list_files_and_ensure_test_file_is_gone(self):
    cmd = [
        self.cmd.split(" ")[0], #argv0
        "list",
        TEST_OUTFILE_PATH,
    ]
    removed_file = self._test_files[1].split("/")[-1:][0].encode()
    list_output = wrap_check_output(cmd)
    if removed_file in list_output:
        self.errors.append(("Failed to remove file from archive\n" + \
            "List command showed the following output: {}\n" + \
            "It should not have contained: {}").format(str(list_output),removed_file))
    remove_test_files(self)

def make_new_cstore_with_single_file_and_setup_list(self):
    clean_test_file_remnants()
    make_new_cstore_with_single_file(self)
    self.cmd += self._test_files[0]

    self.expected_output += [
        ".*{}.*"
        .format(self._test_files[1].split("/")[-1:][0])
        .encode()
    ]

def make_new_cstore_with_single_file_and_add_to_cmd_two_args(self):
    clean_test_file_remnants()
    make_new_cstore_with_single_file(self)
    self.cmd += "-p {} {} {}".format(self._password, self._test_files[0], self._test_files[1])


def make_new_cstore_with_two_files_and_add_to_cmd_two_args(self):
    clean_test_file_remnants()
    SECOND_FILE="test-second-file"
    make_new_cstore_with_single_file(self,fn=SECOND_FILE)
    make_new_cstore_with_single_file(self)
    self.cmd += "-p {} {} {}".format(self._password, self._test_files[0], self._test_files[1])

### GENERIC FUNCTIONS 

def clean_test_file_remnants():
    _remove_test_files([TEST_FILE_PATH,TEST_OUTFILE_PATH])

def _remove_test_files(files):
    for test_file in files:
        if exists(test_file):
            unlink(test_file)

def remove_test_files(self):
    _remove_test_files(self._test_files)