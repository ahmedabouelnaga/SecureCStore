from tests.tester import HomeworkTestCase
from secrets import choice, token_bytes
from string import ascii_letters
from os.path import exists
from os import unlink
from copy import deepcopy
import hmac
from hashlib import sha256


def random_str(length=8):
    return ''.join((choice(ascii_letters) for i in range(length)))

def build_test_hash(self):
    self._test_file = "/tmp/testfile"
    data = token_bytes(16)
    self.debug("Using data:{}".format(str(data)))
    with open(self._test_file,"wb") as f:
        f.write(data)
    password = random_str(16)
    self.debug("Using password:{}".format(password))
    self.cmd_input = password
    self.cmd += self._test_file
    hmac_hash = hmac.new(key=password.encode(), msg=data, digestmod=sha256)
    expected_hash = hmac_hash.hexdigest().upper()
    self.expected_output.append("{}\r\n".format(expected_hash).encode())
    

def remove_test_file(self):
    pass
    #if exists(self._test_file):
       # unlink(self._test_file)

basic_tests = [
    [
        HomeworkTestCase( # help message
            cmd = "./hmac --help",
            expected_output = [b'Usage: hmac [OPTION...] source_file\r\n', b'Make an HMAC of the file stored at source_file\r\n', b'\r\n', b'  -o, --outfile=filename     File to write hmac to as binary; otherwise prints\r\n', b'                             to stdout as hex\r\n', b'  -p, --password=password    The password to use; will prompt if not given\r\n', b'  -v, --verify=hash          Verify an existing hash, provided as a hex-encoded\r\n', b'                             ascii string\r\n', b'  -?, --help                 Give this help list\r\n', b'      --usage                Give a short usage message\r\n', b'\r\n', b'Mandatory or optional arguments to long options are also mandatory or optional\r\n', b'for any corresponding short options.\r\n'],
            summary = "get help statement"
        ),
        HomeworkTestCase( # correct hash
            cmd = "./hmac ",
            cmd_input = "test",
            expected_output = [b'\tPlease enter a password to use: \r\n'],
            files = [],
            setup_fn = build_test_hash,
            teardown_fn = remove_test_file,
            summary = "verify correctness"
        )
        # correct verify
        # internally consistent
        # rejects incorrect verify
    ]
]


def run_tests(tests):
    for test_set in tests:
        for cur_test in test_set:
            test_copy = deepcopy(cur_test)
            test_copy.execute_test()
            test_copy.print_result()
