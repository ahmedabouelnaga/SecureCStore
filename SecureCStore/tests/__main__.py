from tests.test_cases import hmac_tests, aes_encrypt_tests, aes_decrypt_tests, cstore_tests
from tests.tester import HomeworkTestSuite
import sys

def part1():
        suite = HomeworkTestSuite(hmac_tests,title="./hmac Tests")
        suite.run_tests()

def part2():
        suite = HomeworkTestSuite(aes_encrypt_tests, title="./aes-encrypt Tests")
        suite.run_tests()
        suite = HomeworkTestSuite(aes_decrypt_tests, title="./aes-decrypt Tests")
        suite.run_tests()

def part3():
        suite = HomeworkTestSuite(cstore_tests,title="./cstore Tests")
        suite.run_tests()

if len(sys.argv) == 2:
        if sys.argv[1] == "part1":
                part1()
        elif sys.argv[1] == "part2":
                part2()
        elif sys.argv[1] == "part3":
                part3()