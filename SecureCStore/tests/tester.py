#!/usr/bin/env python

import re
from pexpect import spawn
from os.path import exists
from copy import deepcopy
import sys

VALGRIND = "/usr/bin/valgrind --leak-check=full -q {}"

class HomeworkTestCase:

    def __init__(self,cmd,cmd_input="",expected_output=False,files=False,setup_fn=lambda _ :0, teardown_fn=lambda _ :0, show_debug=True, buffer_debug=True, summary=""):
        self.cmd = cmd
        self.cmd_input = cmd_input
        if expected_output:
            self.expected_output = expected_output
        else:
            self.expected_output = []
        if files:
            self.files = files
        else:
            self.files = {}
        self.setup_fn = setup_fn
        self.teardown_fn = teardown_fn
        self.show_debug = show_debug
        self.buffer_debug = buffer_debug
        self.summary = summary
        self._test_files = []

        self.msg_buffer = []


    def _execute_cmd(self,cmd):
        proc = spawn(cmd)
        if self.cmd_input != "":
            proc.sendline(self.cmd_input)
        self.output = proc.readlines()
        proc.close()

    def display_debug(self,str):
        if self.show_debug:
            print(str)

    def display_debug_buffer(self):
        for msg in self.msg_buffer:
            self.display_debug(msg)
    

    def debug(self,str):
        if self.buffer_debug:
            self.msg_buffer.append(str)
            return
        self.display_debug(str)

    def execute_test(self):
        self.debug("##### Running Test: {} #####".format(self.summary))
        self.setup_fn(self)
        self._execute_cmd(self.cmd)
        self.check_result()
        self.teardown_fn(self)
        self.print_result()
        if not self.passed:
            self.debug("Command Used:{}".format(self.cmd))

    def check_result(self):
        errors = []
        if len(self.expected_output) != len(self.output):
            errors.append("Actual output line count differed from expected."
                "\n\tExpected:{}\n\tActual:{}".format(
                    str(self.expected_output),
                    str(self.output)))
        else:
            for expected_line, actual_line in zip(self.expected_output,self.output):
                if re.match(expected_line,actual_line) == None and \
                    expected_line != actual_line:
                    errors.append("Output differed from expected."
                        "\n\tExpected:{}\n\tActual:{}".format(
                        str(expected_line),
                        str(actual_line)))
        for filename in self.files:
            expected_contents = self.files[filename]
            if not exists(filename):
                errors.append("Expected file does not exist: {}".format(filename))
            else:
                try:
                    with open(filename,"rb") as f:
                        actual_contents = f.read()
                        if re.match(expected_contents,actual_contents) == None and \
                            expected_contents != actual_contents:
                            errors.append("Contents of {} did not match expected.\n\t"
                                          "Wanted: {}\n\tGot: {}"
                                          .format(filename,expected_contents,actual_contents))
                except:
                    errors.append("Unable to open {}".format(filename))



        self.errors = errors

    def print_result(self):
        if self.passed:
            self.debug("[+] Test Passed!")
        else:
            self.debug("[!] Test Failed! Errors:")
            for error in self.errors:
                self.debug(error)

    @property
    def passed(self):
        return len(self.errors) == 0

                    

    
class HomeworkTestSuite:

    def __init__(self, test_cases, title=""):
        self.test_cases = test_cases
        self.successes = 0
        self.fails = 0
        self.count = 0
        self.title = title
    
    def display_report(self):
        print("Tests Conducted:{}".format(self.count))
        print("Tests Passed:\t{}".format(self.successes))
        print("Tests Failed:\t{}".format(self.fails))

    def run_tests(self):
        if self.title != "":
            print("=>=> Starting Test Suite for {} <=<=".format(self.title))
        for test_case in self.test_cases:
            test = deepcopy(test_case)
            test.buffer_debug = True
            test.execute_test()
            if test.passed:
                self.successes += 1
            else:
                self.fails += 1
                test.display_debug_buffer()

            self.count += 1
        self.display_report()
        if self.fails > 0:
            sys.exit(1)
        
            

