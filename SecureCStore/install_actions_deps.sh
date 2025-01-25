#!/bin/bash

#python3 for tester
which python3 >/dev/null 2>/dev/null || (
    echo [+] installing python3
    sudo apt-get install -y python3
)

#pip for dependencies
which pip3 >/dev/null 2>/dev/null || (
    echo [+] installing python3-pip
    sudo apt-get install -y python3-pip
)

#look for pexpect
python3 -c "import pexpect" 2>/dev/null  1>/dev/null || (
    echo [+] installing pexpect python package
    pip3 install pexpect
)

#look for ptyprocess
python3 -c "import ptyprocess" 2>/dev/null  1>/dev/null || (
    echo [+] installing ptyprocess python package
    pip3 install ptyprocess
)

#look for Crypto
python3 -c "import Crypto" 2>/dev/null  1>/dev/null || (
    echo [+] installing pycryptodome python package
    pip3 install pycryptodome
)

# install valgrind 
which valgrind >/dev/null 2>/dev/null || (
    echo [+] installing valgrind
    sudo apt-get install -y valgrind
)
