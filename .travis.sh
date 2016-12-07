#!/bin/bash

set -ex

if [ "$TRAVIS_OS_NAME" = "osx" ]; then
    curl -O macpython.pkg https://www.python.org/ftp/python/${MACPYTHON}/python-${MACPYTHON}-macosx10.6.pkg
    sudo installer -pkg macpython.pkg -target /
    ls /Library/Frameworks/Python.framework/Versions/*/bin/
    PYTHON_EXE=/Library/Frameworks/Python.framework/Versions/*/bin/python
fi

pip install -U pip

pip install .
pip install -Ur test-requirements.txt

pytest --cov=redll --cov-config=.coveragerc redll

pip install codecov && codecov