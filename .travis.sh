#!/bin/bash

set -ex

if [ "$TRAVIS_OS_NAME" = "osx" ]; then
    curl -o macpython.pkg https://www.python.org/ftp/python/${MACPYTHON}/python-${MACPYTHON}-macosx10.6.pkg
    sudo installer -pkg macpython.pkg -target /
    ls /Library/Frameworks/Python.framework/Versions/*/bin/
    # XX will have to update this if we start supporting py2
    PYTHON_EXE=/Library/Frameworks/Python.framework/Versions/*/bin/python3
    sudo $PYTHON_EXE -m pip install virtualenv
    sudo $PYTHON_EXE -m virtualenv testenv
    source testenv/bin/activate
fi

pip install -U pip

pip install .
pip install -Ur test-requirements.txt

pytest --cov=redll --cov-config=.coveragerc redll

pip install codecov && codecov