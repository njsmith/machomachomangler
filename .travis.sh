#!/bin/bash

set -ex

if [ "$TRAVIS_OS_NAME" = "osx" ]; then
    curl -o macpython.pkg https://www.python.org/ftp/python/${MACPYTHON}/python-${MACPYTHON}-macosx10.6.pkg
    sudo installer -pkg macpython.pkg -target /
    ls /Library/Frameworks/Python.framework/Versions/*/bin/
    if expr "${MACPYTHON}" : 2; then
        PYBASE=python
    else
        PYBASE=python3
    fi
    PYTHON_EXE=/Library/Frameworks/Python.framework/Versions/*/bin/${PYBASE}
    sudo $PYTHON_EXE -m pip install virtualenv
    $PYTHON_EXE -m virtualenv testenv
    source testenv/bin/activate
fi

pip install -U pip

pip install .
INSTALLDIR=$(python -c "import os, machomachomangler; print(os.path.dirname(machomachomangler.__file__))")

pip install -Ur test-requirements.txt

mkdir empty
cd empty
pytest -ra --cov="$INSTALLDIR" --cov-config=../.coveragerc --pyargs machomachomangler

pip install codecov && codecov