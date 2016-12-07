#!/bin/bash

# using debian mingw-w64

ARCH=i686
PLATFORM=${ARCH}-w64-mingw32
CC=${PLATFORM}-gcc
STRIP=${PLATFORM}-strip

set -xe

${CC} -shared test_dll.c -o test_dll.dll
${CC} test.c -o test.exe -L. -ltest_dll
# I don't know why this is necessary.
${STRIP} test.exe
