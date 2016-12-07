# We ship the build files to avoid a dependency on having a Windows C compiler
# around to run tests, and, more importantly, a bunch of annoying code to
# figure out how to run the particular C compiler that's installed on the
# particular OS where this is running.
#
# So, re-run this file if you ever modify the code in src/
#
# The code below is currently written on the assumption that you're on a
# Debian-like system with both 32- and 64-bit versions of their mingw-w64
# cross-toolchain packages installed.

import os
import os.path
import subprocess

os.chdir(os.path.dirname(os.path.abspath(__file__)))

def run(*args, **kwargs):
    kwargs["check"] = True
    return subprocess.run(*args, **kwargs)

for arch in ["i686", "x86_64"]:
    platform = arch + "-w64-mingw32"
    CC = platform + "-gcc"
    STRIP = platform + "-strip"
    run([CC, "-shared", "src/sample-dll.c",
         "-o", arch + "/sample-dll.dll"])
    run([STRIP, arch + "/sample-dll.dll"])
    run([CC, "src/main.c", "-L" + arch, "-lsample-dll",
         "-o", arch + "/main.exe"])
    run([STRIP, arch + "/main.exe"])
