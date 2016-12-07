import os
import os.path
import subprocess

os.chdir(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    print(cmd)
    subprocess.check_call(cmd)

CC = ["clang", "-arch", "i386", "-arch", "x86_64"]

run(CC + ["-shared", "native-lib.c", "-o", "native-lib.dylib"])
run(CC + ["-bundle", "fake-pymodule.c", "./native-lib.dylib",
          "-o", "fake-pymodule.bundle"])
run(CC + ["main-dlopen.c", "-o", "main-dlopen"])
run(CC + ["main-envvar.c", "./native-lib.dylib", "-o", "main-envvar"])
