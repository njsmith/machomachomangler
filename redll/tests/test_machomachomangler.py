import sys
import os.path
import subprocess
import shutil

from ..machomachomangler import (
    macho_macho_mapper,
    rewrite_pynativelib_imports, rewrite_pynativelib_exports,
)

import pytest

TEST_DIR = os.path.dirname(os.path.abspath(__file__))

need_macos = pytest.mark.skipif(sys.platform != "darwin",
                                reason="needs macos")

def read(path):
    with open(path, "rb") as f:
        return f.read()

def write(path, buf):
    if hasattr(path, "strpath"):
        path = path.strpath
    with open(path, "wb") as f:
        f.write(buf)

def run(cmd):
    print(cmd)
    subprocess.check_call(cmd)

@need_macos
def test_pynativelib_end_to_end(tmpdir, monkeypatch):
    for subdir in ["i386", "x86_64", "fat"]:
        print("Doing end-to-end tests for {} binaries".format(subdir))
        subtmpdir = tmpdir.join(subdir)
        subtmpdir.ensure(dir=True)

        def inpath(*args):
            return os.path.join(TEST_DIR, "sample-macho", subdir, *args)
        def outpath(*args):
            return subtmpdir.join(*args).strpath

        if not os.path.exists(inpath("native-lib.dylib")):
            run([sys.executable,
                 os.path.join(TEST_DIR, "sample-macho", "build.py")])

        def mangler(name):
            return b"pynativelib_native_lib_" + name

        libraries_to_mangle = {
            b"native-lib.dylib":
              (b"/nonexistent-directory/mangled-native-lib.dylib", mangler),
        }

        buf = macho_macho_mapper(
            lambda b: rewrite_pynativelib_exports(b, mangler),
            read(inpath("native-lib.dylib")))
        write(outpath("mangled-native-lib.dylib"), buf)

        buf = macho_macho_mapper(
            lambda b: rewrite_pynativelib_imports(b, libraries_to_mangle),
            read(inpath("fake-pymodule.bundle")))
        write(outpath("mangled-fake-pymodule.dylib"), buf)

        shutil.copy(inpath("main-dlopen"), outpath("main-dlopen"))

        buf = macho_macho_mapper(
            lambda b: rewrite_pynativelib_imports(b, libraries_to_mangle),
            read(inpath("main-envvar")))
        write(outpath("mangled-main-envvar"), buf)
        os.chmod(outpath("mangled-main-envvar"), 0o700)

        arches_to_run = {
            "i386": ["-32"],
            "x86_64": ["-64"],
            "fat": ["-32", "-64"],
        }

        with subtmpdir.as_cwd():
            for arch in arches_to_run[subdir]:
                print("Running tests with 'arch {}'".format(arch))

                print("main-dlopen")
                run(["arch", arch, outpath("main-dlopen")])

                print("mangled-main-envvar")
                run(["arch", arch,
                     "-e", "DYLD_LIBRARY_PATH=" + subtmpdir.strpath,
                     outpath("mangled-main-envvar")])
