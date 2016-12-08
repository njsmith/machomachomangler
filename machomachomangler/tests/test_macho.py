import sys
import os.path
import subprocess
import shutil
import ctypes

from ..macho import (
    macho_macho_mapper,
    rewrite_pynativelib_imports, rewrite_pynativelib_exports,
    make_pynativelib_export_reexporter,
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
            lambda b:
              rewrite_pynativelib_exports(
                  b, b"mangled-native-lib.dylib", mangler),
            read(inpath("native-lib.dylib")))
        write(outpath("mangled-native-lib.dylib"), buf)

        buf = macho_macho_mapper(
            lambda b:
              make_pynativelib_export_reexporter(
                  b,
                  b"@loader_path/mangled-native-lib.dylib", mangler,
                  b"placeholder-for-native-lib.dylib"),
            read(inpath("native-lib.dylib")))
        write(outpath("placeholder-for-native-lib.dylib"), buf)

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

        bits_to_test = {
            "i386": [32],
            "x86_64": [64],
            "fat": [32, 64],
        }

        with subtmpdir.as_cwd():
            for bits in bits_to_test[subdir]:
                print()
                print("Running {}-bit tests in {} subdir".format(bits, subdir))

                arch_flag = "-{}".format(bits)

                print("main-dlopen")
                run(["arch", arch_flag, outpath("main-dlopen")])

                print("mangled-main-envvar")
                run(["arch", arch_flag,
                     "-e", "DYLD_LIBRARY_PATH=" + subtmpdir.strpath,
                     outpath("mangled-main-envvar")])

                python_bits = 8 * ctypes.sizeof(ctypes.c_void_p)
                print("python_bits =", python_bits)
                if bits == python_bits:
                    print("ctypes on placeholder lib")
                    lib = ctypes.CDLL(outpath("placeholder-for-native-lib.dylib"))
                    native_int = ctypes.c_int.in_dll(lib, "native_int")
                    assert native_int.value == 13
                    lib.native_func.restype = ctypes.c_int
                    assert lib.native_func() == 14
