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
    subprocess.check_call(cmd)

@need_macos
def test_pynativelib_end_to_end(tmpdir, monkeypatch):
    def pathto(name):
        return os.path.join(TEST_DIR, "sample-macho", name)

    if not os.path.exists(pathto("native-lib.dylib")):
        run([sys.executable, pathto("build.py")])

    def mangler(name):
        return b"pynativelib_native_lib_" + name
    libraries_to_mangle = {
        b"native-lib.dylib":
          (b"/nonexistent-directory/mangled-native-lib.dylib", mangler),
    }

    buf = macho_macho_mapper(
        lambda b: rewrite_pynativelib_exports(b, mangler),
        read(pathto("native-lib.dylib")))
    write(tmpdir.join("mangled-native-lib.dylib"), buf)

    buf = macho_macho_mapper(
        lambda b: rewrite_pynativelib_imports(b, libraries_to_mangle),
        read(pathto("fake-pymodule.bundle")))
    write(tmpdir.join("mangled-fake-pymodule.dylib"), buf)

    shutil.copy(pathto("main-dlopen"), tmpdir.join("main-dlopen").strpath)

    buf = macho_macho_mapper(
        lambda b: rewrite_pynativelib_imports(b, libraries_to_mangle),
        read(pathto("main-envvar")))
    write(tmpdir.join("mangled-main-envvar"), buf)
    os.chmod(tmpdir.join("mangled-main-envvar").strpath, 0o700)

    with tmpdir.as_cwd():
        for arch in ["-32", "-64"]:
            print("Running tests for arch {}".format(arch))

            print("main-dlopen")
            run(["arch", arch, tmpdir.join("main-dlopen").strpath])

            print("mangled-main-envvar")
            run(["arch", arch,
                 "-e", "DYLD_LIBRARY_PATH=" + tmpdir.strpath,
                 tmpdir.join("mangled-main-envvar").strpath])
