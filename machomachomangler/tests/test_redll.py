import sys
import os.path
import subprocess
import shutil

import pytest

TEST_DIR = os.path.dirname(os.path.abspath(__file__))

can_run_exe = (shutil.which("wine") is not None or os.name == "nt")
need_run_exe = pytest.mark.skipif(not can_run_exe,
                                  reason="needs wine or windows")

def run_exe(path, *, expect_success=True):  # pragma: no cover
    if hasattr(path, "strpath"):
        path = path.strpath
    path = os.path.abspath(path)
    if os.name == "nt":
        runner = []
    else:
        runner = ["wine"]
    returncode = subprocess.call(runner + [path])
    if expect_success:
        assert returncode == 0
    else:
        assert returncode != 0

@need_run_exe
def test_redll_end_to_end(tmpdir, monkeypatch):
    monkeypatch.setenv("WINEPREFIX", tmpdir.join("wineprefix").strpath)
    for arch in ["i686", "x86_64"]:
        print("Testing", arch)
        archdir = tmpdir.join(arch)
        shutil.copytree(os.path.join(TEST_DIR, "sample-dll", arch),
                        archdir.strpath)

        # To start with, everything works
        run_exe(archdir.join("main.exe"))

        # Then we rename the .dll, and it stops working
        archdir.join("sample-dll.dll").rename(
            archdir.join("renamed-sample-dll.dll"))
        run_exe(archdir.join("main.exe"), expect_success=False)

        # Then we run redll, and it works again
        subprocess.check_call([sys.executable,
                               "-m", "machomachomangler.cmd.redll",
                               archdir.join("main.exe").strpath,
                               archdir.join("patched-main.exe").strpath,
                               "sample-dll.dll", "renamed-sample-dll.dll"])

        run_exe(archdir.join("patched-main.exe"))
