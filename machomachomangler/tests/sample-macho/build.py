import os
import os.path
import subprocess

os.chdir(os.path.dirname(os.path.abspath(__file__)))

def run(cmd):
    print(cmd)
    subprocess.check_call(cmd)

for arch_name, arches in [
        ("i386", ["-arch", "i386"]),
        ("x86_64", ["-arch", "x86_64"]),
        ("fat", ["-arch", "i386", "-arch", "x86_64"]),
        ]:
    CC = ["clang"] + arches

    if not os.path.exists(arch_name):
        os.mkdir(arch_name)

    def outpath(name):
        return os.path.join(arch_name, name)

    def cc(args, out):
        run(CC + args + ["-o", outpath(out)])

    cc(["-shared", "native-lib.c"], "native-lib.dylib")
    cc(["-bundle", "fake-pymodule.c", outpath("native-lib.dylib")],
       "fake-pymodule.bundle")
    cc(["main-dlopen.c"], "main-dlopen")
    cc(["main-envvar.c", outpath("native-lib.dylib")], "main-envvar")
