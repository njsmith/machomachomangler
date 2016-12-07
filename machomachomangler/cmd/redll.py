import sys

# XX FIXME: write a real command line interface

from ..pe import redll

args = sys.argv[1:]

if len(args) < 4 or len(args) % 2 != 0:
    sys.stderr.write(
        "Usage: python3 -m redll INPUT OUTPUT "
        "OLD-DLL-1 NEW-DLL-1 [OLD-DLL-2 NEW-DLL-2 [...]]\n"
    )
    sys.exit(2)

in_ = args.pop(0)
out = args.pop(0)

mapping = {}
while args:
    old = args.pop(0).encode("ascii")
    new = args.pop(0).encode("ascii")
    mapping[old] = new

with open(in_, "rb") as f:
    buf = f.read()

new_buf = redll(buf, mapping)

with open(out, "wb") as f:
    f.write(new_buf)
