import pytest
from binascii import unhexlify

from ..util import *

def test_zero_bytearray_slice():
    buf = bytearray(b"-" * 10)
    zero_bytearray_slice(buf, 2, 5)
    assert buf == b"--\x00\x00\x00-----"

def test_round_to_next():
    assert round_to_next(10, 12) == 12
    assert round_to_next(20, 12) == 24
    assert round_to_next(24, 12) == 24

def test_pad_inplace():
    buf = bytearray.fromhex("112233")
    assert pad_inplace(buf, size=5) == bytearray.fromhex("1122330000")
    assert buf == bytearray.fromhex("1122330000")
    pad_inplace(buf, align=4)
    assert buf == bytearray.fromhex("1122330000000000")
    with pytest.raises(TypeError):
        pad_inplace(buf)
    with pytest.raises(TypeError):
        pad_inplace(buf, size=10, align=1)
    with pytest.raises(ValueError):
        pad_inplace(buf, size=4)

def test_read_asciiz():
    assert read_asciiz(b"abc\x00def", 0) == (b"abc", 4)
    assert read_asciiz(b"abc\x00def", 1) == (b"bc", 4)
    assert read_asciiz(b"abc\x00def", 3) == (b"", 4)
    assert read_asciiz(b"abc\x00def\x00", 4) == (b"def", 8)

def test_read_uleb128():
    assert read_uleb128(unhexlify("0a0b"), 0) == (10, 1)
    assert read_uleb128(unhexlify("0a0b"), 1) == (11, 2)
    assert read_uleb128(unhexlify("00" "e58e26" "00"), 1) == (624485, 4)

def test_write_uleb128():
    for value in range(2 ** 15):
        encoded = write_uleb128(value)
        decoded, _ = read_uleb128(encoded, 0)
        assert decoded == value

# Examples from the Dwarf 4 standard, Figure 23
_sleb128_gold_values = [
    (2, [2]),
    (-2, [0x7e]),
    (127, [127 + 0x80, 0]),
    (-127, [1 + 0x80, 0x7f]),
    (128, [0 + 0x80, 1]),
    (-128, [0 + 0x80, 0x7f]),
    (129, [1 + 0x80, 1]),
    (-129, [0x7f + 0x80, 0x7e]),
]

def test_read_sleb128():
    for expected, bytelist in _sleb128_gold_values:
        buf = b"\x00" + bytes(bytelist) + b"\x00"
        value, offset = read_sleb128(buf, 1)
        assert value == expected
        assert offset == 1 + len(bytelist)

def test_write_sleb128():
    for i in range(2 ** 15):
        for value in [i, -i]:
            encoded = write_sleb128(value)
            decoded, _ = read_sleb128(encoded, 0)
            assert decoded == value
