import pytest

from ..destruct import StructType

_fields = [
    ("I", "magic"),
    ("c", "byte"),
]

TEST = StructType("TEST", _fields)
TEST_BE = StructType("TEST_BE", _fields, endian=">")

def test_destruct():
    assert TEST.size == 5
    assert TEST_BE.size == 5

    raw = bytearray(b"\x00\x00\x01\x02\x03\x04")
    view_0_le = TEST.view(raw, 0)
    view_1_be = TEST_BE.view(raw, 1)
    for view in [view_0_le, view_1_be]:
        assert len(view_0_le) == 2
        assert view_0_le.size == 5
        # smoke test
        repr(view)
    assert view_0_le.end_offset == 5
    assert view_1_be.end_offset == 6

    assert dict(view_0_le) == {"magic": 0x02010000, "byte": b"\x03"}
    assert dict(view_1_be) == {"magic": 0x00010203, "byte": b"\x04"}

    view_0_le["magic"] = 0x12345678
    assert raw == bytearray(b"\x78\x56\x34\x12\x03\x04")
    assert view_1_be["magic"] == 0x56341203

    with pytest.raises(NotImplementedError):
        del view_0_le["magic"]
