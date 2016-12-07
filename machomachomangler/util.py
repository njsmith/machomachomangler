def zero_bytearray_slice(buf, start, stop):
    buf[start:stop] = bytes(stop - start)

def round_to_next(size, alignment):
    "Return smallest n such that n % alignment == 0, n >= size"
    if size % alignment == 0:
        return size
    else:
        return alignment * (size // alignment + 1)

def pad_inplace(buf, *, size=None, align=None):
    if (size is None) == (align is None):
        raise TypeError("must specify exactly one of size or align")
    if size is None:
        size = round_to_next(len(buf), align)
    if size < len(buf):
        raise ValueError("new size ({}) is less than current size ({})"
                         .format(size, len(buf)))
    buf += bytes(size - len(buf))
    return buf

def _read_leb128(buf, offset, *, signed):
    value = 0
    shift = 0
    while True:
        byte = buf[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        shift += 7
        if not byte & 0x80:
            break
    if signed:
        if byte & 0x40:
            value = -((1 << shift) - value)
    return value, offset

def read_uleb128(buf, offset):
    return _read_leb128(buf, offset, signed=False)

def read_sleb128(buf, offset):
    return _read_leb128(buf, offset, signed=True)

def _write_leb128(value, *, include_zero_msb):
    assert value >= 0
    buf = bytearray()
    while True:
        buf.append(value & 0x7f)
        value >>= 7
        if not value:
            break
        else:
            buf[-1] |= 0x80
    if include_zero_msb and buf[-1] & 0x40:
        buf[-1] |= 0x80
        buf.append(0x00)
    return buf

def write_uleb128(value):
    return _write_leb128(value, include_zero_msb=False)

def write_sleb128(value):
    if value >= 0:
        return _write_leb128(value, include_zero_msb=True)
    else:
        n = (1 << 6)
        while True:
            if -n <= value < n:
                break
            n <<= 7
        return _write_leb128((n << 1) + value, include_zero_msb=False)

def read_asciiz(buf, offset):
    asciiz = b""
    # next line will break on py2:
    while buf[offset]:
        asciiz += buf[offset:offset+1]
        offset += 1
    return asciiz, offset + 1
