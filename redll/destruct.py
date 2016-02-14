import struct
from collections.abc import MutableMapping

# Usage:
#   COFF_HEADER = StructType("COFF_HEADER", [
#     ("<i4", "magic"),
#     ...
#   ])
#
# Now you can do:
#
#   h = COFF_HEADER.read_from(file_handle)
#   h["magic"]
#   h["magic"] = whatever
#   h.write_to(file_handle)
#
# or if you have a mutable buffer (bytesarray, memoryview, ...):
#
#   h = COFF_HEADER.unpack_from(buf, offset)
#   h["magic"]
#   h["magic"] = whatever
#   h.write_back()  # modifies original buffer
class StructType(object):
    def __init__(self, name, fields, endian="<"):
        self._name = name
        self._fields = fields
        self._types = [f[0] for f in self._fields]
        self._names = [f[1] for f in self._fields]

        self._struct_string = endian + "".join(self._types)
        self.size = struct.calcsize(self._struct_string)

    def _values_to_struct(self, values):
        return Struct(self, dict(zip(self._names, values)))

    def unpack(self, data):
        values = struct.unpack(self._struct_string, data)
        return self._values_to_struct(values)

    def _unpack_from(self, buf, offset):
        values = struct.unpack_from(self._struct_string, buf, offset)
        return self._values_to_struct(values)

    def view(self, buf, offset):
        return StructView(self, buf, offset)

    def _values_from_dict(self, value_dict):
        values = [value_dict[n] for n in self._names]
        assert len(values) == len(value_dict)
        return values

    def pack(self, value_dict):
        return struct.pack(self._struct_string,
                           *self._values_from_dict(value_dict))

    def pack_into(self, buf, offset, value_dict):
        return struct.pack_into(self._struct_string,
                                buf, offset,
                                *self._values_from_dict(value_dict))

    def read_from(self, f):
        data = f.read(self.size)
        return self.unpack(data)

class Struct(dict):
    def __init__(self, struct_type, values):
        self._struct_type = struct_type
        self.update(values)
        assert set(self) == set(self._struct_type._names)

    def __repr__(self):
        return "Struct({}, {})".format(
            self._struct_type._name,
            ", ".join("{}={}".format(n, repr(self._values[n]))
                      for n in self._struct_type._names))

    def pack(self):
        return self._struct_type.pack(self)

    def write_to(self, f):
        return f.write(self.pack())

    @property
    def size(self):
        return self._struct_type.size

def _repr_field(struct_code, value):
    if struct_code in "bBhHiIlLqQnN":
        l = struct.calcsize("<" + struct_code)
        # l bytes -> 2*l nibbles, plus 2 for the "0x"
        f = "{:#0" + str(2 + 2 * l) + "x}"
        return f.format(value)
    else:
        return repr(value)

class StructView(MutableMapping):
    def __init__(self, struct_type, buf, offset):
        self._struct_type = struct_type
        self.buf = buf
        self.offset = offset

    def __repr__(self):
        s = "<{} of <{}>[{:#x}:]\n".format(
            self._struct_type._name, self.buf.__class__.__name__, self.offset)
        d = dict(self)
        for type_, name in self._struct_type._fields:
            s += "  {:>30}: {}\n".format(name, _repr_field(type_, d[name]))
        s += ">"
        return s

    def _value_dict(self):
        return self._struct_type._unpack_from(self.buf, self.offset)

    def __getitem__(self, k):
        return self._value_dict()[k]

    def __setitem__(self, k, v):
        value_dict = self._value_dict()
        value_dict[k] = v
        self._struct_type.pack_into(self.buf, self.offset, value_dict)

    def __delitem__(self, k):
        assert False

    def __len__(self):
        return len(self._struct_type._names)

    def __iter__(self):
        return iter(self._struct_type._names)

    @property
    def size(self):
        return self._struct_type.size

    @property
    def next_offset(self):
        return self.offset + self.size
