import copy
import attr
from .util import (
    read_uleb128, write_uleb128, read_sleb128, write_sleb128, read_asciiz)
from .macho_info import *

# XX FIXME: need to handle fat binaries

################################################################
# Binding tables
################################################################

@attr.s
class Binding:
    segment_index = attr.ib()
    segment_offset = attr.ib()
    type_ = attr.ib()
    symbol_name = attr.ib()
    symbol_flags = attr.ib()
    addend = attr.ib()
    library_ordinal = attr.ib()

def _initial_bind():
    # These defaults have to match the initializations in
    # ImageLoaderMachOCompressed.cpp
    return Binding(
        segment_index=None,
        segment_offset=None,
        type_=0,
        symbol_name=None,
        symbol_flags=0,
        addend=0,
        library_ordinal=0)

def decode_bind_table(buf, start, size, *, sizeof_pointer, lazy):
    max_offset = (2 ** (sizeof_pointer * 8))

    b = _initial_bind()

    def bind():
        # Bizarrely, the opcode format encodes negative steps in
        # segment_offset as positive uleb128's that then intentionally trigger
        # wraparound. Which completely defeats the point of using uleb128. Why
        # not use sleb128? It is a mystery. Anyway, we have to fix the
        # wraparound ourselves.
        b.segment_offset %= max_offset
        return copy.copy(b)

    p = start
    end = start + size
    while p < end:
        opcode = buf[p] & BIND_OPCODE_MASK
        immediate = buf[p] & BIND_IMMEDIATE_MASK
        p += 1

        if opcode == BIND_OPCODE_DONE:
            # Lazy table has DONE opcodes which are no-ops
            # Regular bind table AFAICT doesn't have DONE opcodes in it, so it
            # shouldn't matter... but the code exits the loop when it sees
            # one, so let's be paranoid about being compatible.
            if not lazy:
                break
        elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            b.library_ordinal = immediate
        elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            b.library_ordinal, p = read_uleb128_uleb(buf, p)
        elif opcode == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            # immediate is 4-bit signed negative number (really 0, -1, or -2)
            # 0 = 0x0, -1 = 0xf, -2 = 0xe
            if immediate == 0:
                b.library_ordinal = 0
            else:
                b.library_ordinal = -(0x10 - immediate)
        elif opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            b.symbol_name, p = read_asciiz(buf, p)
            b.symbol_flags = immediate
        elif opcode == BIND_OPCODE_SET_TYPE_IMM:
            b.type_ = immediate
        elif opcode == BIND_OPCODE_SET_ADDEND_SLEB:
            b.addend, p = read_sleb128(buf, p)
        elif opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            b.segment_index = immediate
            b.segment_offset, p = read_uleb128(buf, p)
        elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
            incr, p = read_uleb128(buf, p)
            b.segment_offset += incr
        elif opcode == BIND_OPCODE_DO_BIND:
            yield bind()
            b.segment_offset += sizeof_pointer
        elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            yield bind()
            incr, p = read_uleb128(buf, p)
            b.segment_offset += incr + sizeof_pointer
        elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            yield bind()
            b.segment_offset += (1 + immediate) * sizeof_pointer
        elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            count, p = read_uleb128(buf, p)
            skip, p = read_uleb128(buf, p)
            for i in range(count):
                yield bind()
                b.segment_offset += skip + sizeof_pointer
        else:
            raise ValueError("unrecognized bind opcode {:#x}".format(opcode))

def encode_bind_table(binds, *, sizeof_pointer):
    max_offset = (2 ** (sizeof_pointer * 8))

    buf = bytearray()
    def emit(opcode, immediate):
        assert opcode & BIND_OPCODE_MASK == opcode
        assert immediate & BIND_IMMEDIATE_MASK == immediate
        buf.append(opcode | immediate)
    last = _initial_bind()
    binds_iter = iter(binds)
    for b in binds_iter:
        if b.segment_index != last.segment_index:
            emit(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB, b.segment_index)
            buf += write_uleb128(b.segment_offset)
            last.segment_index = b.segment_index
            last.segment_offset = b.segment_offset
        if b.segment_offset != last.segment_offset:
            delta = b.segment_offset - last.segment_offset
            # Use a very large value to trigger intentional wraparound
            if delta < 0:
                delta += max_offset
            emit(BIND_OPCODE_ADD_ADDR_ULEB, 0)
            buf += write_uleb128(delta)
            last.segment_offset = b.segment_offset
        if b.type_ != last.type_:
            emit(BIND_OPCODE_SET_TYPE_IMM, b.type_)
            last.type_ = b.type_
        if (b.symbol_name != last.symbol_name
              or b.symbol_flags != last.symbol_flags):
            emit(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM, last.symbol_flags)
            buf += b.symbol_name
            buf.append(0)
            last.symbol_name = b.symbol_name
            last.symbol_flags = b.symbol_flags
        if b.addend != last.addend:
            emit(BIND_OPCODE_SET_ADDEND_SLEB, 0)
            buf += write_sleb128(b.addend)
            last.addend = b.addend
        if b.library_ordinal != last.library_ordinal:
            if 0 <= b.library_ordinal <= 0xf:
                emit(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM, b.library_ordinal)
            elif 0xf < b.library_ordinal:
                emit(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB, 0)
                buf += write_uleb128(b.library_ordinal)
            else:
                assert -2 <= b.library_ordinal < 0
                emit(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM,
                     0x10 + b.library_ordinal)
            last.library_ordinal = b.library_ordinal
        assert last == b
        # XX could encode things more efficiently here, but for now I am lazy
        # (the trick would be to peek ahead, and if there are multiple binds
        # with everything except segment_offset the same then use
        # BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB, and if not then if the
        # next bind is at least in the same segment then we can encode the
        # segment_offset delta now)
        emit(BIND_OPCODE_DO_BIND, 0)
        last.segment_offset += sizeof_pointer

    return buf


################################################################
# Import symbol mangling
################################################################

def view_mach_header(buf):
    header = MACH_HEADER.view(buf, 0)
    if header["magic"] == MH_MAGIC:
        sizeof_pointer = 4
    elif header["magic"] == MH_MAGIC_64:
        header = MACH_HEADER_64.view(buf, 0)
        sizeof_pointer = 8
    elif header["magic"] in [MH_CIGAM, MH_CIGAM_64]:
        raise ValueError(
            "This file is big-endian, which I don't currently support --"
            " sorry! patches accepted")
    else:
        raise ValueError("This doesn't seem to be a MACH binary?")
    return header, sizeof_pointer

def view_load_commands(header):
    offset = header.end_offset
    for _ in range(header["ncmds"]):
        load_command = LOAD_COMMAND.view(header.buf, offset)
        yield load_command
        offset += load_command["cmdsize"]

# libraries_to_mangle is a mapping
#   {dylib name: symbol name mangler}
# TODO:
#   also need to rewrite the imports to be weak + use new name
#   the name part can be done with install_name_tool, so for now I just do the
#   weak import part
def rewrite_pynativelib_imports(buf, libraries_to_mangle):
    # Make a mutable copy to work on
    buf = bytearray(buf)
    header, sizeof_pointer = view_mach_header(buf)
    # maps library path -> ordinal
    libraries = {}
    __LINKEDIT = None
    dyld_info = None
    for load_command in view_load_commands(header):
        if load_command["cmd"] in LOAD_DYLIB_COMMANDS:
            load_command = load_command.cast(DYLIB_COMMAND)
            print(load_command)
            name, _ = read_asciiz(
                load_command.buf,
                load_command.offset + load_command["dylib_name"])
            print("name =", name)
            libraries[name] = len(libraries) + 1
            if name in libraries_to_mangle:
                print("Making {} into a weak dylib".format(name))
                load_command["cmd"] = LC_LOAD_WEAK_DYLIB
        elif load_command["cmd"] in {LC_SEGMENT, LC_SEGMENT_64}:
            if load_command["cmd"] == LC_SEGMENT:
                load_command = load_command.cast(SEGMENT_COMMAND)
            else:
                load_command = load_command.cast(SEGMENT_COMMAND_64)
            print(load_command)
            if load_command["segname"].strip(b"\x00") == b"__LINKEDIT":
                __LINKEDIT = load_command
        elif load_command["cmd"] in {LC_DYLD_INFO, LC_DYLD_INFO_ONLY}:
            dyld_info = load_command.cast(DYLD_INFO_COMMAND)
            print(load_command)

    if __LINKEDIT is None:
        raise ValueError("can't find __LINKEDIT segment")
    if __LINKEDIT["fileoff"] + __LINKEDIT["filesize"] != len(buf):
        raise ValueError("__LINKEDIT is not at end of file")

    bind = list(decode_bind_table(buf,
                                  dyld_info["bind_off"],
                                  dyld_info["bind_size"],
                                  sizeof_pointer=sizeof_pointer,
                                  lazy=False))

    # quick smoke test
    reencoded = encode_bind_table(bind, sizeof_pointer=sizeof_pointer)
    bind2 = list(decode_bind_table(reencoded, 0, len(reencoded),
                                       sizeof_pointer=sizeof_pointer,
                                       lazy=False))
    assert bind == bind2
    del bind2

    mangle_table = {}  # {ordinal: mangle function}
    for name, mangler in libraries_to_mangle.items():
        if name not in libraries:
            print("This object file does not import {}; skipping"
                  .format(name))
        else:
            mangle_table[libraries[name]] = mangler

    def mangle_bindings(bindings):
        for binding in bindings:
            o = binding.library_ordinal
            if o in mangle_table:
                binding.symbol_name = mangle_table[o](binding.symbol_name)
                binding.library_ordinal = -2

    # Mangle the eager bindings
    mangle_bindings(bind)

    # Pull out the lazy bindings that need to be mangled, mangle them, and
    # move them into the eager bindings table
    eagerified = []
    lazy = list(decode_bind_table(buf,
                                  dyld_info["lazy_off"],
                                  dyld_info["lazy_size"],
                                  sizeof_pointer=sizeof_pointer,
                                  lazy=True))
    for binding in lazy:
        if binding.library_ordinal in mangle_table:
            eagerified.append(binding)
    mangle_bindings(eagerified)
    bind += eagerified

    # Wipe out the old bind table, to make sure we aren't using it
    # accidentally
    bind_off = dyld_info["bind_off"]
    bind_off_end = dyld_info["bind_off"] + dyld_info["bind_size"]
    buf[bind_off:bind_off_end] = b"\x00"

    # Make the new bind table
    new_bind_buf = encode_bind_table(bind, sizeof_pointer=sizeof_pointer)

    # Update DYLD_INFO to point to where it will be
    dyld_info["bind_off"] = len(buf)
    dyld_info["bind_size"] = len(new_bind_buf)

    # Add it to __LINKEDIT
    buf += new_bind_buf
    __LINKEDIT["filesize"] += len(new_bind_buf)
    __LINKEDIT["vmsize"] += len(new_bind_buf)

    return buf

    # XX do something with weak binds I guess?
    # it looks like maybe how weak binds work is that first you bind them
    #   regularly, to a particular library
    # and then they show up again in the weak binding section without a
    #   library associated with them
    #   and if a new library comes along that also exports that name, then
    #   dyld goes through and finds *all* the places that import that name (no
    #   matter where they imported it from) and binds them to the new place?
    #   (making some guesses based on the comments in mach-o/archive.h)
    # so possibly what we should be doing is that if a symbol is in the weak
    #   imports table, we shouldn't mangle it
    # and similarly on exports, if it's flagged as weak (0x04 maybe? I used
    #   dyldinfo to look at the export trie for libc++ at some symbols that I
    #   know show up in the weak import table for other libraries, imported
    #   from libc++, and in libc++'s export trie they have some sort of "weak"
    #   flag that dyldinfo can see)

    # but if you do want to override one of these then maybe you export it as
    # a *non* weak symbol? so can we even tell that that's the goal if just
    # looking at the exporting dylib?

    # https://en.wikipedia.org/wiki/Weak_symbol

    # also need to think about classic symbol tables
    # should check dyld to see if it even looks at them
    #
    # it looks like dladdr uses the classic symbol table... so, uh... there's
    # that. I guess I don't care very much if dladdr gives somewhat wrong
    # results.
    #
    # there's also something involving "doBindLazySymbol":
    # // A program built targeting 10.5 will have hybrid stubs.  When used with weak symbols
    # // the classic lazy loader is used even when running on 10.6
    # this appears to be called from stub_binding_helper.s
    # I don't know if this is still a thing, though -- new binaries seem to
    # use dyld_stub_binder (which definitely uses the new tables), not
    # stub_binding_helper
    # and it shouldn't come up anyway if we're doing all our loading eagerly
    #
    # so tentatively I'm guessing we can get away without this
    #
    # ImageLoaderMachOCompressed implements setSymbolTableInfo as... throwing
    # it away. and ...Compressed is used for all files that have DYLD_INFO. so
    # it's really only those two functions that use it.
    #
    # I still don't know why strip refused to remove it though... that
    # indirect symbols thing? what's that about?
