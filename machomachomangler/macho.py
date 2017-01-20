import copy
import uuid
import itertools
import attr
from .util import (
    round_to_next, pad_inplace, zero_bytearray_slice,
    read_uleb128, write_uleb128, read_sleb128, write_sleb128,
    read_asciiz,
)
from .macho_info import *

def _sizeslice(start, size):
    return slice(start, start + size)

################################################################
# Fat binaries
################################################################

def macho_macho_mapper(fn, buf):
    # If buf is a fat binary, split it into its constituent objects, call fn
    # on each, and then reconstruct a fat binary from the return values.
    # If buf is a mach-o binary, then just call fn on it and return the
    # result.
    if buf[:4] == FAT_MAGIC_BYTES:
        header = FAT_HEADER.view(buf, 0)
        assert header["magic"] == FAT_MAGIC

        # Read out the per-arch headers:
        arch_offset = header.end_offset
        archs = []
        for _ in range(header["nfat_arch"]):
            archs.append(FAT_ARCH.view(buf, arch_offset))
            arch_offset = archs[-1].end_offset
        # Make a note of where the arch headers end and the data starts --
        # we'll want this later.
        data_start_offset = arch_offset

        # Pull out each contained object and process it
        new_subbufs = []
        for arch in archs:
            start = arch["offset"]
            end = arch["offset"] + arch["size"]
            new_subbufs.append(fn(buf[start:end]))

        # Now we'll make a new fat object. The initial headers will have
        # identical layout to the original (though some of the values inside
        # will be different), so we start with an empty file of that
        # size, which we'll fill in incrementally. (This pre-padding makes it
        # easy to alternate between filling in headers and filling in the
        # actual contained objects.)
        new_buf = bytearray(data_start_offset)
        new_header = FAT_HEADER.view(new_buf, 0)
        new_header.update(header)
        for arch, new_subbuf in zip(archs, new_subbufs):
            # Append the contained object to the new file (respecting
            # alignment)
            pad_inplace(new_buf, align=2**arch["align"])
            new_subbuf_offset = len(new_buf)
            new_buf += new_subbuf
            # Now that we know where it ended up, fill in the corresponding
            # header.
            new_arch = FAT_ARCH.view(new_buf, arch.offset)
            new_arch.update(arch)
            new_arch["offset"] = new_subbuf_offset
            new_arch["size"] = len(new_subbuf)
        return new_buf
    else:
        # Probably this is a plain Mach-O object? To check we call
        # view_mach_header for its validity-checking side-effects; it'll raise
        # an exception if not.
        view_mach_header(buf)
        return fn(buf)


################################################################
# Mach-O basics
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
    # Probably most of the other Mach-O subtypes are similar enough that most
    # things this code does would work, but since they're so exotic let's play
    # it safe for now...
    if header["filetype"] not in {MH_EXECUTE, MH_DYLIB, MH_BUNDLE}:
        raise ValueError("Unrecognized Mach-O file type {:#x}"
                         .format(header["filetype"]))
    return header, sizeof_pointer


def view_load_command(buf, offset):
    load_command = LOAD_COMMAND.view(buf, offset)
    if load_command["cmd"] in LC_ID_TO_STRUCT:
        load_command = load_command.cast(LC_ID_TO_STRUCT[load_command["cmd"]])
    return load_command

def view_load_commands(header, cmds=None):
    offset = header.end_offset
    for _ in range(header["ncmds"]):
        load_command = view_load_command(header.buf, offset)
        if cmds is None or load_command["cmd"] in cmds:
            yield load_command
        offset += load_command["cmdsize"]


def view_sections(segment_command):
    if segment_command["cmd"] == LC_SEGMENT:
        secttype = SECTION
    else:
        assert segment_command["cmd"] == LC_SEGMENT_64
        secttype = SECTION_64
    return secttype.view_array(
        segment_command.buf, segment_command.end_offset,
        segment_command["nsects"])


def view_dyld_info(header):
    for lc in view_load_commands(header, {LC_DYLD_INFO, LC_DYLD_INFO_ONLY}):
        return lc

# Head + load commands are allowed to use the space up until the first byte
# that's part of a non-empty non-zerofill section, or part of a non-empty
# segment with no sections that does not start at the beginning of the
# file. (This is somewhat messy logic is copied from install_name_tool -- see
# update_load_commands in install_name_tool.c).
def available_header_size(header):
    smallest = 1e100
    for load_command in view_load_commands(header, LC_SEGMENT_ANY):
        if load_command["nsects"] == 0:
            if load_command["filesize"] > 0:
                smallest = min(smallest, load_command["fileoff"])
        else:
            for section in view_sections(load_command):
                if (section["size"] != 0
                      and section["flags"] & SECTION_TYPE != S_ZEROFILL):
                    smallest = min(smallest, section["offset"])
    return smallest


# fn receives old load command, and returns the new load command. The new
# command should have an accurate cmdsize (so we can figure out where it
# begins and ends!), but this function will worry about adding any necessary
# padding.
def map_load_commands_inplace(header, pointer_size, fn):
    buf = header.buf
    new_lc_bufs = []
    for lc in view_load_commands(header):
        new_lc = fn(lc)
        new_lc_buf = new_lc.buf[_sizeslice(new_lc.offset, new_lc["cmdsize"])]
        if not isinstance(new_lc_buf, bytearray):
            new_lc_buf = bytearray(new_lc_buf)
        pad_inplace(new_lc_buf, align=pointer_size)
        new_lc = LOAD_COMMAND.view(new_lc_buf, 0)
        new_lc["cmdsize"] = len(new_lc_buf)
        new_lc_bufs.append(new_lc_buf)
    new_lc_buf_joined = b"".join(new_lc_bufs)
    header_space = available_header_size(header)
    lc_space = header_space - header.end_offset
    if len(new_lc_buf_joined) > lc_space:
        raise ValueError(
            "Not enough space to rewrite Mach-O header: "
            "need {}, but only {} available. Relink using -headerpad"
            .format(len(new_header_buf), space_avail))
    pad_inplace(new_lc_buf_joined, size=lc_space)
    new_lc_slice = _sizeslice(header.end_offset, len(new_lc_buf_joined))
    buf[new_lc_slice] = new_lc_buf_joined
    header["sizeofcmds"] = len(new_lc_buf_joined)


# Returns a new dylib_command object that is a view onto a new buffer
# containing just that command object, i.e., the returned object always has
#   lc.offset == 0
#   lc.end_offset == len(lc.buf)
# And the new lc is identical to the input one, except that the dylib_name has
# been changed.
def dylib_command_with_new_name(old_command, new_name):
    assert old_command.struct_type is DYLIB_COMMAND
    new_buf = old_command.buf[old_command.offset:old_command.end_offset]
    new_buf = bytearray(new_buf)
    new_dc = DYLIB_COMMAND.view(new_buf, 0)
    # Almost certainly redundant, but just in case
    new_dc["dylib_name"] = len(new_buf)
    new_buf += new_name
    new_buf += b"\x00"
    new_dc["cmdsize"] = len(new_buf)
    return new_dc


def replace_linkedit_chunk(buf, old_offset, old_size, new_chunk):
    # buf must be writeable; it's modified in place
    # returns: new_offset
    header, _ = view_mach_header(buf)
    for load_command in view_load_commands(header, LC_SEGMENT_ANY):
        if load_command["segname"].strip(b"\x00") == b"__LINKEDIT":
            __LINKEDIT = load_command
            break
    else:
        raise ValueError("can't find __LINKEDIT segment")

    # Get rid of the old chunk, to avoid any confusion
    if old_offset + old_size == len(buf):
        # If it's at the end, we can truncate.
        del buf[old_offset:]
        __LINKEDIT["filesize"] -= old_size
        __LINKEDIT["vmsize"] -= old_size
        old_size = 0
    else:
        # Otherwise, set it to all-zero.
        zero_bytearray_slice(buf, old_offset, old_offset + old_size)

    # Now we want to put the new chunk in.
    if len(new_chunk) < old_size:
        # We can replace it in-place
        buf[_sizeslice(old_offset, len(new_chunk))] = new_chunk
        return old_offset
    else:
        # We have to append to the end of the file
        if __LINKEDIT["fileoff"] + __LINKEDIT["filesize"] != len(buf):
            raise ValueError("__LINKEDIT is not at end of file")
        new_offset = len(buf)
        buf += new_chunk
        __LINKEDIT["filesize"] += len(new_chunk)
        __LINKEDIT["vmsize"] += len(new_chunk)
        return new_offset

################################################################
# Binding tables
################################################################


# If we do:
#   xcrun dyldinfo -lazy_info user-dylib.dylib
# we can see that user-dylib.dylib indeed has a lazy binding to the
# _mangled_dylib_public_function in mangled-dylib.dylib :-(
#
# (Note the need to use "xcrun" to run the super-useful "dyldinfo"
# utility. Why? beats me.)
#
# Empirically it looks like this can be prevented by passing -bind_at_load
# when linking user-dylib.dylib (i.e. the library whose import symbols need to
# be mangled). (ld(1) seems to suggest that this just sets a flag, but in fact
# when I pass this to ld the resulting binary has lazy_bind_size == 0.)
#
# Maybe adding these into the regular binding table is enough though?

# zibi:mangle-test njs$ xcrun dyldinfo -lazy_bind user-dylib.dylib.with-lazy
# lazy binding information (from lazy_bind part of dyld info):
# segment section          address    index  dylib            symbol
# __DATA  __la_symbol_ptr  0x00001020 0x0000 flat-namespace   _mangled_dylib_public_function
# __DATA  __la_symbol_ptr  0x00001028 0x0025 libSystem        _fprintf

# vm address 0x1020 is in __DATA, which starts at 0x1000
# file offset 4096
# and has segment __la_symbol_ptr, starting at address 0x1020
#  = offset 4128 = 0x1020
#
# 0x1020 has bytes
#    08 0f 00 00 00 00 00 00
# 0x1028 has bytes
#    24 0f 00 00 00 00 00 00
#
# 0x0f08 is in __TEXT, section __stub_helper which starts at 0x0f08
# 0x0f08 has bytes
#    68 00 00 00 00 e9 02 00
#
# Some info on how this works -- it looks like __stub_helper has a call to
# dyld_stub_binder
# https://reverseengineering.stackexchange.com/questions/8163/in-a-mach-o-executable-how-can-i-find-which-function-a-stub-targets
# which when run will rewrite the data in __la_symbol_ptr
# so the bind opcode actually says where to put the function pointer once we
# get it

# and in fact, it looks like -bind_at_load even leaves the __nl_symbol_ptr /
# __la_symbol_ptr distinction in place, and just puts the lazy symbol binding
# opcodes in with the regular binding opcodes. So that's OK, we can kill the
# laziness ourselves. Phew.

# otool -s __TEXT __stub_helper -V says:

# Contents of (__TEXT,__stub_helper) section
# 0000000000000f08      pushq   $0x0
# 0000000000000f0d      jmp     0xf14
# 0000000000000f12      addb    %al, (%rax)
# 0000000000000f14      leaq    0xed(%rip), %r11
# 0000000000000f1b      pushq   %r11
# 0000000000000f1d      jmpq    *0xdd(%rip)
# 0000000000000f23      nop
# 0000000000000f24      pushq   $0x25
# 0000000000000f29      jmp     0xf14

# so it looks like _mangled_dylib_public_function does
#
#   pushq $0x0
#   jmp 0xf14
#
# (which pushes 0x0 to the stack
#
# and _fprintf does
#
#   pushq $0x25
#   jmp 0xf14
#
# and then at 0xf14 we have:
# 0000000000000f14      leaq    0xed(%rip), %r11
# 0000000000000f1b      pushq   %r11
# 0000000000000f1d      jmpq    *0xdd(%rip)

# And those 0x0, 0x25 numbers appear to be the offset into the lazy bind
# opcode stream where you have to go to get the binding for each item.
# (this person agrees: https://stackoverflow.com/questions/8825537/mach-o-symbol-stubs-ios/8836580#comment11133246_8836580)

# And they're encoded directly into the assembly instructions:
# 0000000000000f08      6800000000              pushq   $0x0
# 0000000000000f24      6825000000              pushq   $0x25
#
# (first number is offset, second number is x86-64 binary, notice the
# immediate inside the bytes.) So in theory I guess we could fix these up by
# going in and finding the address + 1 of the entry in the __stub_helper
# section, in practice this seems a litttttttle too fragile.

# we can (and probably should!) leave the lazy stream intact, while copying
# out the parts we want to mangle.

# Python script to decode bind opcode stream:
# https://github.com/zneak/fcd/blob/b29b4ac/scripts/macho.py#L307
# (GPLv3)

@attr.s(slots=True)
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
            b.library_ordinal, p = read_uleb128(buf, p)
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
# Exports
################################################################

# References:
#
# 1) http://www.m4b.io/reverse/engineering/mach/binaries/2015/03/29/mach-binaries.html
# 2) The dyld source code. Specifically:
#    trieWalk: skips over terminal information while searching the trie for
#      a specific symbol
#    findShallowExportedSymbol: decodes the terminal information

@attr.s(slots=True)
class Export:
    symbol_name = attr.ib()
    flags = attr.ib()
    # for re-exports
    library_ordinal = attr.ib(default=None)
    imported_name = attr.ib(default=None)
    # for stub-and-resolver
    stub = attr.ib(default=None)
    resolver = attr.ib(default=None)
    # for everything else
    address = attr.ib(default=None)

def print_exports(buf):
    header, pointer_size = view_mach_header(buf)
    dyld_info = view_dyld_info(header)
    exports = decode_export_trie(buf, dyld_info["export_off"])
    for export in exports:
        print(export)

def decode_export_trie(buf, start):
    def decode_node(prefix, p):
        terminal_size, p = read_uleb128(buf, p)
        expected_p = p + terminal_size
        if terminal_size:
            flags, p = read_uleb128(buf, p)
            # AFAICT having both of these flags set is not entirely ruled out,
            # but I'm not sure about what it would mean. (I am pretty sure we
            # handle it correctly if it happens -- the code in dyld all seems
            # to do if REEXPORT: ... else if STUB_AND_RESOLVER: ...)
            assert not (flags & EXPORT_SYMBOL_FLAGS_REEXPORT
                        and flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER)
            if flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
                library_ordinal, p = read_uleb128(buf, p)
                imported_name, p = read_asciiz(buf, p)
                if imported_name == b"":
                    imported_name = prefix
                yield Export(symbol_name=prefix, flags=flags,
                             library_ordinal=library_ordinal,
                             imported_name=imported_name)
            elif flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
                stub, p = read_uleb128(buf, p)
                resolver, p = read_uleb128(buf, p)
                yield Export(symbol_name=prefix, flags=flags,
                             stub=stub, resolver=resolver)
            else:
                address, p = read_uleb128(buf, p)
                yield Export(symbol_name=prefix, flags=flags, address=address)
        assert expected_p == p
        branches = buf[p]
        p += 1
        for _ in range(branches):
            child_prefix, p = read_asciiz(buf, p)
            child_offset, p = read_uleb128(buf, p)
            yield from decode_node(prefix + child_prefix, start + child_offset)

    return list(decode_node(b"", start))

# The export trie format has a very odd design choice, which is that it
# combines the following features:
#
# - you have to start with the root at offset 0
# - each node contains the offsets of the children
# - the offsets are variable-length encoded
#
# This creates a nice circularity, where the offset of the children is
# determined by the encoded length of the parent (or at least the root), and
# the encoded length of the parent (or root) is determined by the offset of
# the children. Basically we have to solve a little constraint system just to
# write out the export trie.
#
# Our strategy:
# - first, insert all export items into the "deep trie", which is like a trie
#   except each node consumes exactly 1 byte. So you get deep, inefficient
#   chains of nodes with exactly 1 child. (This is just because I'm too lazy
#   to write proper trie insert code.)
# - then, roll this up into a proper trie by collapsing unary chains. While
#   doing this:
#   - compute the fixed part of each node (the "payload")
#   - make an initial speculative guess as to the final offset of the
#     node. By "speculative" I mean "wrong", and by "wrong" I mean we always
#     guess 0. But it's a start!
# - Linearize the trie order (parents before children)
# - Make a first attempt at encoding the trie. When serializing a parent, use
#   our current guess as to the offsets of its children. As we process each
#   node, update our guess about its offset based on where it ended up on this
#   pass, to use on the next pass.
# - Repeat until we manage a complete pass without any offsets changing.

# Fake trie where each step consumes exactly 1 byte
@attr.s(slots=True)
class _DeepNode:
    # maps bytestrings to _DeepNode objects
    children = attr.ib(default=attr.Factory(dict))
    export = attr.ib(default=None)

def _deep_tree(exports):
    deep_root = _DeepNode()
    for export in exports:
        suffix = export.symbol_name
        node = deep_root
        while suffix:
            byte = suffix[0:1]
            suffix = suffix[1:]
            if byte not in node.children:
                node.children[byte] = _DeepNode()
            node = node.children[byte]
        node.export = export
    return deep_root

# Real trie
@attr.s(slots=True)
class _TrieNode:
    payload = attr.ib()
    # [(prefix, child), (prefix, child), ...]
    children = attr.ib(default=attr.Factory(list))
    offset_guess = attr.ib(default=0)

def _trieify(deep_node):
    if deep_node.export is not None:
        e = deep_node.export
        terminal_buf = bytearray()
        terminal_buf += write_uleb128(e.flags)
        # AFAICT having both of these flags set is not entirely ruled out, but
        # I'm not sure about what it would mean. (I am pretty sure we handle
        # it correctly if it happens -- the code in dyld all seems to do if
        # REEXPORT: ... else if STUB_AND_RESOLVER: ...)
        assert not (e.flags & EXPORT_SYMBOL_FLAGS_REEXPORT
                    and e.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER)
        if e.flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
            terminal_buf += write_uleb128(e.library_ordinal)
            if e.imported_name != e.symbol_name:
                terminal_buf += e.imported_name
            terminal_buf.append(0)
        elif e.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
            terminal_buf += write_uleb128(e.stub)
            terminal_buf += write_uleb128(e.resolver)
        else:
            terminal_buf += write_uleb128(e.address)
        payload = write_uleb128(len(terminal_buf)) + terminal_buf
    else:
        # non-terminal marker
        payload = bytes([0])
    trie_node = _TrieNode(payload=payload)
    for prefix, deep_child in sorted(deep_node.children.items()):
        # Collapse chains of single-child nodes:
        while deep_child.export is None and len(deep_child.children) == 1:
            next_byte, deep_child = next(iter(deep_child.children.items()))
            prefix += next_byte
        child_trie_node = _trieify(deep_child)
        trie_node.children.append((prefix, child_trie_node))
    return trie_node

def encode_export_trie(exports):
    if not exports:
        return bytearray()

    deep_root = _deep_tree(exports)
    trie_root = _trieify(deep_root)

    trie_nodes = []
    def _linearize_trie(node):
        trie_nodes.append(node)
        for _, child in node.children:
            _linearize_trie(child)
    _linearize_trie(trie_root)
    assert trie_nodes[0] is trie_root

    while True:
        buf = bytearray()
        any_offset_changed = False
        for node in trie_nodes:
            new_offset = len(buf)
            if new_offset != node.offset_guess:
                node.offset_guess = new_offset
                any_offset_changed = True
            buf += node.payload
            buf.append(len(node.children))
            for prefix, child in node.children:
                buf += prefix
                buf.append(0)
                buf += write_uleb128(child.offset_guess)
        if not any_offset_changed:
            break
    return buf


################################################################
# Smoke test
################################################################

def _roundtrip_smoketest(buf):
    header, sizeof_pointer = view_mach_header(buf)
    dyld_info = view_dyld_info(header)

    exports = decode_export_trie(buf, dyld_info["export_off"])
    reencoded = encode_export_trie(exports)
    exports2 = decode_export_trie(reencoded, 0)
    assert sorted(exports) == sorted(exports2)

    bind = list(decode_bind_table(
        buf, dyld_info["bind_off"], dyld_info["bind_size"],
        sizeof_pointer=sizeof_pointer, lazy=False))
    reencoded = encode_bind_table(bind, sizeof_pointer=sizeof_pointer)
    bind2 = list(decode_bind_table(
        reencoded, 0, len(reencoded),
        sizeof_pointer=sizeof_pointer, lazy=False))
    assert bind == bind2


################################################################
# Pynativelib imports rewriter
################################################################

def _pynativelib_mangle_import_libs(header, sizeof_pointer, libraries_to_mangle):
    # buf must be a bytearray, which we modify in place
    # this rewrites the load command table, so if you have a load command view
    # then calling this function will invalidate it.
    # Returns a mapping {ordinal: symbol mangler}

    # Libraries are assigned ordinal values in the order they appear in the
    # load commands, starting with 1. (This is how they're referred to later
    # in the import bindings table.)
    library_ordinal_count = itertools.count(1)
    ordinal_to_mangler = {}

    def mapper(old_lc):
        if old_lc["cmd"] not in LOAD_DYLIB_COMMANDS:
            return old_lc
        library_ordinal = next(library_ordinal_count)
        name, _ = read_asciiz(old_lc.buf, old_lc.offset + old_lc["dylib_name"])
        basename = name.rsplit(b"/", 1)[-1]
        if basename not in libraries_to_mangle:
            return old_lc
        # Okay, we've found a target library, let's do this.
        new_name, symbol_mangler = libraries_to_mangle[basename]
        # Remember the ordinal and symbol mangler for later.
        ordinal_to_mangler[library_ordinal] = symbol_mangler
        # Make the new load command
        new_lc = dylib_command_with_new_name(old_lc, new_name)
        # Make the import weak
        new_lc["cmd"] = LC_LOAD_WEAK_DYLIB
        return new_lc

    map_load_commands_inplace(header, sizeof_pointer, mapper)

    return ordinal_to_mangler

# libraries_to_mangle is a mapping
#   {dylib name: (new name, symbol name mangler)}
def rewrite_pynativelib_imports(buf, libraries_to_mangle):
    _roundtrip_smoketest(buf)

    # Make a mutable copy to work on
    buf = bytearray(buf)
    header, sizeof_pointer = view_mach_header(buf)

    # Read and mangle the file headers
    ordinal_to_symbol_mangler = (
        _pynativelib_mangle_import_libs(header, sizeof_pointer,
                                        libraries_to_mangle))

    # Pull out the symbol information
    dyld_info = view_dyld_info(header)

    bind = list(decode_bind_table(
        buf, dyld_info["bind_off"], dyld_info["bind_size"],
        sizeof_pointer=sizeof_pointer, lazy=False))

    mangled_count = 0
    def mangle_bindings(bindings):
        nonlocal mangled_count
        for binding in bindings:
            mangler = ordinal_to_symbol_mangler.get(binding.library_ordinal)
            if mangler is not None:
                binding.symbol_name = mangler(binding.symbol_name)
                binding.library_ordinal = BIND_SPECIAL_DYLIB_FLAT_LOOKUP
                mangled_count += 1

    # Mangle the eager bindings
    mangle_bindings(bind)

    # Pull out the lazy bindings that need to be mangled, mangle them, and
    # move them into the eager bindings table
    eagerified = []
    lazy = list(decode_bind_table(
        buf, dyld_info["lazy_bind_off"], dyld_info["lazy_bind_size"],
        sizeof_pointer=sizeof_pointer, lazy=True))
    for binding in lazy:
        if binding.library_ordinal in ordinal_to_symbol_mangler:
            # For some reason, lazy bindings don't have this set, but eager
            # bindings do. If you ask ld to eagerify the bindings by using
            # -bind_at_load, then this is the value it fills in:
            binding.type_ = BIND_TYPE_POINTER
            eagerified.append(binding)
    mangle_bindings(eagerified)
    bind += eagerified

    # Make the new bind table
    new_bind_buf = encode_bind_table(bind, sizeof_pointer=sizeof_pointer)

    # Add it to the __LINKEDIT segment
    new_bind_offset = replace_linkedit_chunk(
        buf, dyld_info["bind_off"], dyld_info["bind_size"], new_bind_buf)

    # Update DYLD_INFO to point to the new table
    dyld_info["bind_off"] = new_bind_offset
    dyld_info["bind_size"] = len(new_bind_buf)

    _roundtrip_smoketest(buf)

    print("Mangled + flattened {} imports (and eagerified {})"
          .format(mangled_count, len(eagerified)))

    return buf


################################################################
# Pynativelib exports rewriter
################################################################

def rewrite_pynativelib_exports(buf, new_lib_id, symbol_mangler):
    _roundtrip_smoketest(buf)

    # Make a mutable copy to work on
    buf = bytearray(buf)

    header, sizeof_pointer = view_mach_header(buf)
    # Rewrite the library id (like install_name_tool -id):
    def mapper(old_lc):
        if old_lc["cmd"] == LC_ID_DYLIB:
            return dylib_command_with_new_name(old_lc, new_lib_id)
        else:
            return old_lc
    map_load_commands_inplace(header, sizeof_pointer, mapper)

    dyld_info = view_dyld_info(header)
    exports = decode_export_trie(buf, dyld_info["export_off"])

    for export in exports:
        export.symbol_name = symbol_mangler(export.symbol_name)
    print("Mangled {} exports".format(len(exports)))

    new_export_buf = encode_export_trie(exports)
    new_export_offset = replace_linkedit_chunk(
        buf, dyld_info["export_off"], dyld_info["export_size"], new_export_buf)

    dyld_info["export_off"] = new_export_offset
    dyld_info["export_size"] = len(new_export_buf)

    _roundtrip_smoketest(buf)

    return buf


################################################################
# Pynativelib re-exporter writer
################################################################

# Given a dylib and a new_id/mangling rule, create a new dylib that imports
# the dylib that rewrite_pynativelib_exports made, and re-exports everything
# under its original name.
def make_pynativelib_export_reexporter(
        old_buf, imported_lib_id, symbol_mangler, new_lib_id):
    _roundtrip_smoketest(old_buf)

    old_header, pointer_size = view_mach_header(old_buf)

    new_buf = bytearray()
    new_buf += old_buf[:old_header.end_offset]
    new_header, _ = view_mach_header(new_buf)

    # load commands:
    # __TEXT segment with no sections, to cover the load header/load command
    # __LINKEDIT segment with no sections, for the DYLD_INFO
    # LC_LOAD_DYLIB to import the thing
    # LC_ID_DYLIB to name our new library
    #   these both should copy all non-name fields from the original id struct
    # LC_UUID I guess?
    # version-related commands copied from original
    # LC_DYLD_INFO_ONLY (with export table only)

    if pointer_size == 4:
        segment_lc = LC_SEGMENT
        segment_command = SEGMENT_COMMAND
    else:
        segment_lc = LC_SEGMENT_64
        segment_command = SEGMENT_COMMAND_64

    # These load commands should each be the same size as their underlying
    # buffer (so you don't have to worry about setting cmdsize)
    load_commands = []

    __TEXT = segment_command.new()
    __TEXT["cmd"] = segment_lc
    __TEXT["segname"] = b"__TEXT"
    __TEXT["vmaddr"] = 0
    # vmsize to be set later
    __TEXT["fileoff"] = 0
    # filesize to be set later
    # magic values copied from a random ld-generated dylib
    __TEXT["maxprot"] = 0x7
    __TEXT["initprot"] = 0x5
    __TEXT["nsects"] = 0
    __TEXT["flags"] = 0
    load_commands.append(__TEXT)
    # make sure we don't accidentally use this later
    del __TEXT

    __LINKEDIT = segment_command.new()
    __LINKEDIT["cmd"] = segment_lc
    __LINKEDIT["segname"] = b"__LINKEDIT"
    # vmaddr to be set later
    # vmsize to be set later
    # fileoff to be set later
    # filesize to be set later
    # magic values copied from a random ld-generated dylib
    __LINKEDIT["maxprot"] = 0x7
    __LINKEDIT["initprot"] = 0x1
    __LINKEDIT["nsects"] = 0
    __LINKEDIT["flags"] = 0
    load_commands.append(__LINKEDIT)

    for orig_id_lc in view_load_commands(old_header, [LC_ID_DYLIB]):  # pragma: no branch
        new_import_lc = dylib_command_with_new_name(orig_id_lc, imported_lib_id)
        new_import_lc["cmd"] = LC_LOAD_DYLIB
        load_commands.append(new_import_lc)
        new_id_lc = dylib_command_with_new_name(orig_id_lc, new_lib_id)
        load_commands.append(new_id_lc)

    version_lcs = {LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_IPHONEOS,
                   LC_VERSION_MIN_WATCHOS, LC_SOURCE_VERSION}
    for orig_lc in view_load_commands(old_header, version_lcs):
        # ld refuses to let us use -reexported_symbols_list unless we specify
        # -macosx_version_min 10.7, so we'll use that as our minimal version
        # here too.
        lc = orig_lc.copy()
        if lc["cmd"] == LC_VERSION_MIN_MACOSX:
            # "X.Y.Z is encoded in nibbles xxxx.yy.zz" -- loader.h
            lc["version"] = max((10 << 16) | (7 << 8), lc["version"])
        load_commands.append(orig_lc.copy())

    uuid_lc = UUID_COMMAND.new()
    uuid_lc["cmd"] = LC_UUID
    uuid_lc["uuid"] = uuid.uuid4().bytes
    load_commands.append(uuid_lc)

    dyld_lc = DYLD_INFO_COMMAND.new()
    dyld_lc["cmd"] = LC_DYLD_INFO_ONLY
    # all fields default to zero
    # we'll fill in export_off and export_size later
    load_commands.append(dyld_lc)
    # make sure we don't accidentally use this later
    del dyld_lc

    for lc in load_commands:
        assert lc.offset == 0
        pad_inplace(lc.buf, align=pointer_size)
        lc["cmdsize"] = len(lc.buf)
        new_header["sizeofcmds"] += len(lc.buf)
        new_buf += lc.buf
    new_header["ncmds"] = len(load_commands)

    pad_inplace(new_buf, align=4096)
    for lc in view_load_commands(new_header, LC_SEGMENT_ANY):
        if lc["segname"].strip(b"\x00") == b"__TEXT":
            lc["vmsize"] = lc["filesize"] = len(new_buf)
        if lc["segname"].strip(b"\x00") == b"__LINKEDIT":
            lc["vmaddr"] = lc["fileoff"] = len(new_buf)

    old_dyld_info = view_dyld_info(old_header)
    exports = decode_export_trie(old_buf, old_dyld_info["export_off"])
    for export in exports:
        # I'm not 100% sure if this is correct -- maybe we should just be
        # using = instead of |=? AFAICT when REEXPORT is set then dyld ignores
        # everything else, so it may not matter either way.
        # ld -reexported_symbols_list does preserve the WEAK_DEFINITION flag,
        # at least.
        export.flags |= EXPORT_SYMBOL_FLAGS_REEXPORT
        # We can't do the shallow namespace trick and use ordinal -1 here;
        # dyld requires reexport ordinals to be > 0. (See
        # findShallowExportedSymbol.) That's fine, we can use a real import.
        export.library_ordinal = 1
        export.imported_name = symbol_mangler(export.symbol_name)
        export.address = None
    new_export_buf = encode_export_trie(exports)

    new_export_off = replace_linkedit_chunk(new_buf, 0, 0, new_export_buf)
    new_dyld_info = view_dyld_info(new_header)
    new_dyld_info["export_off"] = new_export_off
    new_dyld_info["export_size"] = len(new_export_buf)
    # ld-generated files don't seem to pad __LINKEDIT to a page size multiple
    # so we won't either.
    for lc in view_load_commands(new_header, LC_SEGMENT_ANY):
        if lc["segname"].strip(b"\x00") == b"__LINKEDIT":
            lc["vmsize"] = lc["filesize"] = len(new_export_buf)

    _roundtrip_smoketest(new_buf)

    return new_buf
