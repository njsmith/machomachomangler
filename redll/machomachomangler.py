import copy
import attr
from .util import (
    round_to_next,
    read_uleb128, write_uleb128, read_sleb128, write_sleb128,
    read_asciiz,
)
from .macho_info import *

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
            align_size = 2**arch["align"]
            new_subbuf_offset = round_to_next(len(new_buf), align_size)
            new_buf += b"\x00" * (new_subbuf_offset - len(new_buf))
            assert len(new_buf) == new_subbuf_offset
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

def view_load_commands(header):
    offset = header.end_offset
    for _ in range(header["ncmds"]):
        load_command = view_load_command(header.buf, offset)
        yield load_command
        offset += load_command["cmdsize"]


def replace_linkedit_chunk(buf, old_offset, old_size, new_chunk):
    # buf must be writeable; it's modified in place
    # returns: new_offset
    for load_command in view_load_commands(view_mach_header(buf)[0]):
        if load_command["cmd"] in {LC_SEGMENT, LC_SEGMENT_64}:
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
        buf[old_offset : old_offset+old_size] = b"\x00" * old_size

    # Now we want to put the new chunk in.
    if len(new_chunk) < old_size:
        # We can replace it in-place
        buf[old_offset : old_offset+len(new_chunk)] = new_chunk
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
            print(load_command)
            name, _ = read_asciiz(
                load_command.buf,
                load_command.offset + load_command["dylib_name"])
            print("name =", name)
            libraries[name] = len(libraries) + 1
            if name in libraries_to_mangle:
                print("Making {} into a weak dylib".format(name))
                load_command["cmd"] = LC_LOAD_WEAK_DYLIB
        elif load_command["cmd"] in {LC_DYLD_INFO, LC_DYLD_INFO_ONLY}:
            dyld_info = load_command
            print(load_command)

    exports = list(decode_export_trie(buf, dyld_info["export_off"]))
    reencoded = encode_export_trie(exports)
    exports2 = list(decode_export_trie(reencoded, 0))
    from pprint import pprint
    pprint(exports)
    pprint(exports2)
    assert sorted(exports) == sorted(exports2)

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
    del reencoded, bind2

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
                binding.library_ordinal = BIND_SPECIAL_DYLIB_FLAT_LOOKUP

    # Mangle the eager bindings
    mangle_bindings(bind)

    # Pull out the lazy bindings that need to be mangled, mangle them, and
    # move them into the eager bindings table
    eagerified = []
    lazy = list(decode_bind_table(buf,
                                  dyld_info["lazy_bind_off"],
                                  dyld_info["lazy_bind_size"],
                                  sizeof_pointer=sizeof_pointer,
                                  lazy=True))
    for binding in lazy:
        if binding.library_ordinal in mangle_table:
            eagerified.append(binding)
    mangle_bindings(eagerified)
    bind += eagerified

    # Make the new bind table
    new_bind_buf = encode_bind_table(bind, sizeof_pointer=sizeof_pointer)

    # Add it to the __LINKEDIT segment
    new_bind_offset = replace_linkedit_chunk(
        buf, dyld_info["bind_off"], dyld_info["bind_size"], new_bind_buf)

    # Update DYLD_INFO to point to where it will be
    dyld_info["bind_off"] = new_bind_offset
    dyld_info["bind_size"] = len(new_bind_buf)

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


################################################################
# Exports
################################################################

# trieWalk skips over terminal information while searching the trie for a
# specific symbol
# then findShallowExportedSymbol decodes the terminal information

# EXPORT_SYMBOL_FLAGS_KIND_MASK =                          0x03
# EXPORT_SYMBOL_FLAGS_KIND_REGULAR =                       0x00
# EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL =                  0x01
# EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION =                    0x04
# EXPORT_SYMBOL_FLAGS_REEXPORT =                           0x08
# EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER =                  0x10

@attr.s(slots=True)
class Export:
    symbol = attr.ib()
    flags = attr.ib()
    # for re-exports
    library_ordinal = attr.ib(default=None)
    imported_name = attr.ib(default=None)
    # for stub-and-resolver
    stub = attr.ib(default=None)
    resolver = attr.ib(default=None)
    # for everything else
    address = attr.ib(default=None)

def decode_export_trie(buf, start):
    print(buf[start:start + 100].hex())
    def decode_node(prefix, p):
        print("decoding prefix", prefix, " at ", p)
        terminal_size, p = read_uleb128(buf, p)
        print("terminal_size", terminal_size)
        if terminal_size:
            flags, p = read_uleb128(buf, p)
            print("flags =", flags)
            if flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
                library_ordinal, p = read_uleb128(buf, p)
                imported_name, p = read_asciiz(buf, p)
                if imported_name == b"":
                    imported_name = prefix
                yield Export(symbol=prefix, flags=flags,
                             library_ordinal=library_ordinal,
                             imported_name=imported_name)
            elif flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER:
                stub, p = read_uleb128(buf, p)
                resolver, p = read_uleb128(buf, p)
                yield Export(symbol=prefix, flags=flags,
                             stub=stub, resolver=resolver)
            else:
                address, p = read_uleb128(buf, p)
                yield Export(symbol=prefix, flags=flags, address=address)
        branches = buf[p]
        p += 1
        print("branches", branches)
        for _ in range(branches):
            child_prefix, p = read_asciiz(buf, p)
            child_offset, p = read_uleb128(buf, p)
            yield from decode_node(prefix + child_prefix, start + child_offset)

    return decode_node(b"", start)

# The export trie has a very oddly designed format, where:
# - you have to start with the root at offset 0
# - each node contains the offsets of the children
# - the offsets are variable-length encoded
# This creates a nice circularity, where the offset of the children of course
# is determined by the encoded length of the parent (or at least the root),
# and the encoded length of the parent (/root) is determined by the offset of
# the children.
#
# Our strategy:
# - first, insert all export items into the "deep trie", which is like a trie
#   except each node consumes exactly 1 byte. So you get deep, inefficient
#   chains of nodes with exactly 1 child.
# - then, roll this up into a proper trie. While doing this:
#   - compute the fixed part of each node (the "payload")
#   - make an initial speculative guess as to the final offset of the
#     node. Very speculative, i.e., wrong, i.e., we always guess offset 0.
# - Linearize the trie order (parents before children)
# - Encode the trie. When serializing a parent, use our current guess as to
#   the offsets of its children. As we process each node, update our guess
#   about its offset based on where it ended up on this pass, to use on the
#   next pass.
# - Repeat until we manage a complete pass without any offsets changing.

# Fake trie where each step consumes exactly 1 byte
@attr.s(slots=True)
class DeepNode:
    # maps bytestrings to DeepNode objects
    children = attr.ib(default=attr.Factory(dict))
    export = attr.ib(default=None)

def _deep_tree(exports):
    deep_root = DeepNode()
    for export in exports:
        suffix = export.symbol
        node = deep_root
        while suffix:
            byte = suffix[0:1]
            suffix = suffix[1:]
            if byte not in node.children:
                node.children[byte] = DeepNode()
            node = node.children[byte]
        node.export = export
    return deep_root

# Real trie
@attr.s(slots=True)
class TrieNode:
    payload = attr.ib()
    # [(prefix, child), (prefix, child), ...]
    children = attr.ib(default=attr.Factory(list))
    offset_guess = attr.ib(default=0)

def _trieify(deep_node):
    if deep_node.export is not None:
        e = deep_node.export
        terminal_buf = bytearray()
        terminal_buf += write_uleb128(e.flags)
        if e.flags & EXPORT_SYMBOL_FLAGS_REEXPORT:
            terminal_buf += write_uleb128(e.library_ordinal)
            if e.imported_name != e.symbol:
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
    trie_node = TrieNode(payload=payload)
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
        print(trie_root)
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
