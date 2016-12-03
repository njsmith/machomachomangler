from .destruct import StructType

# This file contains structs and constants describing the Mach-O format.
#
# Reference:
#
#   Mostly the MacOSX header files, which can be found in e.g.:
#     /Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk/usr/include/
#
# In particular:
#   mach-o/loader.h
#   mach-o/fat.h

uint32_t = "I"
uint64_t = "Q"
# 32 bits signed int, even on 64 bit systems -- see
# mach/{machine,i386}/vm_types.h
integer_t = "i"
cpu_type_t = integer_t
cpu_subtype_t = integer_t
# mach/vm_prot.h
vm_prot_t = "i"

FAT_MAGIC = 0xcafebabe
FAT_CIGAM = 0xbebafeca
# Fat binary structs are always big-endian
FAT_MAGIC_BYTES = bytes.fromhex("cafebabe")

FAT_HEADER = StructType(
    "FAT_HEADER", [
        (uint32_t, "magic"),
        (uint32_t, "nfat_arch"),
    ],
    endian=">")

FAT_ARCH = StructType(
    "FAT_ARCH", [
        (cpu_type_t, "cputype"),
        (cpu_subtype_t, "cpusubtype"),
        (uint32_t, "offset"),
        (uint32_t, "size"),
        (uint32_t, "align"), # needs alignment to 2**<this value>
    ],
    endian=">")

_mach_header_fields = [
        (uint32_t, "magic"),
        (cpu_type_t, "cputype"),
        (cpu_subtype_t, "cpusubtype"),
        (uint32_t, "filetype"),
        (uint32_t, "ncmds"),
        (uint32_t, "sizeofcmds"),
        (uint32_t, "flags"),
    ]

MACH_HEADER = StructType(
    "MACH_HEADER", _mach_header_fields)

# Magic field (32-bit architectures)
MH_MAGIC = 0xfeedface
# Byteswapped magic field
MH_CIGAM = 0xcefaedfe

MACH_HEADER_64 = StructType(
    "MACH_HEADER", _mach_header_fields + [
        (uint32_t, "reserved"),
    ])

# Magic field (64-bit architectures)
MH_MAGIC_64 = 0xfeedfacf
# Byteswapped magic field (64-bit)
MH_CIGAM_64 = 0xcffaedfe

# File types (the ones we care about)
# regular executables:
MH_EXECUTE =     0x2             # demand paged executable file
# ".dylib":
MH_DYLIB =       0x6             # dynamically bound shared library
# ".so":
MH_BUNDLE =      0x8             # dynamically bound bundle file

## Load commands

# Load commands observed in a random 64-bit executable:
#   LC_SEGMENT_64
#   LC_DYLD_INFO_ONLY
#   LC_SYMTAB
#   LC_DYSYMTAB
#   LC_LOAD_DYLINKER
#   LC_UUID
#   LC_VERSION_MIN_MACOSX
#   LC_SOURCE_VERSION
#   LC_MAIN
#   LC_LOAD_DYLIB
#   LC_FUNCTION_STARTS
#   LC_DATA_IN_CODE
#
# Random dylib also uses:
#   LC_ID_DYLIB

# LC_SYMTAB is the old-style symbol table, which can be stripped
#   LC_DYSYMTAB goes along with LC_SYMTAB to further refine it
#   in practice, strip says it can't remove all symbols from this
#   table...
# zibi:mangle-test njs$ strip stripped-orig-dylib.dylib
#    /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/strip: symbols referenced by indirect symbol table entries that can't be stripped in: /Users/njs/mangle-test/stripped-orig-dylib.dylib
# _fprintf
# dyld_stub_binder
# ___stderrp
#
# LC_DYLD_INFO_ONLY is the real import/export table
#
# All of these tables appear to live in the __LINKEDIT segment (no sections)
# which appears to come at the end of the file (always?)

# this is OR'ed into the command constant if dyld is required to understand
# the command; commands without this bit set are ignored if unrecognized
LC_REQ_DYLD = 0x80000000

LC_SEGMENT = 0x1
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xb
LC_LOAD_DYLIB = 0xc
LC_ID_DYLIB = 0xd
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_REEXPORT_DYLIB = 0x1f | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD

# These are the commands that load dylibs.
# When a bind opcode refers to "library 2", it means the second command
# (1-based) load command that falls in this set:
LOAD_DYLIB_COMMANDS = {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB,
                       LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB}
# (it's 1-based because -2 means flat namespace, -1 means main executable, and
# 0 means within the same file)

LC_SEGMENT_64 = 0x19
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD

# These use the LINKEDIT_DATA_COMMAND struct and contain an offset to a blob
# of data in the __LINKEDIT segment. Since we're rewriting with the __LINKEDIT
# segment, we might have to pay attention.
LC_CODE_SIGNATURE = 0x1d
LC_SEGMENT_SPLIT_INFO = 0x1e
LC_FUNCTION_STARTS = 0x26
LC_DATA_IN_CODE = 0x29
LC_DYLIB_CODE_SIGNS_DRS = 0x2b
LC_LINKER_OPTIMIZATION_HINT = 0x2e
# For example, it looks like files commonly have LC_FUNCTION_STARTS data
# sitting into between the LC_DYLD_INFO_ONLY tables and the LC_SYMTAB tables.
# (Alternatively I guess we could leave all the existing data there and just
# append onto the end...)

# it looks like there's typically padding left between the end of the load
# commands and the first segment
# if you pass a really huge name to install_name_tool -id, you get:
# error: /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/install_name_tool: changing install names or rpaths can't be redone for: renamed-orig-dylib.dylib (for architecture x86_64) because larger updated load commands do not fit (the program must be relinked, and you may need to use -headerpad or -headerpad_max_install_names)

def _command(name, fields):
    return StructType(name,
                      [(uint32_t, "cmd"), (uint32_t, "cmdsize")] + fields)

LOAD_COMMAND = _command("LOAD_COMMAND", [])

LC_ID_TO_STRUCT = {}

def _segment_fields(addr_t):
    return [
        ("16s", "segname"),
        (addr_t, "vmaddr"),
        (addr_t, "vmsize"),
        (addr_t, "fileoff"),
        (addr_t, "filesize"),
        (vm_prot_t, "maxprot"),
        (vm_prot_t, "initprot"),
        (uint32_t, "nsects"),
        (uint32_t, "flags"),
    ]

SEGMENT_COMMAND = _command("SEGMENT_COMMAND", _segment_fields(uint32_t))
LC_ID_TO_STRUCT[LC_SEGMENT] = SEGMENT_COMMAND

SEGMENT_COMMAND_64 = _command("SEGMENT_COMMAND_64", _segment_fields(uint64_t))
LC_ID_TO_STRUCT[LC_SEGMENT_64] = SEGMENT_COMMAND_64

# load command variable length strings are uint32_t, which is the offset from
# the start of the load command struct
lc_str = uint32_t

# dylib = StructType(
#     "dylib", [
#         (lc_str, "name"),
#         (uint32_t, "timestamp"),
#         (uint32_t, "current_version"),
#         (uint32_t, "compatibility_version"),
#     ])

# For: LC_ID_DYLIB, LC_LOAD{,_WEAK}_DYLIB, LC_REEXPORT_DYLIB
DYLIB_COMMAND = _command(
    "DYLIB_COMMAND", [
        # Really this is a nested struct, but destruct.py doesn't support
        # those...
        #(dylib, "dylib"),
        (lc_str, "dylib_name"),
        (uint32_t, "dylib_timestamp"),
        (uint32_t, "dylib_current_version"),
        (uint32_t, "dylib_compatibility_version"),
    ])
for lc in [LC_ID_DYLIB, LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB,
           LC_LOAD_UPWARD_DYLIB]:
    LC_ID_TO_STRUCT[lc] = DYLIB_COMMAND

# Interpreting this involves stab.h and nlist.h
SYMTAB_COMMAND = _command(
    "SYMTAB_COMMAND", [
        (uint32_t, "symoff"),
        (uint32_t, "nsyms"),
        (uint32_t, "stroff"),
        (uint32_t, "strsize"),
    ])
LC_ID_TO_STRUCT[LC_SYMTAB] = SYMTAB_COMMAND

# There's a very long and confusing comment about this struct in
# mach-o/loader.h
DYSYMTAB_COMMAND = _command(
    "DYSYMTAB_COMMAND", [
        (uint32_t, "ilocalsym"),
        (uint32_t, "nlocalsym"),
        (uint32_t, "iextdefsym"),
        (uint32_t, "nextdefsym"),
        (uint32_t, "iundefsym"),
        (uint32_t, "nundefsym"),

        (uint32_t, "tocoff"),
        (uint32_t, "ntoc"),

        (uint32_t, "modtaboff"),
        (uint32_t, "nmodtab"),

        (uint32_t, "extrelsymoff"),
        (uint32_t, "nextrefsyms"),

        (uint32_t, "indirectsymoff"),
        (uint32_t, "nindirectsyms"),

        (uint32_t, "extreloff"),
        (uint32_t, "nextrel"),

        (uint32_t, "locreloff"),
        (uint32_t, "nlocrel"),
    ])
LC_ID_TO_STRUCT[LC_DYSYMTAB] = DYSYMTAB_COMMAND

# LC_DYLD_INFO, LC_DYLD_INFO_ONLY
DYLD_INFO_COMMAND = _command(
    "DYLD_INFO_COMMAND", [
        # memory modifications to make when loading at a non-preferred address
        (uint32_t, "rebase_off"),
        (uint32_t, "rebase_size"),

        # binding to external symbols
        (uint32_t, "bind_off"),
        (uint32_t, "bind_size"),

        # some special magic for binding to C++ unique symbols -- same format
        # as above, but sorted alphabetically by symbol name.
        (uint32_t, "weak_bind_off"),
        (uint32_t, "weak_bind_size"),

        # ugghhh there might be pointers into this.
        (uint32_t, "lazy_bind_off"),
        (uint32_t, "lazy_bind_size"),

        (uint32_t, "export_off"),
        (uint32_t, "export_size"),
        ])
LC_ID_TO_STRUCT[LC_DYLD_INFO] = DYLD_INFO_COMMAND
LC_ID_TO_STRUCT[LC_DYLD_INFO_ONLY] = DYLD_INFO_COMMAND

BIND_TYPE_POINTER =                                      1
BIND_TYPE_TEXT_ABSOLUTE32 =                              2
BIND_TYPE_TEXT_PCREL32 =                                 3

BIND_SPECIAL_DYLIB_SELF =                                 0
BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE =                     -1
BIND_SPECIAL_DYLIB_FLAT_LOOKUP =                         -2

BIND_SYMBOL_FLAGS_WEAK_IMPORT =                          0x1
BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION =                  0x8

BIND_OPCODE_MASK =                                       0xF0
BIND_IMMEDIATE_MASK =                                    0x0F
BIND_OPCODE_DONE =                                       0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM =                      0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB =                     0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM =                      0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM =              0x40
BIND_OPCODE_SET_TYPE_IMM =                               0x50
BIND_OPCODE_SET_ADDEND_SLEB =                            0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB =                0x70
BIND_OPCODE_ADD_ADDR_ULEB =                              0x80
BIND_OPCODE_DO_BIND =                                    0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB =                      0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED =                0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB =           0xC0


EXPORT_SYMBOL_FLAGS_KIND_MASK =                          0x03
EXPORT_SYMBOL_FLAGS_KIND_REGULAR =                       0x00
EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL =                  0x01
EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION =                    0x04
EXPORT_SYMBOL_FLAGS_REEXPORT =                           0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER =                  0x10


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
