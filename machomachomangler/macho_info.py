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
LC_SEGMENT_64 = 0x19
LC_UUID = 0x1b
LC_REEXPORT_DYLIB = 0x1f | LC_REQ_DYLD
LC_DYLD_INFO = 0x22
LC_DYLD_INFO_ONLY = 0x22 | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_IPHONEOS = 0x25
LC_SOURCE_VERSION = 0x2A
LC_VERSION_MIN_WATCHOS = 0x30

# These are the commands that load dylibs.
# When a bind opcode refers to "library 2", it means the second command
# (1-based) load command that falls in this set:
LOAD_DYLIB_COMMANDS = {LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB,
                       LC_LOAD_UPWARD_DYLIB}
# (it's 1-based because -2 means flat namespace, -1 means main executable, and
# 0 means within the same file)

LC_SEGMENT_ANY = {LC_SEGMENT, LC_SEGMENT_64}

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

def _section_fields(addr_t):
    fields = [
        ("16s", "sectname"),
        ("16s", "segname"),
        (addr_t, "addr"),  # vm address
        (addr_t, "size"),
        (uint32_t, "offset"),  # file offset
        (uint32_t, "align"),
        (uint32_t, "reloff"),
        (uint32_t, "nreloc"),
        (uint32_t, "flags"),
        (uint32_t, "reserved1"),
        (uint32_t, "reserved2"),
    ]
    if addr_t is uint64_t:
        fields += [
            (uint32_t, "reserved3"),
        ]
    return fields

SECTION = StructType("SECTION", _section_fields(uint32_t))
SECTION_64 = StructType("SECTION_64", _section_fields(uint64_t))

SECTION_TYPE = 0x000000ff
SECTION_ATTRIBUTES = 0xffffff00

S_ZEROFILL = 0x1

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

UUID_COMMAND = _command(
    "UUID_COMMAND", [
        ("16s", "uuid"),
    ])
LC_ID_TO_STRUCT[LC_UUID] = UUID_COMMAND

VERSION_MIN_COMMAND = _command(
    "VERSION_MIN_COMMAND", [
        (uint32_t, "version"),
        (uint32_t, "sdk"),
    ])
LC_ID_TO_STRUCT[LC_VERSION_MIN_MACOSX] = VERSION_MIN_COMMAND
LC_ID_TO_STRUCT[LC_VERSION_MIN_IPHONEOS] = VERSION_MIN_COMMAND
LC_ID_TO_STRUCT[LC_VERSION_MIN_WATCHOS] = VERSION_MIN_COMMAND

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
# Defined in src/ImageLoaderMachOCompressed.cpp, not loader.h:
EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE =                      0x02
EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION =                    0x04
EXPORT_SYMBOL_FLAGS_REEXPORT =                           0x08
EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER =                  0x10
