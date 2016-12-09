from .destruct import StructType

# Information in this file is all copied straight from the PE/COFF
# specification:
#
#    http://www.microsoft.com/whdc/system/platform/firmware/PECOFF.mspx
#
# When I looked (v8.3), the license was actually OK (there weren't any terms
# that imposed any restrictions on software you wrote based on looking at it),
# but of course check for yourself rather than taking my word for it.
#
# You might also want to check the document "Windows Authenticode Portable
# Executable Signature Format"
#
# Whenever possible this uses exactly the same naming conventions as that
# spec. So if they're clunky or inconsistent... at least they're consistent
# with something!

################################################################
# A few selected constants (add more here if you need them)
################################################################

IMAGE_SCN_CNT_INITIALIZED_DATA =       0x40
IMAGE_SCN_MEM_READ             = 0x40000000

# The offsets of these different entries in the DATA_DIRECTORY array (e.g. the
# 0th entry points to the export table)
DATA_DIRECTORY_EXPORT_TABLE = 0
DATA_DIRECTORY_IMPORT_TABLE = 1
# ...
DATA_DIRECTORY_CERTIFICATE_TABLE = 4
# ...
DATA_DIRECTORY_DELAY_IMPORT_DESCRIPTOR = 13

################################################################
# Structure definitions
################################################################

I1 = "B"
I2 = "H"
I4 = "I"
I8 = "Q"

COFF_HEADER = StructType(
    "COFF_HEADER", [
        (I2, "Machine"),
        (I2, "NumberOfSections"),
        (I4, "TimeDateStamp"),
        (I4, "PointerToSymbolTable"),
        (I4, "NumberOfSymbols"),
        (I2, "SizeOfOptionalHeader"),
        (I2, "Characteristics"),
        ])

def _optional_header_fields(bits):
    assert bits in (32, 64)
    fields = [
        (I2, "Magic"),
        (I1, "MajorLinkerVersion"),
        (I1, "MinorLinkerVersion"),
        (I4, "SizeOfCode"),
        (I4, "SizeOfInitializedData"),
        (I4, "SizeOfUninitializedData"),
        (I4, "AddressOfEntryPoint"),
        (I4, "BaseOfCode"),
        ]
    if bits == 32:
        fields += [(I4, "BaseOfData"),
                   (I4, "ImageBase")]
        I_ptr = I4
    else:
        fields += [(I8, "ImageBase")]
        I_ptr = I8
    fields += [
        (I4, "SectionAlignment"),
        (I4, "FileAlignment"),
        (I2, "MajorOperatingSystemVersion"),
        (I2, "MinorOperatingSystemVersion"),
        (I2, "MajorImageVersion"),
        (I2, "MinorImageVersion"),
        (I2, "MajorSubsystemVersion"),
        (I2, "MinorSubsystemVersion"),
        (I4, "Win32VersionValue"),
        (I4, "SizeOfImage"),
        (I4, "SizeOfHeaders"),
        # Undocumented (really) algorithm; not actually checked in almost any
        # cases:
        (I4, "CheckSum"),
        (I2, "Subsystem"),
        (I2, "DllCharacteristics"),
        (I_ptr, "SizeOfStackReserve"),
        (I_ptr, "SizeOfStackCommit"),
        (I_ptr, "SizeOfHeapReserve"),
        (I_ptr, "SizeOfHeapCommit"),
        (I4, "LoaderFlags"),
        (I4, "NumberOfRvaAndSizes"),
    ]
    return fields

OPTIONAL_HEADER_32 = StructType(
    "OPTIONAL_HEADER_32",
    _optional_header_fields(32))

OPTIONAL_HEADER_64 = StructType(
    "OPTIONAL_HEADER_64",
    _optional_header_fields(64))

OPTIONAL_MAGIC_32 = 0x10b
OPTIONAL_MAGIC_64 = 0x20b

DATA_DIRECTORY = StructType(
    "DATA_DIRECTORY", [
        (I4, "VirtualAddress"),
        (I4, "Size"),
    ])

SECTION_TABLE_ENTRY = StructType(
    "SECTION_TABLE_ENTRY", [
        ("8s", "Name"),
        # mapping will be zero-padded or truncated to make it this big
        (I4, "VirtualSize"),
        # memory address where this mapping will be loaded
        (I4, "VirtualAddress"),
        # number of bytes this section takes up in file
        (I4, "SizeOfRawData"),
        # file offset of this data
        (I4, "PointerToRawData"),
        (I4, "PointerToRelocations"),
        (I4, "PointerToLinenumbers"),
        (I2, "NumberOfRelocations"),
        (I2, "NumberOfLinenumbers"),
        (I4, "Characteristics"),
    ])

# page 63
DELAY_LOAD_DIRECTORY_TABLE = StructType(
    "DELAY_LOAD_DIRECTORY_TABLE", [
        (I4, "Attributes"),
        # The DLL name
        (I4, "Name"),
        (I4, "Module Handle"),
        (I4, "Delay Import Address Table"),
        (I4, "Delay Import Name Table"),
        (I4, "Bound Delay Import Table"),
        (I4, "Unload Delay Import Table"),
        (I4, "Time Stamp"),
    ])

# page 74
EXPORT_DIRECTORY_TABLE = StructType(
    "EXPORT_DIRECTORY_TABLE", [
        (I4, "Export Flags"),
        (I4, "Time/Date Stamp"),
        (I2, "Major Version"),
        (I2, "Minor Version"),
        (I4, "Name RVA"),  # name of this DLL
        (I4, "Ordinal Base"),
        (I4, "Address Table Entries"),
        (I4, "Number of Name Pointers"),
        (I4, "Export Address Table RVA"),
        (I4, "Name Pointer RVA"),  # pointer to sequence of asciiz export names
        (I4, "Ordinal Table RVA"),
    ])

# page 78
IMPORT_DIRECTORY_TABLE = StructType(
    "IMPORT_DIRECTORY_TABLE", [
        (I4, "Import Lookup Table RVA"),
        (I4, "Time/Date Stamp"),
        (I4, "Forwarder Chain"),
        # The DLL name
        (I4, "Name RVA"),
        # The actual thunks that the loader will bind
        (I4, "Import Address Table RVA"),
    ])
