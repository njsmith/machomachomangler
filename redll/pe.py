import struct
from io import BytesIO
from collections import namedtuple
import warnings

from .pe_info import (
    IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_READ,
    DATA_DIRECTORY_IMPORT_TABLE,
    DATA_DIRECTORY_CERTIFICATE_TABLE,
    DATA_DIRECTORY_DELAY_IMPORT_DESCRIPTOR,
    COFF_HEADER, OPTIONAL_HEADER_32, OPTIONAL_HEADER_64,
    OPTIONAL_MAGIC_32, OPTIONAL_MAGIC_64,
    DATA_DIRECTORY,
    SECTION_TABLE_ENTRY,
    IMPORT_DIRECTORY_TABLE,
    DELAY_LOAD_DIRECTORY_TABLE,
    )

from .util import round_to_next

# Theory of operation
# ===================
#
# Somewhere inside a PE file, there is an "import table" which says:
#
#   from KERNEL32.DLL, import the following symbols:
#     ...
#   from FOO.DLL, import the following symbols:
#     ...
#   ...
#
# (E.g., you can see it if you do 'objdump -x whatever.dll' and look for the
# "Import Tables" section.)
#
# Our goal is to find that table, and replace "FOO.DLL" with
# "BAR.DLL". Unfortunately, though, this table is encoded in a rather
# complicated way, and finding it, decoding it, and modifying it will require
# us to understand some details about the PE file format.
#
# Each PE file starts with several archeological strata of headers:
# - the DOS executable header (which is basically ignored)
# - the COFF header (COFF is the format used for .obj files)
# - the PE "optional header" (which is not optional in .dll and .exe files)
#
# This is then followed by the "section table". The section table is a very
# low-level, non-semantic kind of data structure: it contains a bunch of
# entries saying stuff like:
#   "take the bytes in this file at span FILE_OFFSET through FILE_OFFSET+SIZE
#   and place them into memory at span MEM_OFFSET through MEM_OFFSET+SIZE
#   and make the memory (readonly/writable/executable/etc.)"
#
# Once the file has been loaded into memory, then the real fun starts: there
# are a bunch of complicated pointer-filled structures defined inside that
# data, including
#
# Therefore, our basic plan is:
# 1) Add our new string "BAR.DLL" to the end of the file.
# 2) Add a new entry into the section table so that our new data at the end of
#    the file gets loaded into memory.
# 3) This new entry in the section table means that all the data *after* the
#    section table has to shift over to new positions in the file; update the
#    other entries in the section table to point to the new FILE_OFFSETs.
# 4) Go find the entry in the import table that has a pointer to the "FOO.DLL"
#    string, and modify it to instead have a pointer to where we put our new
#    "BAR.DLL" string.
#
# Of course in the process we have to be careful about various things like
# maintaining alignment rules (generally each section has to be padded to the
# page size), etc.

class BadFile(Exception):
    pass

def view_coff_header(barray):
    if barray[:2] != b"MZ":
        raise BadFile("Not a PE file (bad DOS magic)")
    (pe_offset,) = struct.unpack_from("<i", barray, 0x3c)
    if barray[pe_offset : pe_offset+4] != b"PE\x00\x00":
        raise BadFile("Not a PE file (bad PE magic)")
    return COFF_HEADER.view(barray, pe_offset + 4)

def view_optional_header(coff_header):
    buf = coff_header.buf
    # This size includes the data directories, so isn't useful for checking
    # which kind of header we have. And the magic that tells us which sort it
    # is is inside the actual struct. Simplest is to just try 32-bit first
    # (it's shorter, and the magic is in the same place in both headers), and
    # then switch to 64-bit if the magic says we need to.
    size = coff_header["SizeOfOptionalHeader"]
    if size < OPTIONAL_HEADER_32.size:
        raise BadFile("PE optional header missing or too short ({} bytes)"
                      .format(size))
    optional_header = OPTIONAL_HEADER_32.view(buf, coff_header.next_offset)
    if optional_header["Magic"] == OPTIONAL_MAGIC_32:
        pass
    elif optional_header["Magic"] == OPTIONAL_MAGIC_64:
        if size < OPTIONAL_HEADER_64.size:
            raise BadFile(
                "PE optional header too short for 64-bit file ({} bytes)"
                .format(size))
        optional_header = OPTIONAL_HEADER_64.view(buf, coff_header.next_offset)
    else:
        raise BadFile("unrecognized magic in optional header: {:#04x}"
                      .format(optional_header["Magic"]))
    return optional_header

def _view_array(struct_type, buf, offset, count):
    views = []
    next_offset = offset
    for i in range(count):
        view = struct_type.view(buf, next_offset)
        views.append(view)
        next_offset = view.next_offset
    return views

def view_data_directories(optional_header):
    return _view_array(DATA_DIRECTORY,
                       optional_header.buf, optional_header.next_offset,
                       optional_header["NumberOfRvaAndSizes"])

def view_sections(coff_header, data_directories):
    return _view_array(SECTION_TABLE_ENTRY,
                       coff_header.buf, data_directories[-1].next_offset,
                       coff_header["NumberOfSections"])

PEHeaders = namedtuple("PE_HEADERS",
                       ["coff_header",
                        "optional_header",
                        "data_directories",
                        "sections"])

def view_pe_headers(buf):
    coff_header = view_coff_header(buf)
    optional_header = view_optional_header(coff_header)
    data_directories = view_data_directories(optional_header)
    sections = view_sections(coff_header, data_directories)

    return PEHeaders(coff_header,
                     optional_header,
                     data_directories,
                     sections)

def _map_sections(sections, index,
                  from_start_field, from_size_field,
                  to_start_field, to_size_field,
                  index_name):
    for section in sections:
        sec_from_start = section[from_start_field]
        sec_from_end = sec_from_start + section[from_size_field]
        sec_to_start = section[to_start_field]
        sec_to_size = section[to_size_field]
        if sec_from_start <= index < sec_from_end:
            index_in_section = index - sec_from_start
            if index_in_section >= sec_to_size:
                # This may not be technically illegal -- in particular an RVA
                # can point into an un-backed part of a section, which will be
                # zero-initialized. But there is no file offset to return, and
                # we can't handle it.
                raise BadFile(
                    "can't handle {} lookup into uninitialized space"
                    .format(index_name))
            return sec_to_start + index_in_section
    raise BadFile("can't find section containing {} {:#x}"
                  .format(index_name, index))

def rva_to_file_offset(sections, rva):
    return _map_sections(sections, rva,
                         "VirtualAddress", "VirtualSize",
                         "PointerToRawData", "SizeOfRawData",
                         "RVA")

def file_offset_to_rva(sections, offset):
    return _map_sections(sections, rva,
                         "PointerToRawData", "SizeOfRawData",
                         "VirtualAddress", "VirtualSize",
                         "file offset")

def get_asciiz(buf, offset):
    asciiz = b""
    # next line will break on py2:
    while buf[offset]:
        asciiz += buf[offset:offset+1]
        offset += 1
    return asciiz

def _data_directory_offset(pe_headers, data_directory_index):
    data_directory = pe_headers.data_directories[data_directory_index]
    if not data_directory["Size"]:
        return None
    rva = data_directory["VirtualAddress"]
    return rva_to_file_offset(pe_headers.sections, rva)

def _view_null_terminated_array(buf, offset, struct_type, null_field):
    if offset is None:
        return []
    array = []
    while True:
        entry = struct_type.view(buf, offset)
        if entry[null_field]:
            # this one is valid
            array.append(entry)
            offset = entry.next_offset
        else:
            # this one is null -- we're done
            return array

def view_import_directory_tables(pe_headers):
    buf = pe_headers.coff_header.buf
    offset = _data_directory_offset(pe_headers, DATA_DIRECTORY_IMPORT_TABLE)
    return _view_null_terminated_array(buf, offset,
                                       IMPORT_DIRECTORY_TABLE,
                                       "Import Lookup Table RVA")

def view_delay_load_directory_tables(pe_headers):
    buf = pe_headers.coff_header.buf
    offset = _data_directory_offset(pe_headers,
                                    DATA_DIRECTORY_DELAY_IMPORT_DESCRIPTOR)
    return _view_null_terminated_array(buf, offset,
                                       DELAY_LOAD_DIRECTORY_TABLE,
                                       "Name")

# returns a new mutable buf, plus rva of new section
def add_section(orig_buf, data, characteristics):
    # 8 bytes max; I don't think duplicate names are a problem?
    name = b"redll"
    orig_pe_headers = view_pe_headers(orig_buf)

    max_offset = -1
    max_rva = -1
    for section in orig_pe_headers.sections:
        max_offset = max(max_offset,
                         section["PointerToRawData"]
                         + section["SizeOfRawData"])
        max_rva = max(max_rva,
                      section["VirtualAddress"]
                      + section["VirtualSize"])
    if max_offset < len(orig_buf):
        # There is junk *after* the end of the data visible through PE
        # sections. This will usually be e.g. the payload data for an
        # installer, or a self-extracting zip-file. Either way, we don't want
        # to mess around with this file, because we don't know what invariants
        # it imposes on this trailing data.
        raise ValueError(
            "Can't add new section due to trailing data "
            "(PE ends at {:#x}, file length is {:#x}). "
            "Usually this happens for installers, self-extracting archives, "
            "etc. Sorry, I can't help you."
            .format(max_offset, len(orig_buf)))

    end_of_sections = orig_pe_headers.sections[-1].next_offset
    new_writer = BytesIO()
    # Copy over existing headers
    new_writer.write(orig_buf[:end_of_sections])
    # Add space for our new section metadata.
    # It's likely that there's already some unused space in the file that we
    # could claim. But... that sounds finicky and error-prone, so we just
    # unconditionally add enough space to always allow for our new section
    # table entry while keeping everything aligned. (Usually this will add 512
    # bytes to the file.)
    file_alignment = orig_pe_headers.optional_header["FileAlignment"]
    metadata_offset = new_writer.tell()
    metadata_space = round_to_next(SECTION_TABLE_ENTRY.size,
                                   file_alignment)
    new_writer.write(b"\x00" * metadata_space)
    # Copy over the rest of the file.
    new_writer.write(orig_buf[end_of_sections:])
    # Add in our new section
    data_offset = new_writer.tell()
    data_space = round_to_next(len(data),
                               file_alignment)
    new_writer.write(data)
    new_writer.write(b"\x00" * (data_space - len(data)))

    # Remaining updates will be in-place, so extra buffer
    new_buf = new_writer.getbuffer()

    # Scan over section table to update things, and make sure we didn't mess
    # anything up. Note that our new section will not appear in the section
    # headers yet, because we have not yet incremented NumberOfSections
    new_pe_headers = view_pe_headers(new_buf)
    new_pe_headers.coff_header["NumberOfSections"] += 1
    new_pe_headers.optional_header["SizeOfInitializedData"] += len(data)
    new_pe_headers.optional_header["SizeOfImage"] += metadata_space
    new_pe_headers.optional_header["SizeOfImage"] += data_space
    new_pe_headers.optional_header["SizeOfHeaders"] += metadata_space
    # Unfortunately, this checksum algorithm is secret and
    # proprietary. (Whyyyyy.) Fortunately, for regular programs, nothing cares
    # -- it's checked only for "drivers, any DLL loaded at boot time, and any
    # DLL that is loaded into a critical Windows process". If you really need
    # it then supposedly signing the binary will fix the checksum as well.
    new_pe_headers.optional_header["CheckSum"] = 0

    # Update old sections (remember, our new one doesn't appear here)
    for section in new_pe_headers.sections:
        section["PointerToRawData"] += metadata_space

    # Reload headers so as to see our new section
    new_pe_headers = view_pe_headers(new_buf)

    memory_alignment = new_pe_headers.optional_header["SectionAlignment"]
    new_section_rva = round_to_next(max_rva, memory_alignment)

    new_section = new_pe_headers.sections[-1]
    new_section["Name"] = name
    new_section["VirtualAddress"] = new_section_rva
    new_section["VirtualSize"] = len(data)
    new_section["PointerToRawData"] = data_offset
    new_section["SizeOfRawData"] = data_space
    new_section["Characteristics"] = characteristics

    cert_table = new_pe_headers.data_directories[DATA_DIRECTORY_CERTIFICATE_TABLE]
    if cert_table["Size"] > 0:
        # Clear any certificates
        cert_table["VirtualAddress"] = 0
        cert_table["Size"] = 0
        warnings.warn(UserWarning,
                      "This file used to have an Authenticode signature. "
                      "Now it doesn't. You might want to re-sign it.")

    return new_buf, new_section_rva

def redll(buf, mapping):
    # mapping is a dict of bytes->bytes for dlls to rename
    # Make the section to store the new strings.
    section_offset_mapping = {}
    data_writer = BytesIO()
    for old_dll, new_dll in mapping.items():
        data_offset = data_writer.tell()
        data_writer.write(new_dll)
        data_writer.write(b"\x00")
        section_offset_mapping[old_dll] = data_offset
    data = data_writer.getbuffer()

    # I check python27.dll, and its DLL name RVAs point into section .rdata
    # which has characteristic:
    #   0x40000040
    # = 0x40000000  IMAGE_SCN_MEM_READ
    # +         40  IMAGE_SCN_CNT_INITIALIZED_DATA
    # which sounds about right.
    characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA
    new_buf, new_section_rva = add_section(buf, data,
                                           characteristics)
    rva_mapping = {old_dll: new_section_rva + offset
                   for (old_dll, offset) in section_offset_mapping.items()}

    pe_headers = view_pe_headers(new_buf)

    unused_names = set(rva_mapping)
    def rewrite_names(viewer, name_field):
        for s in viewer(pe_headers):
            name_offset = rva_to_file_offset(pe_headers.sections, s[name_field])
            name = get_asciiz(new_buf, name_offset)
            if name in rva_mapping:
                s[name_field] = rva_mapping[name]
                print("New RVA:", hex(rva_mapping[name]))
                unused_names.discard(name)

    rewrite_names(view_import_directory_tables, "Name RVA")
    rewrite_names(view_delay_load_directory_tables, "Name")

    if unused_names:
        warnings.warn(UserWarning,
                      "Did not find any imports from following DLLs: "
                      + ", ".join(str(name) for name in unused_names))

    return new_buf
