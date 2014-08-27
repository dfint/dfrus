
import struct
from collections import namedtuple

from binio import *

# IMAGE_DOS_HEADER
MZ_SIGNATURE = 0x00
# ...
MZ_LFANEW    = 0x3C

# PE header structure offsets
# IMAGE_NT_HEADER
PE_SIGNATURE                = 0x00 # 'PE\0\0'
# IMAGE_FILE_HEADER
PE_MACHINE                  = 0x04
PE_NUMBER_OF_SECTIONS       = 0x06 # !
PE_TIMEDATE_STAMP           = 0x08
PE_POINTER_TO_SYMBOL_TABLE  = 0x0C
PE_NUMBER_OF_SYMBOLS        = 0x10
PE_SIZE_OF_OPTIONAL_HEADER  = 0x14
PE_CHARACTERISTICS          = 0x16
# IMAGE_OPTIONAL_HEADER
PE_MAGIC                    = 0x18
PE_MAJOR_LINKER_VER         = 0x1A
PE_MINOR_LINKER_VER         = 0x1B
PE_SIZE_OF_CODE             = 0x1C
PE_SIZE_OF_INIT_DATA        = 0x20
PE_SIZE_OF_UNINIT_DATA      = 0x24
PE_ENTRY_POINT_RVA          = 0x28, # !
PE_BASE_OF_CODE             = 0x2C,
PE_BASE_OF_DATA             = 0x30,
PE_IMAGE_BASE               = 0x34, # !
PE_SECTION_ALIGNMENT        = 0x38,
PE_FILE_ALIGNMENT           = 0x3C,
PE_MAJOR_OS_VER             = 0x40,
PE_MINOR_OS_VER             = 0x42,
PE_MAJOR_IMAGE_VER          = 0x44,
PE_MINOR_IMAGE_VER          = 0x46,
PE_MAJOR_SUBSYS_VER         = 0x48,
PE_MINOR_SUBSYS_VER         = 0x4A,
PE_WIN32_VER                = 0x4C,
PE_SIZE_OF_IMAGE            = 0x50,
PE_SIZE_OF_HEADER           = 0x54,
PE_CHECKSUM                 = 0x58,
PE_SUBSYSTEM                = 0x5C, # !
PE_DLL_CHARACTERISTICS      = 0x5E,
PE_SIZE_OF_STACK_RESERVE    = 0x60,
PE_SIZE_OF_STACK_COMMIT     = 0x64,
PE_SIZE_OF_HEAP_RESERVE     = 0x68,
PE_SIZE_OF_HEAP_COMMIT      = 0x6C,
PE_LOADER_FLAGS             = 0x70,
PE_NUMBER_OF_RVA_AND_SIZES  = 0x74, # reserved
PE_DATA_DIRECTORY           = 0x78,
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16,
SIZEOF_DATA_DIRECTORY       = 0x08,
SIZEOF_PE_HEADER            = 0xF8

def check_pe(fn):
    if fpeek(fn, MZ.SIGNATURE, 2) != b'MZ':
        return None
    pe_header_offset = fpeek4u(fn, MZ_LFANEW)
    if fpeek(fn, pe_header_offset + PE_SIGNATURE, 4) != b'PE\0\0':
        return None
    return pe_header_offset

DD_EXPORT, DD_IMPORT, DD_RESOURCE, DD_EXCEPTION, \
DD_SECURITY, DD_BASERELOC, DD_DEBUG, DD_ARCHITECTURE, \
DD_GLOBALPTR, DD_TLS, DD_LOAD_CONFIG, DD_BOUND_IMPORT, \
DD_IAT, DD_DELAY_IMPORT, DD_COM_DESCRIPTOR = range(15)

def get_data_directory(fn):
    pe = fpeek4u(fn, MZ_LFANEW)
    fn.seek(pe + PE_DATA_DIRECTORY)
    return [get_dwords(fn, 2) for i in range(IMAGE_NUMBEROF_DIRECTORY_ENTRIES)]

# name, virtual size, relative virtual address, physical size, physical offset
# SECTION_NAME, SECTION_VSIZE, SECTION_RVA, SECTION_PSIZE, SECTION_POFFSET = range(5)
# SECTION_FLAGS = 9  # section flags

SIZEOF_IMAGE_SECTION_HEADER = 0x28

Section = namedtuple('Section', ['name', 'virtual_size', 'rva', 'physical_size', 'physical_offset',
                                '-', '-', '-', '-', 'flags'], rename = True)

def get_section_table(fn, pe = None):
    if pe is None:
        pe = fpeek4u(fn, MZ_LFANEW)
    n = fpeek2u(fn, pe + PE_NUMBER_OF_SECTIONS)
    fn.seek(pe + SIZEOF_PE_HEADER)
    return [Section._make(struct.unpack('<8s6L2HL', fn.read(SIZEOF_IMAGE_SECTION_HEADER)))
            for i in range(n)]

