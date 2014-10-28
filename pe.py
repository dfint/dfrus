
import struct
from collections import namedtuple
from binio import *
import bisect

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
    if fpeek(fn, MZ_SIGNATURE, 2) != b'MZ':
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

Section = namedtuple('Section', ['name', 'virtual_size', 'rva', 'physical_size', 
    'physical_offset', '-', '-', '-', '-', 'flags'], rename = True)

def get_section_table(fn, pe = None):
    if pe is None:
        pe = fpeek4u(fn, MZ_LFANEW)
    n = fpeek2u(fn, pe + PE_NUMBER_OF_SECTIONS)
    fn.seek(pe + SIZEOF_PE_HEADER)
    return [Section._make(struct.unpack('<8s6L2HL', fn.read(SIZEOF_IMAGE_SECTION_HEADER)))
            for i in range(n)]

def put_section_info(fn, off, sect_info):
    fn.seek(off)
    fn.write(struct.pack('<8s6L2HL',sect_info))

IMAGE_SCN_CNT_CODE                  = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA      = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA    = 0x00000080
IMAGE_SCN_MEM_DISCARDABLE           = 0x02000000
IMAGE_SCN_MEM_SHARED                = 0x10000000
IMAGE_SCN_MEM_EXECUTE               = 0x20000000
IMAGE_SCN_MEM_READ                  = 0x40000000
IMAGE_SCN_MEM_WRITE                 = 0x80000000

def rva_to_off(rva, section_table):
    lo = 0
    hi = len(section_table)-1
    while lo <= hi:
        mid = (lo+hi)//2
        local_offset = rva - section_table[mid].rva
        if loc < 0:
            hi = mid-1
        elif loc < section_table[mid].virtual_size:
            return local_offset + section_table[mid].physical_offset
        else:
            lo = mid+1

def rva_to_off_ex(rva, section):
    return rva + section.physical_offset - section.rva

def off_to_rva(off, section_table):
    lo = 0
    hi = len(section_table)-1
    while lo <= hi:
        mid = (lo+hi)//2
        local_offset = off - section_table[mid].physical_offset
        if loc < 0:
            hi = mid-1
        elif loc < section_table[mid].physical_size:
            return local_offset + section_table[mid].rva
        else:
            lo = mid+1

def off_to_rva_ex(off, section):
    return rva - section.physical_offset + section.rva

IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW  = 3

def get_reloc_table(fn, offset, reloc_size):
    reloc_table = dict()
    cur_off = 0
    fn.seek(offset)
    while cur_off<reloc_size:
        cur_page = get_integer32(fn)
        bloc_size = get_integer32(fn)
        assert(block_size % 4 == 0)
        relocs = get_words(fn, (bloc_size-8)//8)
        reloc_table[cur_page] = relocs
        cur_off += block_size
    return reloc_table

def table_to_relocs(reloc_table):
    relocs = set()
    for cur_page in roloc_table:
        for record in reloc_table[cur_page]:
            if record & 0x3000 == IMAGE_REL_BASED_HIGHLOW << 12:
                relocs.add(cur_page | (record & 0x0FFF))
    return relocs

def get_relocations(fn, sections = None):
    dd = get_data_directory(fn)
    if sections is None:
        sections = get_section_table(fn)
    reloc_off = rva_to_off(dd[DD_BASERELOC][1], sections)
    reloc_size = dd[DD_BASERELOC][2]
    return table_to_relocs( get_reloc_table(fn, reloc_off, reloc_size ) )

def relocs_to_table(relocs):
    reloc_table = dict()
    cur_page = 0
    padding_words = 0
    for item in relocs:
        page = item & 0xFFFFF000
        off  = item & 0x00000FFF
        if page not in reloc_table:
            reloc_table[page] = []
        bisect.insort(reloc_table[page], off)
    reloc_table_size = length(reloc_table)*8 + (length(relocs)+padding_words)*2
    return reloc_table_size, reloc_table

def write_relocation_table(fn, offset, reloc_table):
    fn.seek(offset)
    for page in sorted(reloc_table):
        if len(reloc_table[page]) % 2 == 1:
            reloc_table[page].append(IMAGE_REL_BASED_ABSOLUTE << 12 + 0)
        records = reloc_table[page]
        block_size = len(records)*2 + 8
        write_dwords(fn, [page, block_size])
        write_words(fn, records)

class TestPeObject(TestFileObject):
    file_structure = {
        MZ_SIGNATURE:b'MZ',
        MZ_LFANEW:0x100.to_bytes(4,byteorder='little'),
        0x100:b'PE\0\0'
    }
    def read(self, n):
        if self.position in self.file_structure:
            item_at_pos = self.file_structure[self.position]
            if n<=len(item_at_pos):
                return item_at_pos[:n]
            else:
                return item_at_pos + super().read(n-len(item_at_pos))
        else:
            return super().read(n)
            
if __name__ == "__main__":
    assert(check_pe(TestFileObject()) is None)
    assert(check_pe(TestPeObject()) is not None)
    assert(len(TestPeObject().read(10))==10)
    
