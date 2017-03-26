import struct
from binio import *
import bisect

# IMAGE_DOS_HEADER
MZ_SIGNATURE = 0x00
# ...
MZ_LFANEW = 0x3C

# PE header structure offsets
# IMAGE_NT_HEADER
PE_SIGNATURE = 0x00  # 'PE\0\0'
# IMAGE_FILE_HEADER
PE_MACHINE = 0x04
PE_NUMBER_OF_SECTIONS = 0x06  # !
PE_TIMEDATE_STAMP = 0x08
PE_POINTER_TO_SYMBOL_TABLE = 0x0C
PE_NUMBER_OF_SYMBOLS = 0x10
PE_SIZE_OF_OPTIONAL_HEADER = 0x14
PE_CHARACTERISTICS = 0x16
# IMAGE_OPTIONAL_HEADER
PE_MAGIC = 0x18
PE_MAJOR_LINKER_VER = 0x1A
PE_MINOR_LINKER_VER = 0x1B
PE_SIZE_OF_CODE = 0x1C
PE_SIZE_OF_INIT_DATA = 0x20
PE_SIZE_OF_UNINIT_DATA = 0x24
PE_ENTRY_POINT_RVA = 0x28  # !
PE_BASE_OF_CODE = 0x2C
PE_BASE_OF_DATA = 0x30
PE_IMAGE_BASE = 0x34  # !
PE_SECTION_ALIGNMENT = 0x38
PE_FILE_ALIGNMENT = 0x3C
PE_MAJOR_OS_VER = 0x40
PE_MINOR_OS_VER = 0x42
PE_MAJOR_IMAGE_VER = 0x44
PE_MINOR_IMAGE_VER = 0x46
PE_MAJOR_SUBSYS_VER = 0x48
PE_MINOR_SUBSYS_VER = 0x4A
PE_WIN32_VER = 0x4C
PE_SIZE_OF_IMAGE = 0x50
PE_SIZE_OF_HEADER = 0x54
PE_CHECKSUM = 0x58
PE_SUBSYSTEM = 0x5C  # !
PE_DLL_CHARACTERISTICS = 0x5E
PE_SIZE_OF_STACK_RESERVE = 0x60
PE_SIZE_OF_STACK_COMMIT = 0x64
PE_SIZE_OF_HEAP_RESERVE = 0x68
PE_SIZE_OF_HEAP_COMMIT = 0x6C
PE_LOADER_FLAGS = 0x70
PE_NUMBER_OF_RVA_AND_SIZES = 0x74  # reserved
PE_DATA_DIRECTORY = 0x78
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
SIZEOF_DATA_DIRECTORY = 0x08
SIZEOF_PE_HEADER = 0xF8


def check_pe(fn):
    """Check if the given file is Portable Executable and return offset of the PE-header"""
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
    return [get_dwords(fn, 2) for _ in range(IMAGE_NUMBEROF_DIRECTORY_ENTRIES)]


def update_data_directory(fn, dd):
    pe = fpeek4u(fn, MZ_LFANEW)
    fn.seek(pe + PE_DATA_DIRECTORY)
    for item in dd:
        write_dwords(fn, item)

# name, virtual size, relative virtual address, physical size, physical offset
# SECTION_NAME, SECTION_VSIZE, SECTION_RVA, SECTION_PSIZE, SECTION_POFFSET = range(5)
# SECTION_FLAGS = 9  # section flags

SIZEOF_IMAGE_SECTION_HEADER = 0x28


class Section:
    __slots__ = ('name', 'virtual_size', 'rva', 'physical_size', 'physical_offset', 'flags')

    _struct = struct.Struct('<8s4L12xL')
    assert (_struct.size == SIZEOF_IMAGE_SECTION_HEADER)

    @classmethod
    def unpack(cls, x):
        return cls(*cls._struct.unpack(x))

    def pack(self):
        return self._struct.pack(*self)

    @classmethod
    def read(cls, file):
        return cls.unpack(file.read(cls._struct.size))

    def write(self, file):
        file.write(self.pack())

    def __init__(self, name, virtual_size, rva, physical_size, physical_offset, flags):
        self.name = name
        self.virtual_size = virtual_size
        self.rva = rva
        self.physical_size = physical_size
        self.physical_offset = physical_offset
        self.flags = flags

    def __iter__(self):
        yield self.name
        yield self.virtual_size
        yield self.rva
        yield self.physical_size
        yield self.physical_offset
        yield self.flags

    def __repr__(self):
        """Return a nicely formatted representation string"""
        return ((self.__class__.__name__ + '(name=%r, virtual_size=0x%X, rva=0x%X, physical_size=0x%X,' +
                'physical_offset=0x%X, flags=0x%X)') %
                self)


def get_section_table(fn, pe=None):
    if pe is None:
        pe = fpeek4u(fn, MZ_LFANEW)
    n = fpeek2u(fn, pe + PE_NUMBER_OF_SECTIONS)
    fn.seek(pe + SIZEOF_PE_HEADER)
    return [Section.read(fn) for _ in range(n)]


IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_SHARED = 0x10000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


def rva_to_off(rva, section_table):
    lo = 0
    hi = len(section_table) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        local_offset = rva - section_table[mid].rva
        if local_offset < 0:
            hi = mid - 1
        elif local_offset < section_table[mid].virtual_size:
            return local_offset + section_table[mid].physical_offset
        else:
            lo = mid + 1


def rva_to_off_ex(rva, section):
    return rva + section.physical_offset - section.rva


def off_to_rva(off, section_table):
    lo = 0
    hi = len(section_table) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        local_offset = off - section_table[mid].physical_offset
        if local_offset < 0:
            hi = mid - 1
        elif local_offset < section_table[mid].physical_size:
            return local_offset + section_table[mid].rva
        else:
            lo = mid + 1


def off_to_rva_ex(off, section):
    return off - section.physical_offset + section.rva


IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGHLOW = 3


def get_reloc_table(fn, offset, reloc_size) -> iter:
    cur_off = 0
    fn.seek(offset)
    while cur_off < reloc_size:
        cur_page = get_integer32(fn)
        block_size = get_integer32(fn)
        assert (block_size > 8)
        assert ((block_size - 8) % 2 == 0)
        relocs = get_words(fn, (block_size - 8) // 2)
        yield cur_page, relocs
        cur_off += block_size


def table_to_relocs(reloc_table: collections.Iterable) -> iter:
    for cur_page, records in reloc_table:
        for record in records:
            if record >> 12 == IMAGE_REL_BASED_HIGHLOW:
                yield cur_page | (record & 0x0FFF)


def get_relocations(fn, sections=None, offset=None, size=None) -> iter:
    if offset is None or size is None:
        dd = get_data_directory(fn)
        if sections is None:
            sections = get_section_table(fn)
        offset = rva_to_off(dd[DD_BASERELOC][0], sections)
        size = dd[DD_BASERELOC][1]
    return table_to_relocs(get_reloc_table(fn, offset, size))


def relocs_to_table(relocs: collections.Sequence) -> (int, dict):
    reloc_table = dict()
    for item in relocs:
        page = item & 0xFFFFF000
        off = item & 0x00000FFF
        if page not in reloc_table:
            reloc_table[page] = []
        bisect.insort(reloc_table[page], off)
    padding_words = sum(len(reloc_table[page]) % 2 for page in reloc_table)
    reloc_table_size = len(reloc_table) * 8 + (len(relocs) + padding_words) * 2
    return reloc_table_size, reloc_table


def write_relocation_table(fn, offset, reloc_table: dict):
    fn.seek(offset)
    for page in sorted(reloc_table):
        for i, item in enumerate(reloc_table[page]):
            reloc_table[page][i] = item | IMAGE_REL_BASED_HIGHLOW << 12
        # Padding records:
        if len(reloc_table[page]) % 2 == 1:
            reloc_table[page].append(IMAGE_REL_BASED_ABSOLUTE << 12 + 0)
        records = reloc_table[page]
        block_size = len(records) * 2 + 8
        write_dwords(fn, [page, block_size])
        write_words(fn, records)


class TestPeObject(TestFileObject):
    file_structure = {
        MZ_SIGNATURE: b'MZ',
        MZ_LFANEW: 0x100.to_bytes(4, byteorder='little'),
        0x100: b'PE\0\0'
    }

    def read(self, n):
        if self.position in self.file_structure:
            item_at_pos = self.file_structure[self.position]
            if n <= len(item_at_pos):
                return item_at_pos[:n]
            else:
                return item_at_pos + super().read(n - len(item_at_pos))
        else:
            return super().read(n)


if __name__ == "__main__":
    assert(check_pe(TestFileObject()) is None)
    assert(check_pe(TestPeObject()) is not None)
    assert(len(TestPeObject().read(10)) == 10)
    Section(b'123', 1, 2, 3, 4, 5).write(TestPeObject())