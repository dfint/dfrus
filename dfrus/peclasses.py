import bisect
from array import array
from ctypes import c_char, c_ushort, c_uint, sizeof, c_ubyte
from itertools import zip_longest
from typing import (Iterable, MutableMapping, List, Mapping, BinaryIO, Tuple, Sequence, Optional, Type, TypeVar,
                    SupportsBytes)

from .ctypes_annotated_structure import AnnotatedStructure
from .disasm import align

TStructure = TypeVar("TStructure")


def read_structure(cls: Type[TStructure], file: BinaryIO, offset=None) -> TStructure:
    if offset is not None:
        file.seek(offset)

    raw = file.read(sizeof(cls))
    new_obj = cls.from_buffer_copy(raw)
    return new_obj


class ImageDosHeader(AnnotatedStructure):
    e_magic: c_char * 2
    e_cblp: c_ushort
    e_cp: c_ushort
    e_crlc: c_ushort
    e_cparhdr: c_ushort
    e_minalloc: c_ushort
    e_maxalloc: c_ushort
    e_ss: c_ushort
    e_sp: c_ushort
    e_csum: c_ushort
    e_ip: c_ushort
    e_cs: c_ushort
    e_lfarlc: c_ushort
    e_ovno: c_ushort
    e_res: c_ushort * 4
    e_oemid: c_ushort
    e_oeminfo: c_ushort
    e_res2: c_ushort * 10
    e_lfanew: c_uint


print(sizeof(ImageDosHeader))


class ImageFileHeader(AnnotatedStructure):
    machine: c_ushort
    number_of_sections: c_ushort
    timedate_stamp: c_uint
    pointer_to_symbol_table: c_uint
    number_of_symbols: c_uint
    size_of_optional_header: c_ushort
    characteristics: c_ushort


class DataDirectory(AnnotatedStructure):
    virtual_address: c_uint
    size: c_uint


class ImageDataDirectory(AnnotatedStructure):
    export: DataDirectory
    import_directory: DataDirectory
    resource: DataDirectory
    exception: DataDirectory
    security: DataDirectory
    basereloc: DataDirectory
    debug: DataDirectory
    copyright: DataDirectory
    globalptr: DataDirectory
    tls: DataDirectory
    load_config: DataDirectory
    bound_import: DataDirectory
    iat: DataDirectory
    delay_import: DataDirectory
    com_descriptor: DataDirectory
    reserved: DataDirectory


class ImageOptionalHeader(AnnotatedStructure):
    magic: c_ushort
    major_linker_version: c_ubyte
    minor_linker_version: c_ubyte
    size_of_code: c_uint
    size_of_initialized_data: c_uint
    size_of_uninitialized_data: c_uint
    address_of_entry_point: c_uint
    base_of_code: c_uint
    base_of_data: c_uint
    image_base: c_uint
    section_alignment: c_uint
    file_alignment: c_uint
    major_operating_system_version: c_ushort
    minor_operating_system_version: c_ushort
    major_image_version: c_ushort
    minor_image_version: c_ushort
    major_subsystem_version: c_ushort
    minor_subsystem_version: c_ushort
    win32_version_value: c_uint
    size_of_image: c_uint
    size_of_headers: c_uint
    check_sum: c_uint
    subsystem: c_ushort
    dll_characteristics: c_ushort
    size_of_stack_reserve: c_uint
    size_of_stack_commit: c_uint
    size_of_heap_reserve: c_uint
    size_of_heap_commit: c_uint
    loader_flags: c_uint
    number_of_rva_and_sizes: c_uint
    image_data_directory: ImageDataDirectory


class ImageNTHeaders(AnnotatedStructure):
    signature: c_char * 4
    image_file_header: ImageFileHeader
    image_optional_header: ImageOptionalHeader


class Section(AnnotatedStructure):
    # ImageSectionHeader
    IMAGE_SCN_CNT_CODE = 0x00000020
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
    IMAGE_SCN_MEM_SHARED = 0x10000000
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    IMAGE_SCN_MEM_READ = 0x40000000
    IMAGE_SCN_MEM_WRITE = 0x80000000

    name: c_char * 8
    virtual_size: c_uint
    virtual_address: c_uint
    size_of_raw_data: c_uint
    pointer_to_raw_data: c_uint
    pointer_to_relocations: c_uint
    pointer_to_linenumbers: c_uint
    number_of_relocations: c_ushort
    number_of_linenumbers: c_ushort
    characteristics: c_uint

    @staticmethod
    def new(name: bytes, flags: int,
            pointer_to_raw_data: int,
            size_of_raw_data: int,
            virtual_address: int,
            virtual_size: int):
        self = Section()
        self.name = type(self.name)(name)
        self.characteristics = flags
        self.pointer_to_raw_data = pointer_to_raw_data
        self.size_of_raw_data = size_of_raw_data
        self.virtual_address = virtual_address
        self.virtual_size = virtual_size
        return self

    def offset_to_rva(self, offset):
        local_offset = offset - self.pointer_to_raw_data
        assert 0 <= local_offset < self.size_of_raw_data
        return local_offset + self.virtual_address

    def rva_to_offset(self, virtual_address):
        local_offset = virtual_address - self.virtual_address
        assert 0 <= local_offset < self.virtual_size
        return local_offset + self.pointer_to_raw_data

    def __repr__(self):
        return f"{self.__class__.__name__}({self.name!r}, flags=0x{self.characteristics:X}, " \
               f"pstart=0x{self.pointer_to_raw_data:X}, psize=0x{self.size_of_raw_data:X}, " \
               f"vstart=0x{self.virtual_address:X}, vsize=0x{self.virtual_size:X})"


class Key(Sequence):
    def __init__(self, sequence: Sequence, key):
        self.sequence = sequence
        self.key = key

    def __len__(self):
        return len(self.sequence)

    def __getitem__(self, i):
        return self.key(self.sequence[i])


class SectionTable(Sequence[Section]):
    def __init__(self, sections: Sequence[Section]):
        self._sections: Sequence[Section] = sections

        # Make auxiliary objects to perform bisection search among physical offsets and rvas:
        self._offset_key = Key(self, lambda x: x.pointer_to_raw_data)
        self._rva_key = Key(self, lambda x: x.virtual_address)

        assert all(x.virtual_address < self._sections[i + 1].virtual_address
                   for i, x in enumerate(self._sections[:-1]))
        assert all(x.pointer_to_raw_data < self._sections[i + 1].pointer_to_raw_data
                   for i, x in enumerate(self[:-1]))

    @classmethod
    def read(cls, file, offset, number):
        file.seek(offset)
        return cls([read_structure(Section, file) for _ in range(number)])

    def write(self, file, offset=None):
        if offset is not None:
            file.seek(offset)

        section: SupportsBytes
        for section in self._sections:
            file.write(bytes(section))

    def offset_to_rva(self, offset):
        i = bisect.bisect(self._offset_key, offset) - 1
        return self._sections[i].offset_to_rva(offset)

    def rva_to_offset(self, rva):
        i = bisect.bisect(self._rva_key, rva) - 1
        return self._sections[i].rva_to_offset(rva)

    def which_section(self, offset=None, rva=None):
        if offset is not None:
            return bisect.bisect(self._offset_key, offset) - 1
        elif rva is not None:
            return bisect.bisect(self._rva_key, rva) - 1
        else:
            return None

    def diff(self, other):
        for left, right in zip_longest(self._sections, other):
            if left != right:
                yield left, right

    def __repr__(self):
        return 'SectionTable([\n\t%s\n])' % ',\n\t'.join(repr(x) for x in self._sections)

    def __str__(self):
        return 'SectionTable([\n\t%s\n])' % ',\n\t'.join(str(x) for x in self._sections)

    def __getitem__(self, item):
        return self._sections[item]

    def __len__(self):
        return len(self._sections)

    def __iter__(self):
        return iter(self._sections)


class RelocationTable:
    IMAGE_REL_BASED_ABSOLUTE = 0
    IMAGE_REL_BASED_HIGHLOW = 3

    _table: Mapping[int, List[int]]

    def __init__(self, table: Mapping[int, List[int]]):
        self._table = table

    def __iter__(self):
        for page, records in self._table.items():
            for record in records:
                yield page | (record & 0x0FFF)

    @classmethod
    def build(cls, relocs: Iterable[int]):
        reloc_table: MutableMapping[int, List[int]] = dict()
        for item in relocs:
            page = item & 0xFFFFF000
            offset = item & 0x00000FFF
            if page not in reloc_table:
                reloc_table[page] = []
            bisect.insort(reloc_table[page], offset)
        return cls(reloc_table)

    @staticmethod
    def iter_read(file: BinaryIO, reloc_size: int) -> Iterable[Tuple[int, List[int]]]:
        cur_off = 0
        while cur_off < reloc_size:
            cur_page = int.from_bytes(file.read(4), 'little')
            block_size = int.from_bytes(file.read(4), 'little')
            assert (block_size > 8), block_size
            assert ((block_size - 8) % 2 == 0)
            relocs = array('H')
            relocs.fromfile(file, (block_size - 8) // 2)
            yield cur_page, [x for x in relocs if x >> 12 == RelocationTable.IMAGE_REL_BASED_HIGHLOW]
            cur_off += block_size

    @classmethod
    def from_file(cls, file, reloc_size):
        return cls(dict(cls.iter_read(file, reloc_size)))

    @property
    def size(self):
        words = sum(align(len(val), 2) for val in self._table.values())
        return len(self._table) * 8 + words * 2

    def to_file(self, file):
        for page in sorted(self._table):
            records = [item | RelocationTable.IMAGE_REL_BASED_HIGHLOW << 12
                       for item in self._table[page]]

            # Padding records:
            if len(records) % 2 == 1:
                records.append(RelocationTable.IMAGE_REL_BASED_ABSOLUTE << 12 | 0)
            block_size = 8 + 2 * len(records)  # 2 dwords + N words
            array('I', [page, block_size]).tofile(file)
            array('H', records).tofile(file)


class PortableExecutable:
    file: BinaryIO
    image_dos_header: ImageDosHeader
    image_nt_headers: ImageNTHeaders
    image_file_header: ImageFileHeader
    image_optional_header: ImageOptionalHeader
    image_data_directory: ImageDataDirectory
    _section_table: Optional[SectionTable]
    _relocation_table: Optional[RelocationTable]

    def read_file(self, file):
        self.file = file
        self.file.seek(0)
        self.image_dos_header = read_structure(ImageDosHeader, file)
        assert self.image_dos_header.e_magic == b"MZ"
        self.image_nt_headers = read_structure(ImageNTHeaders, file, self.image_dos_header.e_lfanew)
        assert self.image_nt_headers.signature == b"PE"
        self.image_file_header = self.image_nt_headers.image_file_header
        self.image_optional_header = self.image_nt_headers.image_optional_header
        self.image_data_directory = self.image_optional_header.image_data_directory
        self._section_table = None
        self._relocation_table = None

    def rewrite_image_nt_headers(self):
        offset = self.image_dos_header.e_lfanew
        self.file.seek(offset)
        self.image_nt_headers: SupportsBytes
        self.file.write(bytes(self.image_nt_headers))

    def rewrite_data_directory(self):
        offset = self.image_dos_header.e_lfanew + sizeof(ImageNTHeaders) - sizeof(ImageDataDirectory)
        self.file.seek(offset)
        self.image_data_directory: SupportsBytes
        self.file.write(bytes(self.image_data_directory))

    def reread(self):
        self.read_file(self.file)

    def __init__(self, file):
        self.read_file(file)

    @property
    def section_table(self):
        if self._section_table is None:
            n = self.image_file_header.number_of_sections
            offset = self.image_dos_header.e_lfanew + sizeof(self.image_nt_headers)
            self._section_table = SectionTable.read(self.file, offset, n)
        return self._section_table

    @property
    def relocation_table(self) -> RelocationTable:
        if self._relocation_table is None:
            rva = self.image_data_directory.basereloc.virtual_address
            offset = self.section_table.rva_to_offset(rva)
            size = self.image_data_directory.basereloc.size
            self.file.seek(offset)
            self._relocation_table = RelocationTable.from_file(self.file, size)
        return self._relocation_table

    def info(self):
        entry_point = self.image_optional_header.address_of_entry_point + self.image_optional_header.image_base
        return (
            f'DOS signature: {self.image_dos_header.e_magic!r}\n'
            f'e_lfanew: 0x{self.image_dos_header.e_lfanew:x}\n'
            f'PE signature: {self.image_nt_headers.signature!r}\n'
            f'Entry point address: 0x{entry_point}\n'
            f'{self.image_file_header}\n'
            f'{self.image_optional_header}\n'
            f'{self.image_data_directory}\n'
            f'{self.section_table}\n'
        )


def main():
    with open("/home/insolor/Projects/Dwarf Fortress/df/df_42_06_win_s/Dwarf Fortress.exe", 'rb') as file:
        pe = PortableExecutable(file)
        print(pe.info())


if __name__ == "__main__":
    main()
