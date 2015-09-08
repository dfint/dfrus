#! python3
import struct
# from operator import itemgetter
from collections import OrderedDict, namedtuple


class ImageDosHeader:
    _size = 0x40
    
    def __init__(self, file, offset=0):
        file.seek(offset)
        self.raw = file.read(self._size)
        self.signature = self.raw[:2]
        if self.signature != b'MZ':
            raise ValueError('IMAGE_DOS_HEADER wrong signature: %r' % self.signature)
        self.e_lfanew = int.from_bytes(self.raw[0x3C:], 'little')


class ImageFileHeader:
    _size = 0x14
    _template = '2H 3L 2H'
    _field_names = ('machine', 'number_of_sections', 'timedate_stamp', 'pointer_to_symbol_table',
                    'number_of_symbols', 'size_of_optional_header', 'characteristics')
    
    def __init__(self, file, offset=None):
        if offset is not None:
            file.seek(offset)
        self.raw = file.read(self._size)
        self.items = OrderedDict(zip(self._field_names, struct.unpack(self._template, self.raw)))
    
    def __getattr__(self, attr):
        return self.items[attr]


data_directory_entry = namedtuple('data_directory_entry', ('virtual_address', 'size'))


class DataDirectory:
    _number_of_directory_entries = 16
    _field_names = ('export', 'import', 'resource', 'exception', 'security', 'basereloc', 'debug', 'copyright,'
                    'globalptr', 'tls', 'load_config', 'bound_import', 'iat', 'delay_import', 'com_descriptor',
                    'reserved_1', 'reserved_2')

    def __init__(self, raw):
        self.raw = raw
        self.items = OrderedDict(zip(self._field_names,
                                     (data_directory_entry._make(x) for x in struct.iter_unpack('LL', self.raw))))

    def __getattr__(self, attr):
        return self.items[attr]


class ImageOptionalHeader:
    _template = 'H B B 9L 6H 4L 2H 6L'
    _field_names = (
        'magic', 'major_linker_version', 'minor_linker_version', 'size_of_code',
        'size_of_initialized_data', 'size_of_uninitialized_data',
        'address_of_entry_point', 'base_of_code', 'base_of_data',
        'image_base', 'section_alignment', 'file_alignment',
        'major_operating_system_version', 'minor_operating_system_version',
        'major_image_version', 'minor_image_version',
        'major_subsystem_version', 'minor_subsystem_version',
        'win32_version_value', 'size_of_image', 'size_of_headers', 'check_sum', 'subsystem',
        'dll_characteristics', 'size_of_stack_reserve', 'size_of_stack_commit',
        'size_of_heap_reserve', 'size_of_heap_commit',
        'loader_flags', 'number_of_rva_and_sizes'
    )

    _data_directory_offset = 0x60

    def __init__(self, file, offset=None, size=224):
        if offset is not None:
            file.seek(offset)
        self._size = size
        self.raw = file.read(self._size)
        self.items = OrderedDict(zip(self._field_names,
                                     struct.unpack(self._template, self.raw[:self._data_directory_offset])))

        self._data_directory = DataDirectory(self.raw[self._data_directory_offset:])

    def __getattr__(self, attr):
        if attr == 'data_directory':
            return self._data_directory
        else:
            return self.items[attr]


class ImageNTHeaders:
    def __init__(self, file, offset):
        file.seek(offset)
        self.signature = file.read(4)
        assert self.signature == b'PE\0\0'
        if self.signature != b'PE\0\0':
            raise ValueError('IMAGE_NT_HEADERS wrong signature: %r' % self.signature)
        self.file_header = ImageFileHeader(file)
        assert self.file_header.size_of_optional_header > 0
        self.optional_header = ImageOptionalHeader(file)


class Pe:
    def __init__(self, file):
        self.dos_header = ImageDosHeader(file)
        self.nt_headers = ImageNTHeaders(file, self.dos_header.e_lfanew)
        self.file_header = self.nt_headers.file_header
        self.optional_header = self.nt_headers.optional_header


if __name__ == "__main__":
    with open(r"d:\Games\df_40_24_win_s\Dwarf Fortress.exe", 'rb') as file:
        pe = Pe(file)
        print(pe.dos_header.signature)
        print(hex(pe.dos_header.e_lfanew))
        print(pe.file_header.items)
