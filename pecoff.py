from collections import namedtuple
import struct
import binio

import pe


# IMAGE_FILE_HEADER
IMAGE_FILE_HEADER_ = namedtuple('IMAGE_FILE_HEADER', ['Machine', 'NumberOfSections', 'TimeDateStamp',
                                                      'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader',
                                                      'Characteristics'])


class IMAGE_FILE_HEADER(IMAGE_FILE_HEADER_):
    __slots__ = ()

    _struct = struct.Struct('<2H3L2H')

    Size = _struct.size

    @classmethod
    def unpack(cls, data):
        return cls._make(cls._struct.unpack(data))

    def pack(self):
        return self._struct.pack(self)


# IMAGE_SECTION_HEADER
IMAGE_SECTION_HEADER_ = namedtuple('IMAGE_SECTION_HEADER', ['Name', 'VirtualSize',
                                                            'VirtualAddress', 'SizeOfRawData', 'PointerToRawData',
                                                            'PointerToRelocations',
                                                            'PointerToLinenumbers', 'NumberOfRelocations',
                                                            'NumberOfLinenumbers', 'Characteristics'])


class IMAGE_SECTION_HEADER(IMAGE_SECTION_HEADER_):
    __slots__ = ()

    _struct = struct.Struct('<8s6L2HL')

    Size = _struct.size

    assert (Size == pe.SIZEOF_IMAGE_SECTION_HEADER)

    @classmethod
    def unpack(cls, data):
        return cls._make(cls._struct.unpack(data))

    def pack(self):
        return self._struct.pack(self)


# IMAGE_SYMBOL

IMAGE_SYMBOL_ = namedtuple('IMAGE_SYMBOL', ['Name', 'Value', 'SectionNumber', 'Type',
                                            'StorageClass', 'NumberOfAuxSymbols'])

class IMAGE_SYMBOL(IMAGE_SYMBOL_):
    __slots__ = ()
    
    _struct_longname = struct.Struct('<3L2H2B')
    _struct_shortname = struct.Struct('<8sL2H2B')
    assert(_struct_longname.size == _struct_shortname.size)
    
    Size = _struct_longname.size
    
    @classmethod
    def unpack(cls, data):
        long = cls._struct_longname.unpack(data)
        if long[0]:  # Short name
            return cls._make(cls._struct_shortname.unpack(data))
        else:  # Long name
            return cls._make(long[1:])
    
    @classmethod
    def load_symbol_table(cls, fn, n):
        end_of_symbol_table = fn.tell()+cls.Size*n
        symbol_table = []
        for _ in range(n):
            buf = fn.read(cls.Size)
            if buf[0]:
                symbol_table.append(cls._make(cls._struct_shortname.unpack(buf)))
            else:
                fields = list(cls._struct_longname.unpack(buf))
                name_offset = fields[1]
                saved_position = fn.tell()
                fn.seek(end_of_symbol_table+name_offset)
                name = binio.read_string(fn)
                fn.seek(saved_position)
                fields = fields[1:]
                fields[0] = name
                symbol_table.append(cls._make(fields))
        return symbol_table
        
    
    def pack(self):
        pass # Not implemented


def load_coff(fn):
    fn.seek(0)
    ifh = IMAGE_FILE_HEADER.unpack(fn.read(IMAGE_FILE_HEADER.Size))
    n = ifh.NumberOfSections
    ISH = IMAGE_SECTION_HEADER
    sections = [ISH.unpack(fn.read(ISH.Size)) for _ in range(n)]
    fn.seek(ifh.PointerToSymbolTable)
    symbol_table = IMAGE_SYMBOL.load_symbol_table(fn, ifh.NumberOfSymbols)
    return ifh, sections, symbol_table


with open("addcoloredst.obj", "rb") as obj:
    header, sections, symbol_table = load_coff(obj)
    print(header, end='\n\n')
    print()
    for item in sections:
        print(item)
    print()
    for item in symbol_table:
        print(item)
