from collections import namedtuple
import struct

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


#

def load_coff(fn):
    fn.seek(0)
    ifh = IMAGE_FILE_HEADER.unpack(fn.read(IMAGE_FILE_HEADER.Size))
    n = ifh.NumberOfSections
    ISH = IMAGE_SECTION_HEADER
    sections = [ISH.unpack(fn.read(ISH.Size)) for _ in range(n)]
    return ifh, sections


with open("addcoloredst.obj", "rb") as obj:
    header, sections = load_coff(obj)
    print(header)
    print(sections)
