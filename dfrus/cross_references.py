from collections import defaultdict
from typing import List, Iterable, BinaryIO, Mapping

from .binio import from_dword, read_bytes
from .peclasses import SectionTable

code, rdata, data = range(3)


def get_cross_references(file: BinaryIO,
                         relocation_table: Iterable[int],
                         sections: SectionTable,
                         image_base: int) \
        -> Mapping[int, List[int]]:

    xrefs = defaultdict(list)
    code_section_end_rva = sections[code].virtual_address + sections[code].virtual_size
    # Read all the file sections:
    base_offset = sections[code].pointer_to_raw_data
    size = sections[-1].pointer_to_raw_data + sections[-1].size_of_raw_data - base_offset
    buffer = read_bytes(file, base_offset, size)
    for reloc in relocation_table:
        reloc_off = sections.rva_to_offset(reloc)
        local_off = reloc_off - base_offset
        obj_rva = from_dword(buffer[local_off:local_off+4]) - image_base
        reloc += sections[code].pointer_to_raw_data
        if code_section_end_rva < obj_rva:
            obj_off = sections.rva_to_offset(obj_rva)
            if obj_off is not None:
                xrefs[obj_off].append(reloc_off)

    return xrefs
