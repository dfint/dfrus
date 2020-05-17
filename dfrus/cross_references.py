from collections import defaultdict

from dfrus.binio import read_bytes, from_dword

code, rdata, data = range(3)


def get_cross_references(fn, relocs, sections, image_base):
    xrefs = defaultdict(list)
    code_upper_bound = sections[code].rva + sections[code].virtual_size
    # Read all the file sections:
    base_offset = sections[code].physical_offset
    size = sections[-1].physical_offset + sections[-1].physical_size - base_offset
    buffer = read_bytes(fn, base_offset, size)
    for reloc in relocs:
        reloc_off = sections.rva_to_offset(reloc)
        local_off = reloc_off - base_offset
        obj_rva = from_dword(buffer[local_off:local_off+4]) - image_base
        reloc += sections[code].physical_offset
        if code_upper_bound <= obj_rva:
            obj_off = sections.rva_to_offset(obj_rva)
            if obj_off is not None:
                xrefs[obj_off].append(reloc_off)

    return xrefs
