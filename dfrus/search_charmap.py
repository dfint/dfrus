from typing import BinaryIO, Sequence, Optional

from .binio import to_dword, read_bytes
from .peclasses import Section


def search_charmap(file: BinaryIO, sections: Sequence[Section], xref_table) -> Optional[int]:
    unicode_table_start = b''.join(
        to_dword(item) for item in [0x20, 0x263A, 0x263B, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022]
    )

    offset = sections[1].physical_offset
    size = sum(section.physical_size for section in sections[1:])
    data_block = read_bytes(file, offset, size)
    for obj_off in xref_table:
        off = obj_off - offset
        if 0 <= off < size:
            buf = data_block[off:off+len(unicode_table_start)]
            if buf == unicode_table_start:
                return obj_off

    return None
