from peclasses.pe_classes import ImageSectionHeader
from peclasses.section_table import Section

from dfrus.binio import fpoke
from dfrus.disasm import align


def create_section_blueprint(section_name, virtual_address, physical_address):
    chars = ImageSectionHeader.Characteristics
    return Section(
        name=section_name,
        virtual_address=virtual_address,
        virtual_size=0,  # for now
        pointer_to_raw_data=physical_address,
        size_of_raw_data=0xFFFFFFFF,  # for now
        characteristics=chars.IMAGE_SCN_CNT_INITIALIZED_DATA | chars.IMAGE_SCN_MEM_READ | chars.IMAGE_SCN_MEM_EXECUTE,
    )


def add_to_new_section(fn, new_section_offset, s: bytes, alignment=4, padding_byte=b"\0"):
    aligned = align(len(s), alignment)
    s = s.ljust(aligned, padding_byte)
    fpoke(fn, new_section_offset, s)
    return new_section_offset + aligned
