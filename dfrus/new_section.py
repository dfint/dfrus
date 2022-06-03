from ctypes import sizeof

from .binio import fpoke
from .disasm import align
from .peclasses import PortableExecutable, Section
from .type_aliases import Offset


def create_section_blueprint(section_name, virtual_address, physical_address):
    return Section.new(
        name=section_name,
        virtual_address=virtual_address,
        virtual_size=0,  # for now
        pointer_to_raw_data=physical_address,
        size_of_raw_data=0xFFFFFFFF,  # for now
        flags=Section.IMAGE_SCN_CNT_INITIALIZED_DATA | Section.IMAGE_SCN_MEM_READ | Section.IMAGE_SCN_MEM_EXECUTE
    )


def add_to_new_section(fn, new_section_offset, s: bytes, alignment=4, padding_byte=b"\0"):
    aligned = align(len(s), alignment)
    s = s.ljust(aligned, padding_byte)
    fpoke(fn, new_section_offset, s)
    return new_section_offset + aligned


def add_new_section(pe: PortableExecutable, new_section: Section, new_section_offset: Offset):
    fn = pe.file
    sections = pe.section_table
    section_alignment = pe.image_optional_header.section_alignment
    file_alignment = pe.image_optional_header.file_alignment
    file_size = align(new_section_offset, file_alignment)
    new_section.size_of_raw_data = file_size - new_section.pointer_to_raw_data

    # Align file size
    if file_size > new_section_offset:
        fn.truncate(file_size)

    # Set the new section virtual size
    new_section.virtual_size = new_section_offset - new_section.pointer_to_raw_data
    # Write the new section info
    fn.seek(pe.image_dos_header.e_lfanew + sizeof(pe.image_nt_headers) + len(sections) * sizeof(Section))
    new_section.write(fn)
    # Fix number of sections
    pe.image_file_header.number_of_sections = len(sections) + 1
    # Fix ImageSize field of the PE header
    pe.image_optional_header.size_of_image = align(new_section.virtual_address + new_section.virtual_size,
                                                   section_alignment)
    pe.rewrite_image_nt_headers()
