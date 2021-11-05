from ctypes import sizeof

from dfrus.peclasses import (ImageDosHeader, ImageFileHeader, ImageDataDirectory, DataDirectory, ImageOptionalHeader,
                             SectionTable, Section)


def test_sizes():
    assert sizeof(ImageDosHeader) == 64
    assert sizeof(ImageFileHeader) == 20
    assert sizeof(DataDirectory) == 8
    assert sizeof(ImageDataDirectory) == 8 * 16
    assert sizeof(ImageOptionalHeader) == 224


def test_which_section():
    section_table = SectionTable([
        Section.new(b'.text', flags=0x60000020, pstart=0x400, psize=0xAA9800, vstart=0x1000, vsize=0xAA977F),
        Section.new(b'.rdata', flags=0x40000040, pstart=0xAA9C00, psize=0x12CA00, vstart=0xAAB000, vsize=0x12C802),
        Section.new(b'.data', flags=0xC0000040, pstart=0xBD6600, psize=0x9A00, vstart=0xBD8000, vsize=0xDFC4A4),
        Section.new(b'.rsrc', flags=0x40000040, pstart=0xBE0000, psize=0x1800, vstart=0x19D5000, vsize=0x1630),
        Section.new(b'.reloc', flags=0x42000040, pstart=0xBE1800, psize=0xBA200, vstart=0x19D7000, vsize=0xBA138)
    ])

    assert section_table.which_section(offset=section_table[0].pointer_to_raw_data - 1) == -1
    assert section_table.which_section(offset=section_table[0].pointer_to_raw_data) == 0
    assert section_table.which_section(offset=section_table[0].pointer_to_raw_data + 1) == 0
