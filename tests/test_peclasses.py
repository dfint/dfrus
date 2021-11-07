from ctypes import sizeof

import pytest

from dfrus.peclasses import (ImageDosHeader, ImageFileHeader, ImageDataDirectory, DataDirectory, ImageOptionalHeader,
                             SectionTable, Section)


def test_sizes():
    assert sizeof(ImageDosHeader) == 64
    assert sizeof(ImageFileHeader) == 20
    assert sizeof(DataDirectory) == 8
    assert sizeof(ImageDataDirectory) == 8 * 16
    assert sizeof(ImageOptionalHeader) == 224


@pytest.fixture
def section_table():
    return SectionTable([
        Section.new(
            b'.text',
            flags=0x60000020,
            pointer_to_raw_data=0x400,
            size_of_raw_data=0xAA9800,
            virtual_address=0x1000,
            virtual_size=0xAA977F
        ),
        Section.new(
            b'.rdata',
            flags=0x40000040,
            pointer_to_raw_data=0xAA9C00,
            size_of_raw_data=0x12CA00,
            virtual_address=0xAAB000,
            virtual_size=0x12C802
        ),
        Section.new(
            b'.data',
            flags=0xC0000040,
            pointer_to_raw_data=0xBD6600,
            size_of_raw_data=0x9A00,
            virtual_address=0xBD8000,
            virtual_size=0xDFC4A4
        ),
        Section.new(
            b'.rsrc',
            flags=0x40000040,
            pointer_to_raw_data=0xBE0000,
            size_of_raw_data=0x1800,
            virtual_address=0x19D5000,
            virtual_size=0x1630
        ),
        Section.new(
            b'.reloc',
            flags=0x42000040,
            pointer_to_raw_data=0xBE1800,
            size_of_raw_data=0xBA200,
            virtual_address=0x19D7000,
            virtual_size=0xBA138
        )
    ])


def test_which_section(section_table):
    assert section_table.which_section(offset=section_table[0].pointer_to_raw_data - 1) == -1
    assert section_table.which_section(offset=section_table[0].pointer_to_raw_data) == 0
    assert section_table.which_section(offset=section_table[0].pointer_to_raw_data + 1) == 0


def test_rva_to_offset(section_table):
    assert (section_table.rva_to_offset(section_table[2].virtual_address + 100)
            == section_table[2].pointer_to_raw_data + 100)

    assert (section_table.offset_to_rva(section_table[3].pointer_to_raw_data + 100)
            == section_table[3].virtual_address + 100)
