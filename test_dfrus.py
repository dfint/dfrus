import pytest

from dfrus import find_earliest_midrefs


def test_find_earliest_midrefs_beater():
    offset = 0x54A44C
    xref_table = {
        offset: [0x44eeba, 0x4549b7, 0x4551A1],
        offset+4: [0x44eec0],
        offset+6: [0x44eeb4],
    }
    assert find_earliest_midrefs(offset, xref_table[offset], xref_table, len('Beater')) == [0x44eeb4, 0x4549b7, 0x4551A1]