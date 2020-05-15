import pytest

from dfrus.patchdf import find_earliest_midrefs


def test_find_earliest_midrefs_beater():
    offset = 0x54A44C
    xref_table = {
        offset: [0x44eeba, 0x4549b7, 0x4551A1],
        offset+4: [0x44eec0],
        offset+6: [0x44eeb4],
    }
    assert find_earliest_midrefs(offset, xref_table, len('Beater')) == [0x44eeb4, 0x4549b7, 0x4551A1]


def test_find_earliest_midrefs_sword():
    offset = 0x54A44C
    xref_table = {
        offset: [0x4a306b, 0x496c85, 0x49eb2f],
        offset+4: [0x4a3065, 0x496c78, 0x49eb2b],
    }
    assert find_earliest_midrefs(offset, xref_table, len('SWORD')) == [0x4a3065, 0x496c78, 0x49eb2b]
