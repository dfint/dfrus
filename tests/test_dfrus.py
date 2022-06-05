from dfrus.patchdf import find_earliest_midrefs


def test_find_earliest_midrefs_beater():
    offset = 0x54A44C
    xref_table = {
        offset: [0x44EEBA, 0x4549B7, 0x4551A1],
        offset + 4: [0x44EEC0],
        offset + 6: [0x44EEB4],
    }
    assert find_earliest_midrefs(offset, xref_table, len("Beater")) == [0x44EEB4, 0x4549B7, 0x4551A1]


def test_find_earliest_midrefs_sword():
    offset = 0x54A44C
    xref_table = {
        offset: [0x4A306B, 0x496C85, 0x49EB2F],
        offset + 4: [0x4A3065, 0x496C78, 0x49EB2B],
    }
    assert find_earliest_midrefs(offset, xref_table, len("SWORD")) == [0x4A3065, 0x496C78, 0x49EB2B]
