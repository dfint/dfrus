from .binio import fpoke4


def ord_utf16(c):
    return int.from_bytes(c.encode('utf-16')[2:], 'little')


_additional_codepages = {
    'cp437': dict(),  # Stub entry, so that dfrus.py do not complain that cp437 is not implemented
    'cp1251': {
        0xC0: range(ord_utf16('А'), ord_utf16('Я') + 1),
        0xE0: range(ord_utf16('а'), ord_utf16('я') + 1),
        0xA8: ord_utf16('Ё'),
        0xB8: ord_utf16('ё'),
        0xB2: [ord_utf16('І'), ord_utf16('і')],
        # 0xAF: ord_utf16('Ї'),
        0xBF: ord_utf16('ї'),
        0xAA: ord_utf16('Є'),
        0xBA: ord_utf16('є'),
        0xA5: ord_utf16('Ґ'),
        0xB4: ord_utf16('ґ'),
        # 0xA1: ord_utf16('Ў'),
        0xA2: ord_utf16('ў'),
    },
}
_codepages = dict()


def generate_charmap_table_patch(enc1, enc2):
    bt = bytes(range(0x80, 0x100))
    return dict((i, ord_utf16(b))
                for i, (a, b) in enumerate(zip(bt.decode(enc1), bt.decode(enc2, errors='replace')), start=0x80)
                if a != b and b.isalpha())


def get_codepages():
    global _codepages
    if not _codepages:
        _codepages = dict()
        for i in range(700, 1253):
            try:
                _codepages['cp%d' % i] = generate_charmap_table_patch('cp437', 'cp%d' % i)
            except LookupError:
                pass
        
        _codepages.update(_additional_codepages)

    return _codepages


def patch_unicode_table(fn, off, codepage):
    cp = get_codepages()[codepage]
    for item in cp:
        fpoke4(fn, off + item*4, cp[item])
