import pytest

from patchdf import get_length
from disasm import Operand
from opcodes import Reg

def str_data_to_bytes(s):
    print([int(x, 16) for x in s.split()])
    return bytes([int(x, 16) for x in s.split()])


# 4c1d9a     mov         ecx, [524b50h] ; [aFainted+4]
# 4c1da0     mov         esi, eax
# 4c1da2     mov         eax, [524b4ch] ; [aFainted]
# 4c1da7     mov         [esp+20h], eax
# 4c1dab     mov         [esp+24h], ecx
test_data = str_data_to_bytes(
    '8B 15 44 4B 52 00 8B F0  A1 48 4B 52 00 89 54 24 '
    '20 89 4C 24 24'
)

def test_get_length():
    result = get_length(test_data, 7)
    result['dest'] = str(result['dest'])
    assert result == dict(
        deleted={2, 9},
        dest='[esp+20h]',
        length=21,
        saved_mach=b'\x8b\xf0'
    )
