import pytest

from patchdf import get_length
from disasm import Operand
from opcodes import Reg


# 4c1d9a     mov         ecx, [524b50h] ; [aFainted+4]
# 4c1da0     mov         esi, eax
# 4c1da2     mov         eax, [524b4ch] ; [aFainted]
# 4c1da7     mov         [esp+20h], eax
# 4c1dab     mov         [esp+24h], ecx
test_data_1 = bytes.fromhex(
    '8B 15 44 4B 52 00 8B F0  A1 48 4B 52 00 89 54 24 '
    '20 89 4C 24 24'
)


def test_get_length():
    result = get_length(test_data_1, 7)
    result['dest'] = str(result['dest'])
    assert result == dict(
        deleted_relocs={2, 9},
        added_relocs=set(),
        dest='[esp+20h]',
        length=21,
        saved_mach=b'\x8b\xf0'  # mov esi, eax
    )


# 40253b !   mov         ecx, [strz_DOWN_PLANTS_5406cc]
# 402541 !   mov         eax, [strz_CUT_DOWN_PLANTS_5406c8]
# 402546 !   mov         edx, [strz__PLANTS_5406d0]
# 40254c !   mov         [ebp-46ch], ecx
# 402552 !   mov         [ebp-470h], eax
# 402558 !   mov         eax, [strz_NTS_5406d4]
# 40255d !   lea         ecx, [ebp-470h]
# 402563 !   push        ecx
# 402564 !   mov         [ebp-468h], edx
# 40256a !   mov         [ebp-464h], eax
# 402570 !   call        sub_4544e0
test_data_push = bytes.fromhex(
    '8B 0D CC 06 54 00 A1 C8  06 54 00 8B 15 D0 06 54 '
    '00 89 8D 94 FB FF FF 89  85 90 FB FF FF A1 D4 06 '
    '54 00 8D 8D 90 FB FF FF  51 89 95 98 FB FF FF 89 '
    '85 9C FB FF FF E8 6B 1F  05 00 '
)


def test_get_length_push():
    result = get_length(test_data_push, 15)
    result['dest'] = str(result['dest'])
    assert result == dict(
        deleted_relocs={2, 7, 13, 30},
        added_relocs=set(),
        dest='[ecx]',
        length=53,
        saved_mach=bytes.fromhex('8D 8D 90 FB FF FF  51')  # lea ecx, [ebp-470h] ; push ecx
    )


# 414111 !   mov         edx, [strz_after_a_while_543e38]
# 414117 !   mov         eax, [strz_r_a_while_543e3c]
# 41411c !   sub         ecx, [?data_ad682e0]
# 414122 !   mov         [?data_617990], edx
# 414128 !   mov         edx, [strz_while_543e40]
# 41412e !   mov         [?data_617994], eax
# 414133 !   mov         ax, [data_543e44]
# 414139 !   mov         [?data_617998], edx
# 41413f !   mov         [?data_61799c], ax
# 414145 !   cmp         ecx, 0fh
test_data_sub = bytes.fromhex(
    '8B 15 38 3E 54 00 '
    'A1 3C 3E 54 00 '
    '2B 0D E0 82 D6 0A '
    '89 15 90 79 61 00 '
    '8B 15 40 3E 54 00 '
    'A3 94 79 61 00 '
    '66 A1 44 3E 54 00 '
    '89 15 98 79 61 00 '
    '66 A3 9C 79 61 00 '
    '83 F9 0F '
)


def test_get_length_sub():
    result = get_length(test_data_sub, 13)
    result['dest'] = str(result['dest'])
    assert result == dict(
        deleted_relocs={2, 7, 13, 19, 25, 30, 36, 42, 48},
        added_relocs={2},
        dest='[617990h]',
        length=52,
        saved_mach=bytes.fromhex('2B 0D E0 82 D6 0A ')  # sub ecx, [0ad682e0h]
    )
