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
    '8B 0D 50 4B 52 00 8B F0  A1 4C 4B 52 00 89 44 24 '
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
test_data_abs_ref = bytes.fromhex(
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


def test_get_length_abs_ref():
    result = get_length(test_data_abs_ref, 13)
    result['dest'] = str(result['dest'])
    assert result == dict(
        deleted_relocs={2, 7, 13, 19, 25, 30, 36, 42, 48},
        added_relocs={2},
        dest='[617990h]',
        length=52,
        saved_mach=bytes.fromhex('2B 0D E0 82 D6 0A ')  # sub ecx, [0ad682e0h]
    )


# 428605 !   mov         eax, [strz_nausea_5452c4]
# 42860a !   mov         cx, [data_5452c8]
# 428611 !   mov         dl, [data_5452ca]
# 428617 !   mov         [?data_ae19178], eax
# 42861c !   mov         [?data_ae1917c], cx
# 428623 !   mov         [?data_ae1917e], dl
# 428629 !   mov         dword ptr [?data_ad6848c], 0ffffff93h
test_data_abs_ref_simple = bytes.fromhex(
    'A1 C4 52 54 00 66 8B 0D  C8 52 54 00 8A 15 CA 52 '
    '54 00 A3 78 91 E1 0A 66  89 0D 7C 91 E1 0A 88 15 '
    '7E 91 E1 0A C7 05 8C 84  D6 0A 93 FF FF FF 33 F6 '
    'FF D3 99 B9 03 00 00 00  F7 F9 8B FA FF D3 99 B9 '
)


def test_get_length_abs_ref_simple():
    result = get_length(test_data_abs_ref_simple, 6)
    result['dest'] = str(result['dest'])
    assert result == dict(
        deleted_relocs={1, 8, 14, 19, 26, 32},
        added_relocs=set(),
        dest='[0AE19178h]',
        length=36,
        saved_mach=bytes()
    )


test_data_nausea = bytes.fromhex(
    '0F B7 15 C8 52 54 00 '  # movzx edx, word [5452C8h]
    'B9 0A 00 00 00 '  # mov ecx, 0Ah
    'BE 30 63 54 00 '  # mov esi, 546330h
    'BF F5 B3 62 00 '  # mov edi, 62B3F5h
    'F3 A5 '  # rep movsd
    'B9 0E 00 00 00 '  # mov ecx, 0Eh
    'BE 58 63 54 00 '  # mov esi, 546358h
    'BF F5 B7 62 00 '  # mov edi, 62B7F5h
    'F3 A5 '  # rep movsd
    '66 A5 '  # movsw
    '8B 0D C4 52 54 00 '  # mov ecx, [5452C4h]
    'A4 '  # movsb
    '89 0D 5C BC 62 00 '  # mov [62BC5Ch], ecx
    '0F B6 0D CA 52 54 00 '  # movzx cx, byte [5452CAh]
    '88 0D 62 BC 62 00 '  # mov [62BC62h], cl
    '66 89 15 60 BC 62 00 '  # mov [62BC60h], dx
    'B0 01 '  # <-- mov al, 1
    'A2 5A BC 62 00 '  # mov [62BC5Ah], al
    'B9 08 00 00 00 '  # mov ecx, 8
)


def test_get_length_nausea():
    saved = bytes.fromhex(
        'B9 0A 00 00 00 '  # mov ecx, 0Ah
        'BE 30 63 54 00 '  # mov esi, 546330h
        'BF F5 B3 62 00 '  # mov edi, 62B3F5h
        'F3 A5 '  # rep movsd
        'B9 0E 00 00 00 '  # mov ecx, 0Eh
        'BE 58 63 54 00 '  # mov esi, 546358h
        'BF F5 B7 62 00 '  # mov edi, 62B7F5h
        'F3 A5 '  # rep movsd
        '66 A5 '  # movsw
        'A4 '  # movsb
    )
    result = get_length(test_data_nausea, len('nausea'))
    result['dest'] = str(result['dest'])
    assert result == dict(
        deleted_relocs={3, 13, 18, 30, 35, 45, 52, 59, 65, 72},
        added_relocs={6, 11, 23, 28},
        dest='[62BC5Ch]',
        length=76,
        saved_mach=saved
    )


test_data_whimper_gnaw_intersection = bytes.fromhex(
    '8B 0D 04 1F 54 00 '  # mov ecx, dword ptr ds:aWhimper+4
    '85 C0 '  # test eax, eax
    'A1 00 1F 54 00 '  # mov eax, dword ptr ds:aWhimper
    '0F 95 C2 '  # setnz dl
    'A3 58 F2 8F 06 '  # mov dword ptr buffer_68FF258, eax
    'A0 6C 2F 55 00 '  # mov al, byte ptr ds:aGnaw+4
    'A2 66 F2 8F 06 '  # mov buffer_68FF262+4, al
    'B0 32 '  # mov al, 32h
    '89 0D 5C F2 8F 06 '  # mov dword ptr buffer_68FF258+4, ecx
    'C6 05 75 F2 8F 06 3C '  # mov byte_68FF275, 3Ch
)


def test_get_length_whimper_gnaw_intersection():
    saved = bytes.fromhex(
        '85 C0 '  # test eax, eax
        '0F 95 C2 '  # setnz dl
    )
    result = get_length(test_data_whimper_gnaw_intersection, len('whimper'), 0x541F00)
    result['dest'] = str(result['dest'])
    assert result == dict(
        deleted_relocs={2, 9, 17, 35},
        added_relocs=set(),
        dest='[68FF258h]',
        length=21,
        saved_mach=saved,
        nops={33: 6},
    )
