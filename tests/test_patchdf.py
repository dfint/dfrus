import pytest
from dataclasses import asdict

from dfrus.disasm import disasm
from dfrus.opcodes import *
from dfrus.patchdf import get_length, mach_memcpy, get_start, match_mov_reg_imm32, get_fix_for_moves, Metadata


def convert_test_data_from_copypaste(s: str):
    test_data = bytes()

    for line in s.strip().splitlines():
        line = line.split()
        test_data += bytes.fromhex(line[1])

    return test_data


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
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={2, 9},
        added_relocs=set(),
        dest='[esp+0x20]',
        length=21,
        saved_mach=b'\x8b\xf0',  # mov esi, eax
        nops=dict(),
        pokes=dict(),
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
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={2, 7, 13, 30},
        added_relocs=set(),
        dest='[ecx]',
        length=40,
        saved_mach=bytes.fromhex('8D 8D 90 FB FF FF'),  # lea ecx, [ebp-470h] ; push ecx
        nops={41: 6, 47: 6},
        pokes=dict(),
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
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={2, 7, 13, 19, 25, 30, 36, 42, 48},
        added_relocs={2},
        dest='[0x617990]',
        length=52,
        saved_mach=bytes.fromhex('2B 0D E0 82 D6 0A '),  # sub ecx, [0ad682e0h]
        nops=dict(),
        pokes=dict()
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
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={1, 8, 14, 19, 26, 32},
        added_relocs=set(),
        dest='[0xAE19178]',
        length=36,
        saved_mach=bytes(),
        nops=dict(),
        pokes=dict()
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
    )
    result = get_length(test_data_nausea, len('nausea'))
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={3, 45, 52, 59, 65, 72},
        added_relocs=set(),
        dest='[0x62BC5C]',
        length=12,
        saved_mach=saved,
        nops={43: 6, 50: 6, 56: 7, 63: 6, 69: 7},
        pokes=dict(),
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
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={2, 9, 17, 35},
        added_relocs=set(),
        dest='[0x68FF258]',
        length=21,
        saved_mach=saved,
        nops={33: 6},
        pokes=dict(),
    )


test_data_tanning_tan_intersection = bytes.fromhex(
    '8B 0D B8 AB 55 00'  # mov ecx, [strz_Tanning_55abb8]
    'A1 AC 91 CA 0A'  # mov eax, [?data_aca91ac]
    '8B 15 BC AB 55 00'  # mov edx, [strz_ing_55abbc]
    '83 C4 0C'  # add esp, 0ch
    '56'  # push esi
    '6A 05'  # push 5
    '6A 40'  # push 40h
    '68 C0 AB 55 00'  # push strz_tan_55abc0
    '68 C4 AB 55 00'  # push strz_Select_a_skin_to_tan_55abc4
    '50'  # push eax
    '89 8C 24 40 0D 00 00'  # mov [esp+0d40h], ecx
    '8B 0D CC 7A CA 0A'  # mov ecx, [?data_aca7acc]
    '51'  # push ecx
    '6A FF'  # push 0ffffffffh
    '6A 02'  # push 2
    '89 94 24 50 0D 00 00'  # mov [esp+0d50h], edx
    '89 35 18 96 E1 0A'  # mov [?data_ae19618], esi
)


def test_get_length_tanning_tan_intersection():
    saved = bytes()
    result = get_length(test_data_tanning_tan_intersection, len('Tanning'), 0x55ABB8)
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={2, 13},
        added_relocs=set(),
        dest='[esp+0xD40]',
        length=6,
        saved_mach=saved,
        nops={11: 6, 36: 7, 54: 7},
        pokes=dict(),
    )


test_data_stimulant = bytes.fromhex(
    '8b155c645400'                  # mov         edx, [0054645c] ; "stim"
    'b90a000000'                    # mov         ecx, 0xa
    'be34645400'                    # mov         esi, 00546434
    'bf56de6200'                    # mov         edi, 0062de56
    'f3a5'                          # repz movsd
    '8b0d60645400'                  # mov         ecx, [00546460] ; "ulan"
    '891527c96200'                  # mov         [0062c927], edx
    '0fb71564645400'                # movzx       edx, word ptr [00546464] ; "t\0"
    '890d2bc96200'                  # mov         [0062c92b], ecx
    '6689152fc96200'                # mov         [0062c92f], dx
    '8b1588645400'                  # mov         edx, [00546488]
)


def test_get_length_stimulant():
    saved = bytes.fromhex('B9 0A 00 00 00')  # mov ecx, 0Ah
    result = get_length(test_data_stimulant, len('stimulant'), 0x54645c)
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={2, 25, 31, 38, 44, 51},
        added_relocs=set(),
        dest='[0x62C927]',
        length=11,
        saved_mach=saved,
        nops={23: 6, 29: 6, 35: 7, 42: 6, 48: 7},
        pokes=dict(),
    )


def test_mach_memcpy_stimulant():
    result = get_length(test_data_stimulant, len('stimulant'), 0x54645c)
    dest = result.dest
    string_addr = 0x123456
    newlen = len('стимулятор')
    count = newlen + 1
    mach = mach_memcpy(string_addr, dest, newlen + 1)
    assert [str(line) for line in disasm(mach.build())] == [
        'pushad',
        'mov edi, 0x%X' % dest.disp,
        'mov esi, 0x%X' % string_addr,
        'xor ecx, ecx',
        'mov cl, %d' % ((count+3)//4),
        'rep movsd',
        'popad',
    ]
    assert set(mach.absolute_references) == {2, 7}


test_data_linen_apron = bytes.fromhex(
    '8b0d180b5500'                  # mov         ecx, [00550b18]
    '8b151c0b5500'                  # mov         edx, [00550b1c]
    'a1200b5500'                    # mov         eax, [00550b20]
    '890dc92d7006'                  # mov         [06702dc9], ecx
    '8915cd2d7006'                  # mov         [06702dcd], edx
    'bac02d7006'                    # mov         edx, 06702dc0
    'b918065500'                    # mov         ecx, 00550618
    'c6051a2e700653'                # mov         byte ptr [06702e1a], 0x53
    'a3d12d7006'                    # mov         [06702dd1], eax
    '90'
)


def test_get_length_linen_apron():
    result = get_length(test_data_linen_apron, len('Linen apron'), 0x550b18)
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={2, 8, 13, 19, 25, 47},
        added_relocs=set(),
        dest='[0x6702DC9]',
        length=29,
        saved_mach=bytes(),
        nops={46: 5},
        pokes=dict(),
    )


test_data_smoked = bytes.fromhex(
    '8b15605b5400'                  # mov         edx, [00545b60]
    'a1645b5400'                    # mov         eax, [00545b64]
    '668b0d685b5400'                # mov         cx, [00545b68]
    '893dcca38901'                  # mov         [0189a3cc], edi
    '33ff'                          # xor         edi, edi
    '891d8ca38901'                  # mov         [0189a38c], ebx
    '893dc4a38901'                  # mov         [0189a3c4], edi
    'c605c2a3890101'                # mov         byte ptr [0189a3c2], 0x1
    '89351ca38901'                  # mov         [0189a31c], esi
    'c60524a3890164'                # mov         byte ptr [0189a324], 0x64
    '891525a38901'                  # mov         [0189a325], edx
    'a329a38901'                    # mov         [0189a329], eax
    '66890d2da38901'                # mov         [0189a32d], cx
    '90'
)


def test_get_length_smoked():
    result = get_length(test_data_smoked, len('smoked %s'), 0x545B60)
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={2, 7, 14, 60, 65, 72},
        added_relocs=set(),
        dest='[0x189A325]',
        length=18,
        saved_mach=bytes(),
        nops={58: 6, 64: 5, 69: 7},
        pokes=dict(),
    )


test_data_mild_low_pressure = bytes.fromhex(
    '8b3580ac5700'                  # mov         esi, [0057ac80]
    '8935beaae10a'                  # mov         [0ae1aabe], esi
    '8b3584ac5700'                  # mov         esi, [0057ac84]
    '881d34aae10a'                  # mov         [0ae1aa34], bl
    '0fb61d6cac5700'                # movzx       ebx, byte ptr [0057ac6c]
    '8935c2aae10a'                  # mov         [0ae1aac2], esi
    '8b3588ac5700'                  # mov         esi, [0057ac88]
    '881d51aae10a'                  # mov         [0ae1aa51], bl
    '0fb61d7eac5700'                # movzx       ebx, byte ptr [0057ac7e]
    '8935c6aae10a'                  # mov         [0ae1aac6], esi
    '8b358cac5700'                  # mov         esi, [0057ac8c]
    '890dd8a9e10a'                  # mov         [0ae1a9d8], ecx
    '0fb70d3cac5700'                # movzx       ecx, word ptr [0057ac3c]
    '8935caaae10a'                  # mov         [0ae1aaca], esi
    '0fb73590ac5700'                # movzx       esi, word ptr [0057ac90]
    'a3d4a9e10a'                    # mov         [0ae1a9d4], eax
    'a138ac5700'                    # mov         eax, [0057ac38]
    '8915dca9e10a'                  # mov         [0ae1a9dc], edx
    '8a153eac5700'                  # mov         dl, [0057ac3e]
    '881d9daae10a'                  # mov         [0ae1aa9d], bl
    'b314'                          # mov         bl, 0x14
    '66890de4a9e10a'                # mov         [0ae1a9e4], cx
    'a3e0a9e10a'                    # mov         [0ae1a9e0], eax
    '8815e6a9e10a'                  # mov         [0ae1a9e6], dl
    'c705f4a9e10a02050001'          # mov         dword ptr [0ae1a9f4], 01000502
    '66c705f8a9e10a0302'            # mov         word ptr [0ae1a9f8], 0x203
    'c7051baae10a03060103'          # mov         dword ptr [0ae1aa1b], 03010603
    'b10a'                          # mov         cl, 0xa
    '66c7051faae10a0a14'            # mov         word ptr [0ae1aa1f], 0x140a
    'c70542aae10a03060204'          # mov         dword ptr [0ae1aa42], 04020603
    '66c70546aae10a0a1e'            # mov         word ptr [0ae1aa46], 0x1e0a
    'c60548aae10a00'                # mov         byte ptr [0ae1aa48], 0x0
    'c70569aae10a03060304'          # mov         dword ptr [0ae1aa69], 04030603
    '66c7056daae10a083c'            # mov         word ptr [0ae1aa6d], 0x3c08
    'c6056faae10a08'                # mov         byte ptr [0ae1aa6f], 0x8
    'c70590aae10a02040604'          # mov         dword ptr [0ae1aa90], 04060402
    '66c70594aae10a0a50'            # mov         word ptr [0ae1aa94], 0x500a
    'c60596aae10a0c'                # mov         byte ptr [0ae1aa96], 0xc
    'c705b7aae10a01020a0a'          # mov         dword ptr [0ae1aab7], 0a0a0201
    '66c705bbaae10a1450'            # mov         word ptr [0ae1aabb], 0x5014
    '881dbdaae10a'                  # mov         [0ae1aabd], bl
    '668935ceaae10a'                # mov         [0ae1aace], si
    '90'
)


def test_get_length_mild_low_pressure():
    result = get_length(test_data_mild_low_pressure, len('mild low pressure'), 0x57AC80)
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={2, 8, 14, 33, 39, 58, 64, 83, 90, 288},
        added_relocs=set(),
        dest='[0xAE1AABE]',
        length=18,
        saved_mach=bytes(),
        nops={31: 6, 37: 6, 56: 6, 62: 6, 81: 6, 87: 7, 285: 7},
        pokes=dict(),
    )


test_data_tribesman = bytes.fromhex(
    '8b15743d5400'                  # mov         edx, [00543d74]
    'a1783d5400'                    # mov         eax, [00543d78]
    '8d0cff'                        # lea         ecx, [edi*9]
    '8b0c8dc0eed00a'                # mov         ecx, [ecx*4+0ad0eec0]
    '2b0de082d60a'                  # sub         ecx, [0ad682e0]
    '8916'                          # mov         [esi], edx
    '8b157c3d5400'                  # mov         edx, [00543d7c]
    '894604'                        # mov         [esi+0x4], eax
    '66a1803d5400'                  # mov         ax, [00543d80]
    '83c40c'                        # add         esp, 0xc
    '895608'                        # mov         [esi+0x8], edx
    '6689460c'                      # mov         [esi+0xc], ax
    '83f90a'                        # cmp         ecx, 0xa
    '7d44'                          # jnl         0x1329f
)


def test_get_length_tribesman():
    saved = bytes.fromhex(
        '8d 0c ff'                  # lea         ecx, [edi*9]
        '8b 0c 8d c0 ee d0 0a'      # mov         ecx, [ecx*4+0ad0eec0]
        '2b 0d e0 82 d6 0a'         # sub         ecx, [0ad682e0]
    )
    result = get_length(test_data_tribesman, len('for some time'), 0x543d74)
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={2, 7, 17, 23, 31, 40},
        added_relocs={6, 12},
        dest='[esi]',
        length=44,
        saved_mach=saved,
        nops={47: 3, 50: 4},
        pokes=dict()
    )


test_data_tribesman_peasant_intersection = bytes.fromhex(
    '66a1e4bf5400'                   # mov         ax, [0054bfe4]
    '8b0ddcbf5400'                   # mov         ecx, [0054bfdc]
    '8b15e0bf5400'                   # mov         edx, [0054bfe0]
    '66894598'                       # mov         [ebp-00000068], ax
    'eb0c'                           # jmp         skip
    '8b0dd02b5500'                   # mov         ecx, [00552bd0]
    '8b15d42b5500'                   # mov         edx, [00552bd4]
                                     # skip:
    '895594'                         # mov         [ebp-0000006c], edx
    '894d90'                         # mov         [ebp-00000070], ecx
    '8d4590'                         # lea         eax, [ebp-00000070]
)


def test_get_length_tribesman_peasant_intersection():
    result = get_length(test_data_tribesman_peasant_intersection, len('tribesman'), 0x54bfdc)
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        deleted_relocs={2, 8, 14},
        added_relocs=set(),
        dest='[ebp-0x70]',
        length=22,
        saved_mach=bytes(),
        pokes={23: 0x0C+6},
        nops=dict(),
    )


test_data_has_arrived = bytes.fromhex(
    'a1 002ff100'                     # mov         eax, [00f12f00]  ; +4
    
    '0f2805 a021f400'                 # movaps      xmm0, [00f421a0]  ; address doesn't belong to the string
    
    '8901'                            # mov         [ecx], eax  ; -4
    'a1 042ff100'                     # mov         eax, [00f12f04]  ; +4
    '894104'                          # mov         [ecx+0x4], eax  ; -4
    'a1 082ff100'                     # mov         eax, [00f12f08]  ; +4
    '894108'                          # mov         [ecx+0x8], eax  ; -4
    '66a1 0c2ff100'                   # mov         ax, [00f12f0c]  ; +2
    '6689410c'                        # mov         [ecx+0xc], ax  ; -2 - in total 14 bytes copied
)


def test_get_length_has_arrived():
    result = get_length(test_data_has_arrived, len(' has arrived.'), 0x00F12F00)
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        length=5,
        dest='[ecx]',
        nops={12: 2, 14: 5, 19: 3, 22: 5, 27: 3, 30: 6, 36: 4},
        deleted_relocs={1, 15, 23, 32},
        saved_mach=bytes(),
        added_relocs=set(),
        pokes=dict(),
    )


test_data_select_item = bytes.fromhex(
    '0f100544f9ea00'                 # movups      xmm0, [00eaf944]
    '0f11832c050000'                 # movups      [ebx+0x52c], xmm0
)


def test_get_length_select_item():
    result = get_length(test_data_select_item, len('  Select Item: '), 0x00EAF944)
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        length=len(test_data_select_item),
        deleted_relocs={3},
        dest='[ebx+0x52C]',
        saved_mach=bytes(),
        added_relocs=set(),
        pokes=dict(),
        nops=dict(),
    )


test_data_dnwwap = bytes.fromhex(
    '0f100544ddeb00'                 # movups      xmm0, [00ebdd44] ; +16
    '8d9610010000'                   # lea         edx, [esi+0x110] ; saved
    '8bca'                           # mov         ecx, edx ; saved
    '0f1102'                         # movups      [edx], xmm0 ; -16
    '0f100554ddeb00'                 # movups      xmm0, [00ebdd54] ; +16
    '0f114210'                       # movups      [edx+0x10], xmm0 ; -16
    'f30f7e0564ddeb00'               # movq        xmm0, [00ebdd64] ; +8
    '660fd64220'                     # movq        [edx+0x20], xmm0 ; -8
    '66a16cddeb00'                   # mov         ax, [00ebdd6c] ; +2
    '66894228'                       # mov         [edx+0x28], ax ; -2
)


def test_dnwwap():
    result = get_length(test_data_dnwwap, len('Design New World with Advanced Parameters'), 0x0EBDD44)
    result.dest = str(result.dest)
    assert asdict(result) == dict(
        length=len(test_data_dnwwap),
        dest='[edx]',
        deleted_relocs={3, 21, 33, 44},
        saved_mach=bytes.fromhex('8d9610010000 8bca'),
        added_relocs=set(),
        nops=dict(),
        pokes=dict()
    )


@pytest.mark.parametrize("test_data,expected", [
    ([nop, mov_acc_mem], 1),
    ([Prefix.operand_size, mov_acc_mem], 2),
    ([nop, mov_rm_reg, 0x05], 2),
    ([Prefix.operand_size, mov_rm_reg, 0x05], 3),
    (bytes.fromhex('0f 10 05'), 3),  # movups xmm0, [...]
])
def test_get_start(test_data, expected):
    assert get_start(test_data) == expected


def test_match_mov_reg_imm32():
    assert match_mov_reg_imm32(b'\xb9\x0a\x00\x00\x00', Reg.ecx.code, 0x0a)


test_data_create_new_world = bytes.fromhex(
    "8b 0d b8 a8 f2 00    "  # mov    ecx,DWORD PTR ds:0xf2a8b8
    "89 8b 10 01 00 00    "  # mov    DWORD PTR [ebx+0x110],ecx
    "8b 15 bc a8 f2 00    "  # mov    edx,DWORD PTR ds:0xf2a8bc
    "89 93 14 01 00 00    "  # mov    DWORD PTR [ebx+0x114],edx
    "a1 c0 a8 f2 00       "  # mov    eax,ds:0xf2a8c0
    "89 83 18 01 00 00    "  # mov    DWORD PTR [ebx+0x118],eax
    "8b 0d c4 a8 f2 00    "  # mov    ecx,DWORD PTR ds:0xf2a8c4
    "89 8b 1c 01 00 00    "  # mov    DWORD PTR [ebx+0x11c],ecx
    "66 8b 15 c8 a8 f2 00 "  # mov    dx,WORD PTR ds:0xf2a8c8
    "8d 8b 10 01 00 00    "  # lea    ecx,[ebx+0x110]
    "66 89 93 20 01 00 00 "  # mov    WORD PTR [ebx+0x120],dx
    # end
    "8d 51 01             "  # lea    edx,[ecx+0x1]
    "8a 01                "  # mov    al,BYTE PTR [ecx]
    "41                   "  # inc    ecx
    "84 c0                "  # test   al,al
)


def test_create_new_world():
    original_string_address = 0xf2a8b8
    result = get_length(test_data_create_new_world, len("Create New World!"), original_string_address)
    result_dict = asdict(result)
    result_dict['dest'] = str(result.dest)
    new_len = len("Создать новый мир!")

    assert result_dict == dict(
        length=67,
        dest='[ecx]',  # [ebx+0x110]
        deleted_relocs={2, 14, 25, 37, 50},
        saved_mach=bytes.fromhex("8d 8b 10 01 00 00"),  # lea    ecx,[ebx+0x110]
        added_relocs=set(),
        nops=dict(),
        pokes=dict()
    )

    meta = Metadata()
    fix = get_fix_for_moves(result, new_len, original_string_address, meta)
    assert len(fix.pokes[0]) == result.length
