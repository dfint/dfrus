import pytest

from dfrus.disasm import disasm, analyse_modrm, ModRM, Sib, ModRmAnalysisResult, disassembler


@pytest.mark.parametrize('hex_data,disasm_str', [
    ('90', 'nop'),

    ('B0 01', 'mov al, 1'),
    ('66 B8 01', 'mov ax, 1'),
    ('B8 01', 'mov eax, 1'),
    ('66 A5', 'movsw'),
    ('6A FF', 'push 0xFFFFFFFF'),
    ('8b0c8dc0eed00a', 'mov ecx, [4*ecx+0xAD0EEC0]'),
    ('c605c2a3890101', 'mov byte [0x189A3C2], 1'),
    ('F3 A5', 'rep movsd'),
    ('0f4ff8', 'cmovg edi, eax'),
    ('8d 0c ff', 'lea ecx, [edi+8*edi]'),
    ('8b 0c 8d c0 ee d0 0a', 'mov ecx, [4*ecx+0xAD0EEC0]'),
    ('2b 0d e0 82 d6 0a', 'sub ecx, [0xAD682E0]'),
    ('8916', "mov [esi], edx"),
    ('8b157c3d5400', 'mov edx, [0x543D7C]'),
    ('894604', 'mov [esi+4], eax'),
    ('66a1803d5400', 'mov ax, [0x543D80]'),
    ('83c40c', 'add esp, 0xC'),
    ('895608', 'mov [esi+8], edx'),
    ('6689460c', 'mov [esi+0xC], ax'),
    ('83f90a', 'cmp ecx, 0xA'),

    ('C2 08 00', 'retn 8'),
    ('74 0E', 'je short 0x10'),
    ('FF 44 BC 10', 'inc dword [esp+4*edi+0x10]'),
    ('FE 44 BC 10', 'inc byte [esp+4*edi+0x10]'),
    ('8C 54 BC 10', 'mov [esp+4*edi+0x10], ss'),
    ('8E 54 BC 10', 'mov ss, [esp+4*edi+0x10]'),
    ('8F 44 BC 10', 'pop dword [esp+4*edi+0x10]'),
    ('66 8F 44 BC 10', 'pop word [esp+4*edi+0x10]'),
    ('05 FF FF 00 00', 'add eax, 0xFFFF'),
    ('D1 44 BC 10', 'rol dword [esp+4*edi+0x10], 1'),
    ('C1 44 BC 10 08', 'rol dword [esp+4*edi+0x10], 8'),
    ('D3 44 BC 10', 'rol dword [esp+4*edi+0x10], cl'),
    ('F7 5C BC 10', 'neg dword [esp+4*edi+0x10]'),
    ('F7 44 BC 10 FF 00 00 00', 'test dword [esp+4*edi+0x10], 0xFF'),
    ('0F 84 FA FF 00 00', 'je near 0x10000'),

    # MMX/SSE
    ('0f10 05 2cddeb00', 'movups xmm0, [0xEBDD2C]'),
    ('0f11 02', 'movups [edx], xmm0'),
    ('0f28 05 a021f400', 'movaps xmm0, [0xF421A0]'),
    ('0f6f 05 f017ec00', 'movq mm0, qword [0xEC17F0]'),
    ('0f6e 05 f017ec00', 'movd mm0, dword [0xEC17F0]'),
    ('0f7f 05 f017ec00', 'movq qword [0xEC17F0], mm0'),
    ('0f7e 05 f017ec00', 'movd dword [0xEC17F0], mm0'),
    ('f30f7e 05 f017ec00', 'movq xmm0, qword [0xEC17F0]'),
    ('660fd6 05 f017ec00', 'movq qword [0xEC17F0], xmm0'),
])
def test_disasm(hex_data, disasm_str):
    test_data = bytes.fromhex(hex_data)
    d = next(disasm(test_data))
    assert str(d) == disasm_str
    assert d.data == test_data


@pytest.mark.parametrize('hex_data,disasm_str', [
    ('90', 'nop'),

    ('B0 01', 'mov al, 1'),
    ('66 B8 01', 'mov ax, 1'),
    ('B8 01', 'mov eax, 1'),
    ('66 A5', 'movsw'),
    ('6A FF', 'push 0xFFFFFFFF'),
    ('8b0c8dc0eed00a', 'mov ecx, [4*ecx+0xAD0EEC0]'),
    ('c605c2a3890101', 'mov byte [0x189A3C2], 1'),
    ('F3 A5', 'rep movsd'),
    ('0f4ff8', 'cmovg edi, eax'),
    ('8d 0c ff', 'lea ecx, [edi+8*edi]'),
    ('8b 0c 8d c0 ee d0 0a', 'mov ecx, [4*ecx+0xAD0EEC0]'),
    ('2b 0d e0 82 d6 0a', 'sub ecx, [0xAD682E0]'),
    ('8916', "mov [esi], edx"),
    ('8b157c3d5400', 'mov edx, [0x543D7C]'),
    ('894604', 'mov [esi+4], eax'),
    ('66a1803d5400', 'mov ax, [0x543D80]'),
    ('83c40c', 'add esp, 0xC'),
    ('895608', 'mov [esi+8], edx'),
    ('6689460c', 'mov [esi+0xC], ax'),
    ('83f90a', 'cmp ecx, 0xA'),

    ('C2 08 00', 'retn 8'),
    ('74 0E', 'je short 0x10'),
    ('FF 44 BC 10', 'inc dword [esp+4*edi+0x10]'),
    ('FE 44 BC 10', 'inc byte [esp+4*edi+0x10]'),
    ('8C 54 BC 10', 'mov [esp+4*edi+0x10], ss'),
    ('8E 54 BC 10', 'mov ss, [esp+4*edi+0x10]'),
    ('8F 44 BC 10', 'pop dword [esp+4*edi+0x10]'),
    ('66 8F 44 BC 10', 'pop word [esp+4*edi+0x10]'),
    ('05 FF FF 00 00', 'add eax, 0xFFFF'),
    ('D1 44 BC 10', 'rol dword [esp+4*edi+0x10], 1'),
    ('C1 44 BC 10 08', 'rol dword [esp+4*edi+0x10], 8'),
    ('D3 44 BC 10', 'rol dword [esp+4*edi+0x10], cl'),
    ('F7 5C BC 10', 'neg dword [esp+4*edi+0x10]'),
    ('F7 44 BC 10 FF 00 00 00', 'test dword [esp+4*edi+0x10], 0xFF'),
    ('0F 84 FA FF 00 00', 'je near 0x10000'),

    # MMX/SSE
    ('0f10 05 2cddeb00', 'movups xmm0, [0xEBDD2C]'),
    ('0f11 02', 'movups [edx], xmm0'),
    ('0f28 05 a021f400', 'movaps xmm0, [0xF421A0]'),
    ('0f6f 05 f017ec00', 'movq mm0, qword [0xEC17F0]'),
    ('0f6e 05 f017ec00', 'movd mm0, dword [0xEC17F0]'),
    ('0f7f 05 f017ec00', 'movq qword [0xEC17F0], mm0'),
    ('0f7e 05 f017ec00', 'movd dword [0xEC17F0], mm0'),
    ('f30f7e 05 f017ec00', 'movq xmm0, qword [0xEC17F0]'),
    ('660fd6 05 f017ec00', 'movq qword [0xEC17F0], xmm0'),
])
def test_disassembler(hex_data, disasm_str):
    test_data = bytes.fromhex(hex_data)
    d = next(disassembler.disassemble(test_data))
    assert str(d) == disasm_str
    assert d.data == test_data


def test_analyse_modrm():
    data = bytes.fromhex('0c8dc0eed00a')
    assert (analyse_modrm(data, 0) == (
                ModRmAnalysisResult(
                    modrm=ModRM(mode=0, reg=1, regmem=4),
                    sib=Sib(scale=2, index_reg=1, base_reg=5),
                    disp=0x0AD0EEC0
                ),
                len(data)
    ))
