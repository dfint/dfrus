import pytest

from dfrus.disasm import disasm, analyse_modrm, ModRM, Sib


@pytest.mark.parametrize('hex_data,disasm_str', [
    ('B0 01', 'mov al, 1'),
    ('66 B8 01', 'mov ax, 1'),
    ('B8 01', 'mov eax, 1'),
    ('66 A5', 'movsw'),
    ('6A FF', 'push 0FFFFFFFFh'),
    ('8b0c8dc0eed00a', 'mov ecx, [4*ecx+0AD0EEC0h]'),
    ('0f 10 05 2c dd eb 00', 'movups xmm0, [0EBDD2Ch]'),
    ('0f 11 02', 'movups [edx], xmm0'),
    ('c605c2a3890101', 'mov byte [189A3C2h], 1')
])
def test_disasm(hex_data, disasm_str):
    test_data = bytes.fromhex(hex_data)
    d = next(disasm(test_data))
    assert str(d) == disasm_str
    assert d.data == test_data


def test_analyse_modrm():
    data = bytes.fromhex('0c8dc0eed00a')
    assert (analyse_modrm(data, 0) ==
            (dict(modrm=ModRM(mode=0, reg=1, regmem=4),
                  sib=Sib(scale=2, index_reg=1, base_reg=5),
                  disp=0x0AD0EEC0),
             len(data)))
