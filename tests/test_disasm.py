from dfrus.disasm import disasm, analyse_modrm, ModRM, Sib


def test_mov_al_1():
    assert str(next(disasm(bytes.fromhex('B0 01')))) == 'mov al, 1'
    assert str(next(disasm(bytes.fromhex('66 B8 01')))) == 'mov ax, 1'
    assert str(next(disasm(bytes.fromhex('B8 01')))) == 'mov eax, 1'


def test_movsw():
    data = bytes.fromhex('66 A5')  # movsw
    assert next(disasm(data)).data == data


def test_push_ff():
    assert str(next(disasm(bytes.fromhex('6A FF')))) == 'push 0FFFFFFFFh'


def test_mov_4ecx_imm():
    data = bytes.fromhex('8b0c8dc0eed00a')
    d = next(disasm(data))
    assert str(d) == 'mov ecx, [4*ecx+0AD0EEC0h]'
    assert d.data == data


def test_movups():
    data = bytes.fromhex('0f 10 05 2c dd eb 00')
    d = next(disasm(data))
    assert str(d) == 'movups xmm0, [0EBDD2Ch]'
    data = bytes.fromhex('0f 11 02')
    d = next(disasm(data))
    assert str(d) == 'movups [edx], xmm0'


def test_analyse_modrm():
    data = bytes.fromhex('0c8dc0eed00a')
    assert (analyse_modrm(data, 0) ==
            (dict(modrm=ModRM(mode=0, reg=1, regmem=4),
                  sib=Sib(scale=2, index_reg=1, base_reg=5),
                  disp=0x0AD0EEC0),
             len(data)))


def test_mov_byte_addr_0x1():
    data = bytes.fromhex('c605c2a3890101')
    d = next(disasm(data))
    assert str(d) == 'mov byte [189A3C2h], 1'
    assert d.data == data
