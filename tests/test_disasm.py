from disasm import disasm, analyse_modrm


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
