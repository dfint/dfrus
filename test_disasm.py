from disasm import disasm


def test_mov_al_1():
    assert str(next(disasm(bytes.fromhex('B0 01')))) == 'mov al, 1'
    assert str(next(disasm(bytes.fromhex('66 B8 01')))) == 'mov ax, 1'
    assert str(next(disasm(bytes.fromhex('B8 01')))) == 'mov eax, 1'


def test_movsw():
    data = bytes.fromhex('66 A5')  # movsw
    assert next(disasm(data)).data == data
