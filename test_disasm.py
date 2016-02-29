from disasm import disasm


def test_mov_al_1():
    s = str(next(disasm(bytes.fromhex('B0 01'))))
    assert s == 'mov al, 1'


def test_movsw():
    data = bytes.fromhex('66 A5')  # movsw
    assert next(disasm(data)).data == data
