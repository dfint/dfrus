from disasm import disasm


def test_mov_al_1():
    s = str(next(disasm(bytes.fromhex('B0 01'))))
    assert s == 'mov al, 1'
