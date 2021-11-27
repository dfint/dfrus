from dfrus.opcodes import Reg, RegType


def test_reg_new_parent():
    for item in Reg:
        if item.type != RegType.general or item.size == 4:
            assert item.parent is item
        elif item.size == 2:
            # eg. ebx is parent for bx
            assert str(item)[-2:] == str(item.parent)[-2:] and str(item.parent)[-3] == "e"
        elif item.size == 1:
            # eg. ebx is parent for bh and bl
            assert str(item)[-1] in "hl" and str(item)[-2] == str(item.parent)[-2] and str(item.parent)[-3] == "e"


def test_reg_new():
    size = 2
    assert Reg((RegType.general, 0, 1 << size)) is Reg.eax
