from .binio import from_dword
from .opcodes import Prefix, Reg, mov_acc_mem, mov_reg_imm, mov_rm_reg, x0f_movups


def match_mov_reg_imm32(b: bytes, reg: Reg, imm: int) -> bool:
    assert len(b) == 5, b
    return b[0] == mov_reg_imm | 8 | int(reg) and from_dword(b[1:]) == imm


def get_start(s):
    i = None
    if s[-1] & 0xFE == mov_acc_mem:
        i = 1
    elif s[-2] & 0xF8 == mov_rm_reg and s[-1] & 0xC7 == 0x05:
        i = 2
    elif s[-3] == 0x0F and s[-2] & 0xFE == x0f_movups and s[-1] & 0xC7 == 0x05:
        i = 3
        return i  # prefix is not allowed here

    assert i is not None

    if s[-1 - i] == Prefix.operand_size:
        i += 1

    return i
