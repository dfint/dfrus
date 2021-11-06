from typing import Optional, Union

from .binio import to_signed, from_dword
from .disasm import DisasmLine, join_byte
from .machine_code_assembler import asm
from .opcodes import jmp_short, jmp_near, jcc_short, x0f_jcc_near, Cond, call_near, Reg, lea, mov_acc_mem, mov_rm_reg, \
    x0f_movups, Prefix
from .operand import ImmediateValueOperand


def create_disasm_line_for_jumps_calls(
        data: bytes,
        offset: int,
        size: int,
        mnemonic: str,
        displacement: int) -> DisasmLine:
    next_offset = offset + size
    return DisasmLine(next_offset, data[:size], mnemonic=mnemonic,
                      operands=(ImmediateValueOperand(next_offset + displacement),))


def match_jump(data: bytes, offset: int = 0) -> Optional[DisasmLine]:
    if data[0] == jmp_short:
        displacement = to_signed(data[1], width=8)
        size = 2
        mnemonic = "jmp short"
    elif data[0] == jmp_near:
        displacement = from_dword(data[1:5], signed=True)
        size = 5
        mnemonic = "jmp near"
    else:
        return None

    return create_disasm_line_for_jumps_calls(data, offset, size, mnemonic, displacement)


def match_jump_conditional_short(data: bytes, offset: int = 0) -> Optional[DisasmLine]:
    if data[0] & 0xF0 == jcc_short:
        displacement = to_signed(data[1], width=8)
        size = 2
        condition_code = data[0] & 0x0F
        mnemonic = f"j{Cond(condition_code).name} short"
        return create_disasm_line_for_jumps_calls(data, offset, size, mnemonic, displacement)


def match_jump_conditional_near(data: bytes, offset: int = 0) -> Optional[DisasmLine]:
    if data[0] == 0x0F and data[1] & 0xF0 == x0f_jcc_near:
        displacement = from_dword(data[2:6], signed=True)
        size = 6
        condition_code = data[1] & 0x0F
        mnemonic = f"j{Cond(condition_code).name} near"
        return create_disasm_line_for_jumps_calls(data, offset, size, mnemonic, displacement)


def match_call_near(data: bytes, offset: int = 0) -> Optional[DisasmLine]:
    if data[0] == call_near:
        displacement = from_dword(data[1:5], signed=True)
        size = 5
        mnemonic = "call near"
        return create_disasm_line_for_jumps_calls(data, offset, size, mnemonic, displacement)


def match_mov_reg_imm(b: bytes, reg: Reg, imm: int) -> Optional[int]:
    """
    Try to match given bytes against `mov reg1, imm` and return number of bytes the instruction occupies
    """
    instr = asm().mov_reg_imm(reg, imm).build()
    if b.startswith(instr):
        return len(instr)


def match_lea_reg_reg_disp(b: bytes, reg: Reg, disp: Optional[int] = None) -> Optional[int]:
    """
    Try to match given bytes against `lea reg1, [reg2+disp]` and return number of bytes the instruction occupies
    """
    if b[0] == lea and b[1] & 0xF8 == join_byte(1, reg, 0) and (not isinstance(disp, int) or b[2] == disp):
        return 3


def get_start(s):
    i = None
    if s[-1] & 0xfe == mov_acc_mem:
        i = 1
    elif s[-2] & 0xf8 == mov_rm_reg and s[-1] & 0xc7 == 0x05:
        i = 2
    elif s[-3] == 0x0f and s[-2] & 0xfe == x0f_movups and s[-1] & 0xc7 == 0x05:
        i = 3
        return i  # prefix is not allowed here

    assert i is not None

    if s[-1 - i] == Prefix.operand_size:
        i += 1

    return i
