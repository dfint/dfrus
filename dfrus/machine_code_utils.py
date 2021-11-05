from typing import Union

from .binio import from_dword
from .machine_code_assembler import MachineCodeAssembler
from .machine_code_builder import MachineCodeBuilder
from .opcodes import *
from .operand import MemoryReference, RelativeMemoryReference, AbsoluteMemoryReference

MAX_LEN = 0x100


def mach_strlen(code_chunk: Union[bytes, MachineCodeBuilder]) -> MachineCodeBuilder:
    """
        push ecx
        xor ecx, ecx
    @@:
        cmp byte [eax+ecx], 0  ; assume that eax contains a string address
        jz success
        cmp ecx, 100h
        jg skip
        inc ecx
        jmp @b
    success:
        <code_chunk>
    skip:
        pop ecx
    """
    m = MachineCodeAssembler()
    m.push_reg(Reg.ecx)  # push ecx
    m.byte(xor_rm_reg | 1).modrm(3, Reg.ecx, Reg.ecx)  # xor ecx, ecx
    m.label("@@")
    m.byte(cmp_rm_imm).modrm(0, 7, 4).sib(0, Reg.ecx, Reg.eax).byte(0x00)  # cmp byte [eax+ecx], 0
    m.jump_conditional_short(Cond.z, "success")  # jz success
    m.byte(cmp_rm_imm | 1).modrm(3, 7, Reg.ecx).dword(MAX_LEN)  # cmp ecx, MAX_LEN
    m.jump_conditional_short(Cond.g, "skip")  # jg skip
    m.byte(inc_reg | Reg.ecx.code)  # inc ecx
    m.jump_short("@@")  # jmp @b
    m.label("success")
    m += code_chunk
    m.label("skip")
    m.pop_reg(Reg.ecx)  # pop ecx
    return m


def mach_memcpy(src: int, dest: MemoryReference, count) -> MachineCodeAssembler:
    # dest != [reg1 + scale*reg2 + disp]
    assert not (isinstance(dest, RelativeMemoryReference) and dest.index_reg is not None)

    m = MachineCodeAssembler()

    m.byte(pushad)  # pushad

    # If the destination address is not in edi yet, put it there
    if isinstance(dest, AbsoluteMemoryReference):
        m.mov_reg_imm(Reg.edi, dest.disp, True)  # mov edi, imm32
    elif dest.base_reg != Reg.edi or dest.disp != 0:
        if dest.disp == 0:
            assert dest.base_reg is not None
            m.mov_reg_reg32(Reg.edi, dest.base_reg)  # mov edi, reg
        elif dest.base_reg is None:
            m.mov_reg_imm(Reg.edi, dest.disp, True)  # mov edi, imm32
        else:
            m.lea(Reg.edi, dest)  # lea edi, [reg+imm]

    m.mov_reg_imm(Reg.esi, src, True)  # mov esi, imm32
    m.byte(xor_rm_reg | 1).modrm(3, Reg.ecx.code, Reg.ecx.code)  # xor ecx, ecx
    m.mov_reg_imm(Reg.cl, (count + 3) // 4)  # mov cl, (count+3)//4
    m.byte(Prefix.rep).byte(movsd)  # rep movsd
    m.byte(popad)  # popad
    return m


def match_mov_reg_imm32(b: bytes, reg: Reg, imm: int) -> bool:
    assert len(b) == 5, b
    return b[0] == mov_reg_imm | 8 | int(reg) and from_dword(b[1:]) == imm


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
