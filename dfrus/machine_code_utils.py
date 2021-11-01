from typing import Iterable

from .binio import to_dword, from_dword
from .disasm import join_byte, Operand
from .machine_code_builder import MachineCodeBuilder
from .opcodes import push_reg, Reg, xor_rm_reg, cmp_rm_imm, jcc_short, Cond, inc_reg, jmp_short, pop_reg, pushad, \
    mov_rm_reg, mov_reg_imm, Prefix, movsd, popad, mov_acc_mem, x0f_movups, lea

MAX_LEN = 0x100


def mach_strlen(code_chunk: Iterable[int]) -> bytes:
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
    m = MachineCodeBuilder()
    m.byte(push_reg | Reg.ecx.code)  # push ecx
    m.byte(xor_rm_reg | 1).byte(join_byte(3, Reg.ecx, Reg.ecx))  # xor ecx, ecx
    m.label("@@")
    m.byte(cmp_rm_imm).byte(join_byte(0, 7, 4)).byte(join_byte(0, Reg.ecx, Reg.eax)).byte(0x00)  # cmp byte [eax+ecx], 0
    m.byte(jcc_short | Cond.z).relative_reference("success", size=1)  # jz success
    m.byte(cmp_rm_imm | 1).byte(join_byte(3, 7, Reg.ecx)).dword(MAX_LEN)  # cmp ecx, MAX_LEN
    m.byte(jcc_short | Cond.g).relative_reference("skip", size=1)  # jg skip
    m.byte(inc_reg | Reg.ecx.code)  # inc ecx
    m.byte(jmp_short).relative_reference("@@", size=1)  # jmp @b
    m.label("success")
    m.bytes(code_chunk)
    m.label("skip")
    m.byte(pop_reg | Reg.ecx.code)  # pop ecx
    return m.build()


def mach_memcpy(src, dest: Operand, count):
    mach = bytearray()
    mach.append(pushad)  # pushad
    new_references = set()
    assert dest.index_reg is None
    # If the destination address is not in edi yet, put it there
    if dest.base_reg != Reg.edi or dest.disp != 0:
        if dest.disp == 0:
            # mov edi, reg
            mach += bytes((mov_rm_reg | 1, join_byte(3, dest.base_reg, Reg.edi)))
        elif dest.base_reg is None:
            # mov edi, imm32
            mach.append(mov_reg_imm | 8 | Reg.edi.code)  # mov edi, ...
            new_references.add(len(mach))
            mach += to_dword(dest.disp)  # imm32
        else:
            # lea edi, [reg+imm]
            mach += mach_lea(Reg.edi, dest)

    mach.append(mov_reg_imm | 8 | Reg.esi.code)  # mov esi, ...
    new_references.add(len(mach))
    mach += to_dword(src)  # imm32

    mach += bytes((xor_rm_reg | 1, join_byte(3, Reg.ecx, Reg.ecx)))  # xor ecx, ecx
    mach += bytes((mov_reg_imm | Reg.cl.code, (count + 3) // 4))  # mov cl, (count+3)//4

    mach += bytes((Prefix.rep, movsd))  # rep movsd

    mach.append(popad)  # popad

    return mach, new_references


def match_mov_reg_imm32(b, reg, imm):
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


def mach_lea(dest, src: Operand):
    mach = bytearray()
    mach.append(lea)
    assert src.index_reg is None, 'mach_lea(): right operand with index register not implemented'

    if src.disp == 0 and src.base_reg != Reg.ebp:
        mode = 0
    elif -0x80 <= src.disp < 0x80:
        mode = 1
    else:
        mode = 2

    if src.base_reg == Reg.esp:
        mach.append(join_byte(mode, dest, 4))  # mod r/m byte
        mach.append(join_byte(0, 4, src.base_reg))  # sib byte
    else:
        mach.append(join_byte(mode, dest, src.base_reg))  # just mod r/m byte

    if mode == 1:
        mach += src.disp.to_bytes(1, byteorder='little', signed=True)
    else:
        mach += src.disp.to_bytes(4, byteorder='little', signed=True)
    return mach
