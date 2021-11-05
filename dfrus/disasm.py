from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from enum import auto
from typing import Optional, Tuple, Iterator

from .binio import to_signed
from .opcodes import *


def align(n, edge=4):
    return (n+edge-1) & (-edge)


def split_byte(x):
    """Split byte into groups of bits: (2 bits, 3 bits, 3 bits)"""
    return x >> 6, x >> 3 & 7, x & 7


def join_byte(*parts):
    s = 0
    for x in parts:
        s <<= 3
        s |= int(x)
    return s


@dataclass(frozen=True)
class ModRM:
    mode: int
    reg: int
    regmem: int

    @classmethod
    def split(cls, x):
        return cls(*split_byte(x))
    
    def __int__(self):
        return join_byte(self.mode, self.reg, self.regmem)

    def __index__(self):
        return int(self)


@dataclass(frozen=True)
class Sib:
    scale: int
    index_reg: int
    base_reg: int
    
    @classmethod
    def split(cls, x):
        return cls(*split_byte(x))
    
    def __int__(self):
        return join_byte(self.scale, self.index_reg, self.base_reg)

    def __index__(self):
        return int(self)


@dataclass(frozen=True)
class ModRmAnalysisResult:
    modrm: ModRM
    sib: Optional[Sib]
    disp: Optional[int]

    def as_dict(self):
        return {key: value for key, value in asdict(self).items() if value is not None}


def analyse_modrm(s: bytes, i: int) -> Tuple[ModRmAnalysisResult, int]:
    modrm = ModRM.split(s[i])

    i += 1

    sib = None
    disp = None

    if modrm.mode != 3:
        # Not register addressing
        if modrm.mode == 0 and modrm.regmem == 5:
            # Direct addressing: [imm32]
            imm32 = int.from_bytes(s[i:i+4], byteorder='little')
            disp = imm32
            i += 4
        else:
            # Indirect addressing
            if modrm.regmem == 4:
                # Indirect addressing with scale
                sib = Sib.split(s[i])
                i += 1

            if modrm.mode == 1:
                disp = to_signed(s[i], 8)
                i += 1
            elif modrm.mode == 2:
                disp = int.from_bytes(s[i:i+4], byteorder='little', signed=True)
                i += 4
            elif sib and sib.base_reg == Reg.ebp.code:
                disp = int.from_bytes(s[i:i+4], byteorder='little', signed=True)
                i += 4

    return ModRmAnalysisResult(modrm, sib, disp), i


regs = (
    ("al", "ax", "eax"),
    ("cl", "cx", "ecx"),
    ("dl", "dx", "edx"),
    ("bl", "bx", "ebx"),
    ("ah", "sp", "esp"),
    ("ch", "bp", "ebp"),
    ("dh", "si", "esi"),
    ("bh", "di", "edi"),
)

seg_regs = ("es", "cs", "ss", "ds", "fs", "gs")
seg_prefixes = {Prefix.seg_es: Reg.es, Prefix.seg_cs: Reg.cs, Prefix.seg_ss: Reg.ss, Prefix.seg_ds: Reg.ds,
                Prefix.seg_fs: Reg.fs, Prefix.seg_gs: Reg.gs}


op_sizes = {1: "byte", 2: "word", 4: "dword", 8: "qword", 16: "dqword"}


class OperandType(Enum):
    immediate_value = auto()
    general_purpose_register = auto()
    xmm_register = auto()
    segment_register = auto()
    absolute_memory_reference = auto()
    relative_memory_reference = auto()
    unknown = auto()


class Operand(ABC):
    @abstractmethod
    def get_type(self) -> OperandType:
        return OperandType.unknown

    def get_data_size(self) -> Optional[int]:
        raise NotImplementedError()

    def set_data_size(self, value: Optional[int]):
        raise NotImplementedError()

    @property
    def data_size(self) -> Optional[int]:
        return self.get_data_size()

    @data_size.setter
    def data_size(self, value: Optional[int]):
        self.set_data_size(value)


@dataclass
class ImmediateValueOperand(Operand):
    value: int

    def get_type(self) -> OperandType:
        return OperandType.immediate_value

    def __str__(self):
        if self.value >= 0:
            return asmhex(self.value)
        else:
            return '-' + asmhex(-self.value)


@dataclass
class RegisterOperand(Operand):
    reg: Reg

    def get_type(self) -> OperandType:
        if self.reg.type == RegType.general:
            return OperandType.general_purpose_register
        elif self.reg.type == RegType.xmm:
            return OperandType.xmm_register
        elif self.reg.type == RegType.segment:
            return OperandType.segment_register
        else:
            raise ValueError("Unknown register type")

    def get_data_size(self) -> Optional[int]:
        return self.reg.size

    def set_data_size(self, new_size):
        assert new_size is None or 1 <= new_size

        if self.reg is not None:
            assert self.reg.type == RegType.general, 'Do not change non-general register size explicitly'
            self.reg = Reg((RegType.general, self.reg.code, new_size))

    def __str__(self):
        return self.reg.name


@dataclass
class RelativeMemoryReference(Operand):
    base_reg: Optional[Reg] = None
    index_reg: Optional[Reg] = None
    seg_prefix: Optional[Reg] = None
    scale: Optional[int] = None
    disp: int = 0
    _data_size: Optional[int] = None

    def get_type(self) -> OperandType:
        return OperandType.relative_memory_reference

    def get_data_size(self) -> Optional[int]:
        return self._data_size

    def set_data_size(self, value: Optional[int]):
        self._data_size = value

    def __str__(self):
        if self.base_reg is None and self.index_reg is None:
            result = asmhex(self.disp)
        else:
            result = ""
            if self.base_reg is not None:
                result = self.base_reg.name
                if self.index_reg is not None:
                    result += "+"

            if self.index_reg is not None:
                if self.scale:
                    result += "%d*" % (1 << self.scale)

                result += self.index_reg.name

            if self.disp or not result:
                if self.disp >= 0:
                    if not result:
                        result += asmhex(self.disp)
                    else:
                        result += '+' + asmhex(self.disp)
                else:
                    result += '-' + asmhex(-self.disp)

        if self.seg_prefix is None:
            result = "[%s]" % result
        else:
            result = "%s:[%s]" % (seg_regs[int(self.seg_prefix)], result)

        data_size = self.get_data_size()
        if data_size is not None:
            result = op_sizes[data_size] + ' ' + result

        return result


@dataclass
class AbsoluteMemoryReference(Operand):
    disp: int
    seg_prefix: Optional[Reg] = None
    _data_size: Optional[int] = None

    def get_type(self) -> OperandType:
        return OperandType.absolute_memory_reference

    def get_data_size(self) -> Optional[int]:
        return self._data_size

    def set_data_size(self, value: Optional[int]):
        self._data_size = value

    def __str__(self):
        result = asmhex(self.disp)

        if self.seg_prefix is None:
            result = "[%s]" % result
        else:
            result = "%s:[%s]" % (seg_regs[int(self.seg_prefix)], result)

        data_size = self.get_data_size()
        if data_size is not None:
            result = op_sizes[data_size] + ' ' + result

        return result


# @dataclass
# class Operand:
#     value: Optional[int] = None
#     reg: Optional[Reg] = None
#     base_reg: Optional[Reg] = None
#     index_reg: Optional[Reg] = None
#     seg_prefix: Optional[Reg] = None
#     scale: Optional[int] = None
#     disp: int = 0
#     _data_size: Optional[int] = None
#
#     def __post_init__(self):
#         assert self.reg is None or isinstance(self.reg, Reg)
#         assert self.base_reg is None or isinstance(self.base_reg, Reg)
#         assert(self._data_size is None or 0 <= self._data_size <= 2)
#         assert self.index_reg is None or isinstance(self.index_reg, Reg)
#         if self.reg is not None:
#             self._data_size = self.reg.size
#
#     def get_type(self) -> OperandType:
#         if self.value is not None:
#             return OperandType.immediate_value
#         elif self.reg is not None:
#             if self.reg.type == RegType.general:
#                 return OperandType.general_purpose_register
#             elif self.reg.type == RegType.xmm:
#                 return OperandType.xmm_register
#             elif self.reg.type == RegType.segment:
#                 return OperandType.segment_register
#         elif self.base_reg is None and self.index_reg is None:
#             return OperandType.absolute_memory_reference
#         else:
#             return OperandType.relative_memory_reference
#
#         return OperandType.unknown
#
#     @property
#     def data_size(self):
#         return self._data_size
#
#     @data_size.setter
#     def data_size(self, new_size):
#         assert new_size is None or 1 <= new_size
#
#         if self.reg is not None:
#             assert self.reg.type == RegType.general, 'Do not change non-general register size explicitly'
#             self.reg = Reg((RegType.general, self.reg.code, new_size))
#
#         self._data_size = new_size
#
#     def __str__(self):
#         if self.value is not None:
#             if self.value >= 0:
#                 return asmhex(self.value)
#             else:
#                 return '-' + asmhex(-self.value)
#         elif self.reg is not None:
#             return self.reg.name
#         else:
#             if self.base_reg is None and self.index_reg is None:
#                 result = asmhex(self.disp)
#             else:
#                 result = ""
#                 if self.base_reg is not None:
#                     result = self.base_reg.name
#                     if self.index_reg is not None:
#                         result += "+"
#
#                 if self.index_reg is not None:
#                     if self.scale:
#                         result += "%d*" % (1 << self.scale)
#
#                     result += self.index_reg.name
#
#                 if self.disp or not result:
#                     if self.disp >= 0:
#                         if not result:
#                             result += asmhex(self.disp)
#                         else:
#                             result += '+' + asmhex(self.disp)
#                     else:
#                         result += '-' + asmhex(-self.disp)
#
#             if self.seg_prefix is None:
#                 result = "[%s]" % result
#             else:
#                 result = "%s:[%s]" % (seg_regs[int(self.seg_prefix)], result)
#
#             if self.data_size is not None:
#                 result = op_sizes[self.data_size] + ' ' + result
#
#             return result
#
#     def __repr__(self):
#         args_list = [
#             ('0x{:x}', 'value'), ('{}', 'reg'), ('{}', 'base_reg'), ('{}', 'index_reg'), ('{}', 'scale'),
#             ('0x{:x}', 'disp'), ('{}', 'data_size'), ('{!r}', 'seg_prefix')
#         ]
#         return 'Operand({})'.format(', '.join(('{}=' + fmt).format(argname, getattr(self, argname))
#                                               for fmt, argname in args_list if getattr(self, argname) is not None))
#
#     def __int__(self):
#         if (self.value is None or self.reg is not None or
#                 self.base_reg is not None or self.index_reg is not None):
#             raise ValueError('Failed to represent Operand as integer: %s' % self)
#         return self.value


def create_operand1_from_modrm(analisys_result: ModRmAnalysisResult, size=4) -> Operand:
    return RegisterOperand(Reg((RegType.general, analisys_result.modrm.reg, size)))


def create_operand2_from_modrm_or_sib(analysis_result: ModRmAnalysisResult) -> Operand:
    modrm = analysis_result.modrm

    if modrm.mode == 3:
        # Register addressing
        return RegisterOperand(Reg((RegType.general, modrm.regmem, 4)))
    elif modrm.mode == 0 and modrm.regmem == 5:
        # Direct addressing
        assert analysis_result.disp is not None
        return RelativeMemoryReference(disp=analysis_result.disp)
    elif modrm.regmem != 4:
        # Without SIB-byte
        op = RelativeMemoryReference(base_reg=Reg((RegType.general, modrm.regmem, 4)))
    else:
        # With SIB
        sib = analysis_result.sib

        assert sib is not None
        base_reg = sib.base_reg if not (sib.base_reg == Reg.ebp.code and modrm.mode == 0) else None
        index_reg = sib.index_reg if sib.index_reg != 4 else None

        op = RelativeMemoryReference(scale=sib.scale,
                                     index_reg=None if index_reg is None else Reg((RegType.general, index_reg, 4)),
                                     base_reg=None if base_reg is None else Reg((RegType.general, base_reg, 4)))

    op.disp = analysis_result.disp or 0

    return op


def create_operands_from_modrm_or_sib(x: ModRmAnalysisResult, size=4) -> Tuple[Operand, Operand]:
    op1 = create_operand1_from_modrm(x, size)
    op2 = create_operand2_from_modrm_or_sib(x)
    return op1, op2


def process_operands(x: ModRmAnalysisResult) -> Tuple[Reg, int]:
    op = create_operand2_from_modrm_or_sib(x)
    assert isinstance(op, RelativeMemoryReference)
    if op.base_reg is not None:
        base_reg = op.base_reg
    else:
        assert op.index_reg is not None
        base_reg = op.index_reg
    disp = op.disp
    return base_reg, disp


def analyse_mach(s):
    i = 0
    while True:
        j = i
        if s[i] == Prefix.operand_size:
            i += 1
        op = s[i]
        data = s[j:i+1]
        result = dict(data=data)
        i += 1
        if op & 0xfe == mov_acc_mem:
            result.update(reg=Reg.eax, imm=int.from_bytes(s[i:i+4], byteorder='little'))
            i += 4
        elif op & 0xfc == mov_rm_reg or op == lea:
            modrm, i = analyse_modrm(s, i)
            result.update(modrm.as_dict())
        else:
            break

        yield result, j


op_1byte_nomask_noargs = {
    nop: "nop", ret_near: "retn", pushfd: "pushfd", pushad: "pushad", popfd: "popfd",
    popad: "popad", leave: "leave", int3: "int3",
    cdq: "cdq", movsb: "movsb", movsd: "movsd",
}
op_nomask = {call_near: "call near", jmp_near: "jmp near", jmp_short: "jmp short"}
op_FE_width_REG_RM = {test_rm_reg: "test", xchg_rm_reg: "xchg"}
op_FC_dir_width_REG_RM = {mov_rm_reg: "mov", add_rm_reg: "add", sub_rm_reg: "sub", or_rm_reg: "or", and_rm_reg: "and",
                          xor_rm_reg: "xor", cmp_rm_reg: "cmp", adc_rm_reg: "adc", sbb_rm_reg: "sbb"}
op_F8_reg = {push_reg: 'push', pop_reg: 'pop', inc_reg: 'inc', dec_reg: 'dec'}
op_FE_width_acc_imm = {add_acc_imm: 'add', sub_acc_imm: 'sub', or_acc_imm: 'or', and_acc_imm: 'or', xor_acc_imm: 'xor',
                       cmp_acc_imm: 'cmp', test_acc_imm: 'test', adc_acc_imm: 'adc', sbb_acc_imm: 'sbb'}
op_shifts_rolls = ("rol", "ror", "rcl", "rcr", "shl", "shr", "sal", "sar")


def asmhex(n):
    assert(n >= 0)
    if n < 0xA:
        return str(n)
    else:
        return '0x{:X}'.format(n)


@dataclass(repr=False)
class DisasmLine:
    address: int
    data: bytes
    mnemonic: str
    operands: Optional[Tuple[Operand, ...]] = None
    prefix: Optional[Prefix] = None

    def __str__(self):
        if not self.operands:
            text = self.mnemonic
        else:
            text = self.mnemonic + ' ' + ', '.join(str(item) for item in self.operands)

        if self.prefix is not None:
            text = self.prefix.name + ' ' + text
        
        return text

    def __repr__(self):
        return 'DisasmLine(0x{self.address:x}, {self.data!r}, {self.mnemonic!r}, {self.operands})'.format(self=self)


class BytesLine(DisasmLine):
    def __init__(self, address, data):
        super().__init__(address, data, mnemonic='db', operands=tuple(ImmediateValueOperand(n) for n in data))


def disasm(s: bytes, start_address=0) -> Iterator[DisasmLine]:
    s = bytes(s)
    i = 0
    while i < len(s):
        j = i
        size_prefix = False
        seg_prefix = None
        rep_prefix = None
        line = None
        if s[i] in seg_prefixes:
            seg_prefix = seg_prefixes[Prefix(s[i])]
            i += 1

        if s[i] == Prefix.operand_size:
            size_prefix = True
            i += 1

        if s[i] in {Prefix.rep.value, Prefix.repne.value, Prefix.lock.value}:
            rep_prefix = Prefix(s[i])
            i += 1

        if s[i] in op_1byte_nomask_noargs:
            mnemonic = op_1byte_nomask_noargs[s[i]]
            if i > j:  # Are there any prefixes?
                if size_prefix and mnemonic == 'movsd':
                    mnemonic = 'movsw'
                elif rep_prefix is None:
                    yield BytesLine(start_address+j, data=s[j:i])
                    j = i
            line = DisasmLine(start_address+j, data=s[j:i+1], mnemonic=mnemonic, prefix=rep_prefix, operands=None)
            i += 1
        elif s[i] == ret_near_n:
            if i > j:
                yield BytesLine(start_address+j, data=s[j:i])
                j = i
            i += 1
            immediate = int.from_bytes(bytes(s[i:i+2]), byteorder='little')
            i += 2
            line = DisasmLine(start_address+j, data=s[j:i], mnemonic='retn',
                              operands=(ImmediateValueOperand(immediate),), prefix=rep_prefix)
        elif s[i] in {call_near, jmp_near}:
            if i > j:
                yield BytesLine(start_address+j, data=s[j:i])
                j = i
            i += 1
            immediate = start_address+i+4+int.from_bytes(s[i:i+4], byteorder='little', signed=True)
            i += 4
            line = DisasmLine(start_address+j, data=s[j:i], mnemonic=op_nomask[s[j]],
                              operands=(ImmediateValueOperand(immediate),), prefix=rep_prefix)
        elif s[i] == jmp_short or s[i] & 0xF0 == jcc_short:
            if i > j:
                yield BytesLine(start_address+j, data=s[j:i])
                j = i
            immediate = start_address+i+2+to_signed(s[i+1], 8)
            if s[i] == jmp_short:
                mnemonic = "jmp short"
            else:
                mnemonic = 'j%s short' % Cond(s[i] & 0x0F).name
            line = DisasmLine(start_address+j, data=s[i:i+2], mnemonic=mnemonic,
                              operands=(ImmediateValueOperand(immediate),), prefix=rep_prefix)
            i += 2
        elif s[i] == lea:
            if i > j:
                yield BytesLine(start_address+j, data=s[j:i])
                j = i
            analysis_result, i = analyse_modrm(s, i+1)
            operands = create_operands_from_modrm_or_sib(analysis_result, size=4)
            line = DisasmLine(start_address+j, data=s[j:i], mnemonic='lea', operands=operands, prefix=rep_prefix)

        elif (s[i] & 0xFC) == op_rm_imm and (s[i] & 3) != 2:
            flags = s[i] & 3
            mnemonics = ["add", "or", "adc", "sbb", "and", "sub", "xor", "cmp"]
            analysis_result, i = analyse_modrm(s, i+1)
            mnemonic = mnemonics[analysis_result.modrm.reg]
            operand1 = create_operand2_from_modrm_or_sib(analysis_result)

            if not isinstance(operand1, RegisterOperand):
                operand1.data_size = 1 << (2*bool(flags)-size_prefix)

            if flags == 1:
                immediate = int.from_bytes(s[i:i+4], byteorder='little')
                i += 4
            else:  # flags == 0 or flags == 3
                immediate = s[i]
                i += 1

            operand2 = ImmediateValueOperand(immediate)
            line = DisasmLine(start_address+j,
                              data=s[j:i],
                              mnemonic=mnemonic,
                              operands=(operand1, operand2),
                              prefix=rep_prefix)

        elif (s[i] & 0xFE) in op_FE_width_REG_RM or (s[i] & 0xFE == mov_rm_imm and (s[i+1] & 0x38) == 0):
            # Operation between register and register/memory without direction flag (xchg or test)
            # or move immediate value to memory
            si = s[i]
            mnemonic = op_FE_width_REG_RM.get(si & 0xFE, 'mov')
            flag_size = si & 1
            analysis_result, i = analyse_modrm(s, i+1)
            operand = create_operand2_from_modrm_or_sib(analysis_result)
            if (si & 0xFE) == mov_rm_imm:
                operand.data_size = 1 << (flag_size*2-size_prefix)
                imm_size = operand.data_size
                immediate_operand = ImmediateValueOperand(int.from_bytes(s[i:i + imm_size], byteorder='little'))
                i += imm_size
                line = DisasmLine(start_address+j, data=s[j:i], mnemonic=mnemonic,
                                  operands=(operand, immediate_operand), prefix=rep_prefix)
            else:
                size = 1 << (flag_size*2-size_prefix)
                operand1 = create_operand1_from_modrm(analysis_result, size)
                line = DisasmLine(start_address+j, data=s[j:i], mnemonic=mnemonic,
                                  operands=(operand1, operand), prefix=rep_prefix)

        elif (s[i] & 0xFC) in op_FC_dir_width_REG_RM:
            # Operation between a register and register/memory with direction flag
            mnemonic = op_FC_dir_width_REG_RM[s[i] & 0xFC]
            dir_flag = s[i] & 2
            flag_size = s[i] & 1
            analysis_result, i = analyse_modrm(s, i+1)
            operand1, operand2 = create_operands_from_modrm_or_sib(analysis_result)
            size = 1 << (flag_size*2-size_prefix)
            operand1.data_size = size
            if isinstance(operand2, RegisterOperand):
                operand2.set_data_size(size)
            if seg_prefix is not None:  # redundant check
                operand2.seg_prefix = seg_prefix
            if not dir_flag:
                operand1, operand2 = operand2, operand1
            line = DisasmLine(start_address+j,
                              data=s[j:i],
                              mnemonic=mnemonic,
                              operands=(operand1, operand2),
                              prefix=rep_prefix)

        elif s[i] & 0xF8 in op_F8_reg:
            mnemonic = op_F8_reg[s[i] & 0xF8]
            reg = s[i] & 7
            size = 2 - size_prefix
            operand = RegisterOperand(Reg((RegType.general, reg, 1 << size)))
            i += 1
            line = DisasmLine(start_address+j, data=s[j:i], mnemonic=mnemonic, operands=(operand,), prefix=rep_prefix)
        elif s[i] & 0xFE == 0xFE:
            flag_size = s[i] & 1
            i += 1
            op = (s[i] & 0x38) >> 3
            if op != 7:
                analysis_result, i = analyse_modrm(s, i)
                mnemonics = ["inc", "dec", "call", "call far", "jmp dword", "jmp far", "push dword"]
                mnemonic = mnemonics[op]
                operand1 = create_operand2_from_modrm_or_sib(analysis_result)
                if op < 2:
                    size = flag_size*2-size_prefix
                    operand1.data_size = 1 << size
                    line = DisasmLine(start_address+j, data=s[j:i], mnemonic=mnemonic,
                                      operands=(operand1,), prefix=rep_prefix)
                elif flag_size:
                    if seg_prefix:
                        operand1.seg_prefix = seg_prefix
                    line = DisasmLine(start_address+j, data=s[j:i], mnemonic=mnemonic,
                                      operands=(operand1,), prefix=rep_prefix)
        elif s[i] & 0xFC == mov_acc_mem:
            dir_flag = s[i] & 2
            size_flag = s[i] & 1
            size = size_flag*2 - size_prefix
            i += 1
            imm_size = 4  # 4 bytes in 32-bit mode
            immediate = int.from_bytes(s[i:i+imm_size], byteorder='little')
            i += imm_size
            operand1 = RegisterOperand(Reg((RegType.general, Reg.eax.code, 1 << size)))
            operand = AbsoluteMemoryReference(immediate)
            if seg_prefix:
                operand.seg_prefix = seg_prefix
            if dir_flag:
                operand1, operand = operand, operand1
            line = DisasmLine(start_address+j,
                              data=s[j:i],
                              mnemonic='mov',
                              operands=(operand1, operand),
                              prefix=rep_prefix)

        elif s[i] & 0xFD == mov_rm_seg:
            dir_flag = s[i] & 2
            analysis_result, i = analyse_modrm(s, i+1)

            operand1 = RegisterOperand(Reg.segment(analysis_result.modrm.reg))
            operand2: Operand = create_operand2_from_modrm_or_sib(analysis_result)

            if not dir_flag:
                operand1, operand2 = operand2, operand1
            line = DisasmLine(start_address+j,
                              data=s[j:i],
                              mnemonic='mov',
                              operands=(operand1, operand2),
                              prefix=rep_prefix)

        elif s[i] == pop_rm:
            analysis_result, i = analyse_modrm(s, i+1)
            operand = create_operand2_from_modrm_or_sib(analysis_result)
            operand.data_size = 1 << (2-size_prefix)
            line = DisasmLine(start_address+j, data=s[j:i], mnemonic='pop', operands=(operand,), prefix=rep_prefix)
        elif s[i] & 0xFD == push_imm32:
            size_flag = s[i] & 2
            i += 1
            if size_flag:
                immediate = s[i] | (s[i] >> 7) * 0xFFFFFF00  # 6A FF -> push 0FFFFFFFFh
                i += 1
            else:
                immediate = int.from_bytes(s[i:i+4], byteorder='little')
                i += 4
            line = DisasmLine(start_address+j, data=s[j:i], mnemonic='push',
                              operands=(ImmediateValueOperand(immediate),), prefix=rep_prefix)
        elif s[i] & 0xFE in op_FE_width_acc_imm:
            mnemonic = op_FE_width_acc_imm[s[i] & 0xFE]
            flag_size = s[i] & 1
            i += 1
            size = flag_size*2 - size_prefix
            imm_size = 1 << size
            immediate = int.from_bytes(s[i:i+imm_size], byteorder='little')
            i += imm_size
            operand1 = RegisterOperand(Reg((RegType.general, Reg.eax.code, 1 << size)))
            operand2 = ImmediateValueOperand(immediate)
            line = DisasmLine(start_address+j,
                              data=s[j:i],
                              mnemonic=mnemonic,
                              operands=(operand1, operand2),
                              prefix=rep_prefix)

        elif s[i] & 0xF0 == mov_reg_imm:
            flag_size = (s[i] & 8) >> 3
            reg = s[i] & 7
            i += 1
            size = flag_size*2 - size_prefix
            imm_size = 1 << size
            immediate = int.from_bytes(s[i:i+imm_size], byteorder='little')
            i += imm_size
            operand1 = RegisterOperand(Reg((RegType.general, reg, 1 << size)))
            operand2 = ImmediateValueOperand(immediate)
            line = DisasmLine(start_address+j,
                              data=s[j:i],
                              mnemonic='mov',
                              operands=(operand1, operand2),
                              prefix=rep_prefix)

        elif s[i] & 0xFE in {shift_op_rm_1, shift_op_rm_cl, shift_op_rm_imm8}:
            opcode = s[i] & 0xFE
            flag_size = s[i] & 1
            analysis_result, i = analyse_modrm(s, i+1)
            mnemonic = op_shifts_rolls[analysis_result.modrm.reg]
            operand1 = create_operand2_from_modrm_or_sib(analysis_result)
            operand1.data_size = 1 << (flag_size*2 - size_prefix)
            if opcode == shift_op_rm_1:
                operand = ImmediateValueOperand(value=1)
            elif opcode == shift_op_rm_cl:
                operand = RegisterOperand(Reg.cl)
            else:
                immediate = s[i]
                i += 1
                operand = ImmediateValueOperand(immediate)
            line = DisasmLine(start_address+j,
                              data=s[j:i],
                              mnemonic=mnemonic,
                              operands=(operand1, operand),
                              prefix=rep_prefix)

        elif s[i] & 0xFE == test_or_unary_rm:
            flag_size = s[i] & 1
            analysis_result, i = analyse_modrm(s, i+1)
            modrm1 = analysis_result.modrm.reg
            if modrm1 != 1:
                operand1 = create_operand2_from_modrm_or_sib(analysis_result)
                size = flag_size*2 - size_prefix
                operand1.data_size = 1 << size
                if modrm1 >= 2:
                    # unary operations: not, neg, mul, imul etc.
                    mnemonics = ["not", "neg", "mul", "imul", "div", "idiv"]
                    mnemonic = mnemonics[modrm1-2]
                    line = DisasmLine(start_address+j, data=s[j:i], mnemonic=mnemonic,
                                      operands=(operand1,), prefix=rep_prefix)
                elif modrm1 == 0:
                    # test r/m, imm
                    imm_size = 1 << size
                    immediate = int.from_bytes(s[i:i+imm_size], byteorder='little')
                    i += imm_size
                    operand = ImmediateValueOperand(immediate)
                    line = DisasmLine(start_address+j, data=s[j:i], mnemonic='test',
                                      operands=(operand1, operand), prefix=rep_prefix)
        elif s[i] == 0x0F:
            i += 1
            if s[i] & 0xF0 == x0f_setcc and s[i+1] & 0xC0 == 0xC0:
                condition = s[i] & 0x0F
                mnemonic = "set%s" % Cond(condition).name
                reg_op = RegisterOperand(Reg((RegType.general, s[i+1] & 7, 1)))
                i += 2
                line = DisasmLine(start_address+j,
                                  data=s[j:i],
                                  mnemonic=mnemonic,
                                  operands=(reg_op,),
                                  prefix=rep_prefix)

            elif s[i] & 0xF0 == x0f_jcc_near:
                condition = s[i] & 0x0F
                mnemonic = "j%s near" % Cond(condition).name
                i += 1
                immediate = start_address+i+4+int.from_bytes(s[i:i+4], byteorder='little', signed=True)
                i += 4
                line = DisasmLine(start_address+j,
                                  data=s[j:i],
                                  mnemonic=mnemonic,
                                  operands=(ImmediateValueOperand(immediate),),
                                  prefix=rep_prefix)

            elif s[i] & 0xFE in {x0f_movzx, x0f_movsx}:
                op = s[i] & 0xFE
                mnemonic = 'movzx' if op == x0f_movzx else 'movsx'
                flag_size = s[i] & 1
                analysis_result, i = analyse_modrm(s, i+1)
                size = 1 << (flag_size + 1)
                dest, src = create_operands_from_modrm_or_sib(analysis_result, size)
                src.data_size = 1 << flag_size
                line = DisasmLine(start_address+j, data=s[j:i], mnemonic=mnemonic,
                                  operands=(dest, src), prefix=rep_prefix)

            elif s[i] & 0xFE in {x0f_movups, x0f_movaps}:
                op = s[i] & 0xFE
                mnemonic = 'movups' if op == x0f_movups else 'movaps'
                dir_flag = s[i] & 1
                analysis_result, i = analyse_modrm(s, i+1)
                operand2 = create_operand2_from_modrm_or_sib(analysis_result)
                operand1 = RegisterOperand(Reg.xmm(analysis_result.modrm.reg))
                if dir_flag:
                    operand1, operand2 = operand2, operand1
                line = DisasmLine(start_address+j,
                                  data=s[j:i],
                                  mnemonic=mnemonic,
                                  operands=(operand1, operand2),
                                  prefix=rep_prefix)

            elif s[i] & 0xEE == x0f_movd_mm:
                opcode = s[i]
                size_flag = s[i] & 0x01
                dir_flag = s[i] & 0x10
                mnemonic = 'movq' if size_flag else 'movd'
                analysis_result, i = analyse_modrm(s, i + 1)
                operand1_code = analysis_result.modrm.reg
                operand2 = create_operand2_from_modrm_or_sib(analysis_result)

                if rep_prefix is Prefix.rep and opcode == x0f_movd_mm | 0x10:
                    mnemonic = 'movq'
                    operand1 = RegisterOperand(Reg.xmm(operand1_code))
                    rep_prefix = None
                    operand2.data_size = 8  # qword
                else:
                    operand2.data_size = 4 << size_flag
                    operand1 = RegisterOperand(Reg.mm(operand1_code))
                    if dir_flag:
                        operand1, operand2 = operand2, operand1

                line = DisasmLine(start_address+j,
                                  data=s[j:i],
                                  mnemonic=mnemonic,
                                  operands=(operand1, operand2),
                                  prefix=rep_prefix)

            elif s[i] == x0f_movq_rm_xmm and size_prefix:
                mnemonic = 'movq'
                analysis_result, i = analyse_modrm(s, i + 1)
                operand1 = RegisterOperand(Reg.xmm(analysis_result.modrm.reg))
                operand2 = create_operand2_from_modrm_or_sib(analysis_result)
                operand2.data_size = 8  # qword
                operand1, operand2 = operand2, operand1
                line = DisasmLine(start_address+j, data=s[j:i], mnemonic=mnemonic,
                                  operands=(operand1, operand2), prefix=rep_prefix)

            elif s[i] & 0xF0 == x0f_cmov:
                condition = s[i] & 0x0F
                mnemonic = 'cmov' + Cond(condition).name
                size = 4 >> size_prefix
                analysis_result, i = analyse_modrm(s, i + 1)
                operand1 = create_operand1_from_modrm(analysis_result, size)
                operand2 = create_operand2_from_modrm_or_sib(analysis_result)
                line = DisasmLine(start_address+j, data=s[j:i], mnemonic=mnemonic,
                                  operands=(operand1, operand2), prefix=rep_prefix)

        if not line:
            i += 1
            line = BytesLine(start_address+j, data=s[j:i])

        yield line


def _main(argv):
    if len(argv) < 2:
        pass
    else:
        with open(argv[1], "r+b") as fn:
            pe = PortableExecutable(fn)
            image_base = pe.optional_header.image_base
            sections = pe.section_table
            entry_point = pe.optional_header.address_of_entry_point
            entry_point_offset = sections.rva_to_offset(entry_point)
            fn.seek(entry_point_offset)
            mach = fn.read(0x500)
            prev_addr = None
            prev_size = None
            print('Entry point: 0x%x\n' % (image_base+entry_point))
            for disasm_line in disasm(mach, image_base+entry_point):
                assert(prev_addr is None or disasm_line.address-prev_addr == prev_size)
                prev_addr = disasm_line.address
                prev_size = len(disasm_line.data)
                print("%08x\t%s" % (disasm_line.address, disasm_line))
                if disasm_line.mnemonic == 'db':
                    break


if __name__ == "__main__":
    import sys
    from .peclasses import PortableExecutable
    _main(sys.argv)
