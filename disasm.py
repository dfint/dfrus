
from opcodes import *


def align(n, edge=4):
    return (n+edge-1) & (-edge)


def signed(x, w):
    pow2w = 2**w
    assert(x < pow2w)
    if x & (pow2w//2):
        x -= pow2w
    return x


def split_byte(x):
    """Split byte into groups of bits: (2 bits, 3 bits, 3 bits)"""
    return x >> 6, x >> 3 & 7, x & 7


def analyse_modrm(s, i):
    result = dict()

    modrm = split_byte(s[i])
    result['modrm'] = modrm

    i += 1

    if modrm[0] != 3:
        # Not register addressing
        if modrm[0] == 0 and modrm[2] == 5:
            # Direct addressing: [imm32]
            imm32 = int.from_bytes(s[i:i+4], byteorder='little')
            result['disp'] = imm32
            i += 4
        else:
            # Indirect addressing
            if modrm[2] == 4:
                # Indirect addressing with scale
                sib = split_byte(s[i])
                result['sib'] = sib
                i += 1

            if modrm[0] == 1:
                disp = signed(s[i], 8)
                result['disp'] = disp
                i += 1
            elif modrm[0] == 2:
                disp = signed(int.from_bytes(s[i:i+4], byteorder='little'), 32)
                result['disp'] = disp
                i += 4

    return result, i


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

op_sizes = ("byte", "word", "dword")


class Operand:
    def __init__(self, value=None, reg=None, base_reg=None, index_reg=None, scale=0, disp=0, data_size=2, seg_reg=None):
        self.value = value
        self.reg = reg
        self.base_reg = base_reg
        self.data_size = data_size
        self.index_reg = index_reg
        self.scale = scale
        self.disp = disp
        self.seg_reg = seg_reg

    def __repr__(self):
        if self.value is not None:
            return asmhex(self.value)
        elif self.reg is not None:
            return regs[self.reg][self.data_size]
        else:
            if self.base_reg is None and self.index_reg is None:
                result = '[%s]' % asmhex(self.disp)
            else:
                result = ""
                if self.base_reg is not None:
                    result = regs[self.reg][2]  # Currently only 32-bit addressing supported
                    if self.index_reg is not None:
                        result += " + "

                if self.index_reg is not None:
                    if self.scale > 0:
                        result += "%d*" % (1 << self.scale)

                    result += regs[self.reg][2]

                if self.disp != 0 or not result:
                    if not result:
                        if self.disp >= 0:
                            result = asmhex(self.disp)
                        else:
                            result = '-' + asmhex(-self.disp)
                    else:
                        if self.disp > 0:
                            result += ' + ' + asmhex(self.disp)
                        else:
                            result += ' - ' + asmhex(-self.disp)

            if self.seg_reg is None:
                return "%s [%s]" % (op_sizes[self.data_size], result)
            else:
                return "%s %s:[%s]" % (seg_regs[self.seg_reg], op_sizes[self.data_size], result)


def unify_operands(s):
    modrm = s['modrm']
    op1 = Operand(reg=modrm[1])
    if modrm[0] == 3:
        # Register addressing
        op2 = Operand(reg=modrm[2])
    else:
        if modrm[0] == 0 and modrm[2] == 5:
            # Direct addressing
            op2 = Operand(disp=s['disp'])
        else:
            if modrm[2] != 4:
                # Without SIB-byte
                op2 = Operand(scale=0, index_reg=modrm[2])
            else:
                # Use the SIB, Luke
                sib = s['sib']
                if sib[1] == 4:
                    # Don't use index register
                    op2 = Operand(scale=sib[0], base_reg=[2])
                else:
                    op2 = Operand(scale=sib[0], index_reg=sib[1], base_reg=[2])

            if modrm[0] > 0:
                op2.disp = s['disp']

    return op1, op2


seg_prefixes = {Prefix.seg_cs: "cs", Prefix.seg_ds: "ds", Prefix.seg_es: "es", Prefix.seg_ss: "ss", Prefix.seg_fs: "fs",
                Prefix.seg_gs: "gs"}

op_1byte_nomask_noargs = {nop: "nop", ret_near: "retn", pushfd: "pushfd", pushad: "pushad", popfd: "popfd",
                          popad: "popad", leave: "leave", int3: "int3"}
op_nomask = {call_near: "call near", jmp_near: "jmp near", jmp_short: "jmp short"}

conditions = ("o", "no", "b", "nb", "z", "nz", "na", "a", "s", "ns", "p", "np", "l", "nl", "ng", "g")


def asmhex(n):
    assert(n >= 0)
    if n < 0xA:
        return str(n)
    else:
        h = ('%02xh' % n).upper()
        if 'A' <= h[0] <= 'F':
            h = '0' + 'h'
        return h


class DisasmLine:
    __slots__ = ('address', 'data', 'mnemonic', 'operands')

    def __init__(self, address, data, mnemonic, operands=None):
        self.address = address
        self.data = data
        self.mnemonic = mnemonic
        self.operands = operands

    def __repr__(self):
        if not self.operands:
            return self.mnemonic
        else:
            return self.mnemonic + ' ' + ', '.join(self.operands)


class BytesLine(DisasmLine):
    def __init__(self, address, data):
        super().__init__(address, data, mnemonic='db', operands=[Operand(value=n) for n in data])


def disasm(s, start_address=0):
    i = 0
    while i < len(s):
        j = i
        size_prefix = False
        seg_prefix = ""
        line = None
        if s[i] in seg_prefixes:
            seg_reg = seg_prefixes[s[i]]
            i += 1

        if s[i] == Prefix.operand_size:
            size_prefix = True
            i += 1

        if s[i] in op_1byte_nomask_noargs:
            if i > j:  # Are there any prefixes?
                yield BytesLine(start_address+j, data=s[j:i])
            line = DisasmLine(start_address+i, data=s[i], mnemonic=op_1byte_nomask_noargs[s[i]])
            i += 1
        elif s[i] == ret_near_n:
            if i > j:
                yield BytesLine(start_address+j, data=s[j:i])
            immediate = int.from_bytes(bytes(s[i+1:i+2]), byteorder='little')
            line = DisasmLine(start_address+i, data=s[i:i+4], mnemonic='retn', operands=[Operand(value=immediate)])
            i += 3
        elif s[i] in {call_near, jmp_near}:
            if len(s) < i+4:
                line = BytesLine(start_address+j, data=s[j:])
            else:
                if i > j:
                    yield BytesLine(start_address+j, data=s[j:i])
                j = i
                i += 5
                immediate = start_address+i+signed(int.from_bytes(s[j+1:i], byteorder='little'), 32)
                line = DisasmLine(start_address+i, data=s[j:i], mnemonic=op_nomask[s[i]],
                                  operands=[Operand(value=immediate)])
        elif s[i] == jmp_short or s[i] & 0xF0 == jcc_short:
            if len(s) < i+1:
                line = BytesLine(start_address+j, data=s[j:])
            else:
                if i > j:
                    yield BytesLine(start_address+j, data=s[j:i])
                immediate = start_address+i+2+signed(s[i+1], 8)
                if s[i] == jmp_short:
                    mnemonic = "jmp short"
                else:
                    mnemonic = 'j%s short' % conditions[s[i] & 0x0F]
                line = DisasmLine(start_address+i, data=s[i:i+2], mnemonic=mnemonic, operands=[Operand(value=immediate)])
                i += 2
        elif s[i] == lea:
            if i > j:
                yield BytesLine(start_address+j, data=s[j:i])
            j = i
            x, i = analyse_modrm(s, i)
            operands = unify_operands(x)
            line = DisasmLine(start_address+i, data=s[j:i], mnemonic='lea', operands=operands)
        elif (s[i] & 0xFC) == op_rm_imm and (s[i] & 3) != 2:
            flags = s[i] & 3
            mnemonics = ("add", "or", "adc", "sbb", "and", "sub", "xor", "cmp")
            # Do not make i += 1 !
            x, i = analyse_modrm(s, i)
            mnemonic = mnemonics[x['modrm'][1]]
            _, op = unify_operands(x)
            if op.reg is None:
                if flags == 0:
                    op.data_size = 0
                elif size_prefix:
                    op.data_size = 1
                else:
                    op.data_size = 2
            if flags == 1:
                immediate = int.from_bytes(s[i:i+4], byteorder='little')
                i += 4
            else:  # flags == 0 or flags == 3
                immediate = s[i]
                i += 1
            line = DisasmLine(start_address+j, data=s[j:i], mnemonic=mnemonic, operands=[op, immediate])

        if not line:
            i += 1
            line = BytesLine(start_address+j, data=s[j:i])

        yield line
