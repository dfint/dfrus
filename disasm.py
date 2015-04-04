
from opcodes import *


def align(n, edge=4):
    return (n+edge-1) & (-edge)


def signed(x, w):
    pow2w = 2**w
    assert(x < pow2w)
    if x & (pow2w//2):
        x -= pow2w
    return x


seg_prefixes = {Prefix.seg_cs: "cs", Prefix.seg_ds: "ds", Prefix.seg_es: "es", Prefix.seg_ss: "ss", Prefix.seg_fs: "fs",
                Prefix.seg_gs: "gs"}

op_1byte_nomask_noargs = {nop: "nop", ret_near: "retn", pushfd: "pushfd", pushad: "pushad", popfd: "popfd",
                          popad: "popad", leave: "leave", int3: "int3"}
op_nomask = {call_near: "call near", jmp_near: "jmp near", jmp_short: "jmp short"}

conditions = ("o", "no", "b", "nb", "z", "nz", "na", "a", "s", "ns", "p", "np", "l", "nl", "ng", "g")


def asmhex(n):
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
        super().__init__(address, data, mnemonic='db', operands=[asmhex(n) for n in data])


def disasm(s, start_address=0):
    i = 0
    while i < len(s):
        j = i
        size_prefix = False
        seg_prefix = ""
        line = None
        if s[i] in seg_prefixes:
            seg_prefix = seg_prefixes[s[i]]
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
            line = DisasmLine(start_address+i, data=s[i:i+4], mnemonic='retn', operands=[asmhex(immediate)])
            i += 3
        elif s[i] in {call_near, jmp_near}:
            if len(s) < i+4:
                line = BytesLine(start_address+j, data=s[j:])
            else:
                if i > j:
                    yield BytesLine(start_address+j, data=s[j:i])
                immediate = start_address+i+5+signed(int.from_bytes(s[i+1:i+5], byteorder='little'), 32)
                line = DisasmLine(start_address+i, data=s[i:i+5], mnemonic=op_nomask[s[i]], operands=[asmhex(immediate)])
                i += 5
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
                line = DisasmLine(start_address+i, data=s[i:i+2], mnemonic=mnemonic, operands=[asmhex(immediate)])
                i += 2

        if not line:
            i += 1
            line = BytesLine(start_address+j, data=s[j:i])

        yield line
