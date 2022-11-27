from collections import namedtuple
from enum import Enum, IntEnum, auto


class Cond(IntEnum):
    """Condition codes"""

    (o, no, b, nb, e, ne, be, a, s, ns, p, np, l, nl, le, g) = range(16)

    nae = b
    not_above_equal = nae
    c = b
    ae = nb
    nc = nb
    z = e
    zero = z
    nz = ne
    not_zero = nz
    na = be
    pe = p
    po = np
    nge = l
    ge = nl
    nle = g


class RegType(Enum):
    general = auto()
    segment = auto()
    mm = auto()
    xmm = auto()


RegData = namedtuple("RegData", "type,code,size")


class Reg(Enum):
    eax, ecx, edx, ebx, esp, ebp, esi, edi = ((RegType.general, i, 4) for i in range(8))
    ax, cx, dx, bx, sp, bp, si, di = ((RegType.general, i, 2) for i in range(8))
    al, cl, dl, bl, ah, ch, dh, bh = ((RegType.general, i, 1) for i in range(8))
    es, cs, ss, ds, fs, gs = ((RegType.segment, i, 2) for i in range(6))
    mm0, mm1, mm2, mm3, mm4, mm5, mm6, mm7 = ((RegType.mm, i, 8) for i in range(8))
    xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7 = ((RegType.xmm, i, 16) for i in range(8))

    def __init__(self, *reg_data):
        reg_data = RegData(*reg_data)

        self.type = reg_data.type
        self.code = reg_data.code
        self.size = reg_data.size

        if reg_data.type == RegType.general:
            assert reg_data.size <= 4, "Fix me!"
            if reg_data.size == 4:  # TODO: fix this when 64-bit general purpose registers will be added
                self.parent = self
            elif reg_data.size == 2:
                self.parent = type(self)(RegData(RegType.general, self.code, 4))
            elif reg_data.size == 1:
                self.parent = type(self)(RegData(RegType.general, self.code % 4, 4))
        elif reg_data == RegType.mm:
            # Assume that parent for mm registers are xmm ones
            self.parent = type(self)(RegData(RegType.xmm, self.code, 16))
        else:
            self.parent = self

    @classmethod
    def segment(cls, code: int):
        return cls((RegType.segment, code, 2))

    @classmethod
    def mm(cls, code: int):
        return cls((RegType.mm, code, 8))

    @classmethod
    def xmm(cls, code: int):
        return cls((RegType.xmm, code, 16))

    def __int__(self):
        return self.code

    def __index__(self):
        return self.code

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    def __eq__(self, other):
        if isinstance(other, int):
            return self.code == other
        else:
            return self is other

    def __hash__(self):
        return hash(self.value)


class Prefix(IntEnum):
    """Prefix codes"""

    rep = 0xF3
    repe = rep
    repz = rep
    repne = 0xF2
    repnz = repne
    lock = 0xF0

    operand_size = 0x66
    address_size = 0x67

    seg_es = 0x26
    seg_cs = 0x2E
    seg_ss = 0x36
    seg_ds = 0x3E
    seg_fs = 0x64
    seg_gs = 0x65


jmp_near = 0xE9
jmp_short = jmp_near + 2
jmp_indir = bytes([0xFF, 0x20])
jcc_short = 0x70  # + cond
jcc_near = bytes([0x0F, 0x80])  # + {0,cond}

call_near = 0xE8
call_indir = bytes([0xFF, 0x10])

setcc = bytes([0x0F, 0x90])

cmp_rm_imm = 0x80
cmp_rm_reg = 0x38  # | dir<<1 | width

nop = 0x90
cdq = 0x99

lea = 0x8D

ret_near = 0xC3
ret_far = 0xCB
ret_near_n = 0xC2
ret_far_d = 0xCA
leave = 0xC9
int3 = 0xCC

push_reg = 0x50  # + reg
push_imm32 = 0x68
push_imm8 = push_imm32 + 2
push_indir = bytes([0xFF, 0x30])  # + размер смещение * 40h + базовый регистр [& sib]
pushfd = 0x9C
popfd = 0x9D

pop_reg = 0x58  # + reg
pop_rm = 0x8F

pushad = 0x60
popad = 0x61

add_acc_imm = 0x04  # + width
sub_acc_imm = 0x2C  # + width
xor_acc_imm = 0x34  # + width
or_acc_imm = 0x0C  # + width
and_acc_imm = 0x24  # + width
test_acc_imm = 0xA8  # + width
cmp_acc_imm = 0x3C  # + width
adc_acc_imm = 0x14
sbb_acc_imm = 0x1C

add_rm_reg = 0x00  # + 2*dir + width
sub_rm_reg = 0x28  # + 2*dir + width
sub_reg_rm = sub_rm_reg + 2  # + width
xor_rm_reg = 0x30  # + 2*dir + width
or_rm_reg = 0x08  # + 2*dir + width
and_rm_reg = 0x20  # + 2*dir + width
adc_rm_reg = 0x10
sbb_rm_reg = 0x18

op_rm_imm = 0x80
op_rm_imm8 = 0x83

xchg_rm_reg = 0x86  # + width
xchg_acc_reg = 0x90  # + reg # no width bit, so only eax and ax are acceptable

test_rm_reg = 0x84  # + width

mov_reg_imm = 0xB0  # + 8*width + reg
mov_acc_mem = 0xA0  # + 2*dir + width
mov_rm_reg = 0x88  # + 2*dir + width
mov_reg_rm = mov_rm_reg + 2  # + width
mov_rm_imm = 0xC6  # + width
mov_rm_seg = 0x8C  # + 2*dir

movsb = 0xA4
movsd = 0xA5
# movsw = (Prefix.operand_size, movsd)

inc_reg = 0x40  # + reg
dec_reg = 0x48  # + reg

# Opcodes after 0x0f prefix
x0f_setcc = 0x90
x0f_movzx = 0xB6
x0f_movsx = 0xBE
x0f_jcc_near = 0x80
x0f_movups = 0x10  # + dir
x0f_movaps = 0x28  # + dir
x0f_movd_mm = 0x6E  # + dir << 4 + size_flag
x0f_movq_rm_xmm = 0xD6
x0f_cmov = 0x40  # + cond

shift_op_rm_1 = 0xD0  # + width
shift_op_rm_cl = 0xD2  # + width
shift_op_rm_imm8 = 0xC0  # + width

test_or_unary_rm = 0xF6  # + width & MODRM (reg==0 - test; reg==1 - n/a; reg==2 through 7 - unary ops)
