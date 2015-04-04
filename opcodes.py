

class Cond:
    """Condition codes"""

    (overflow, not_overflow, below, not_below, equal, not_equal, below_equal, above, sign, not_sign, parity,
        not_parity, less, not_less, less_equal, greater) = range(16)

    o = overflow
    no = not_overflow

    b = below
    nae = b
    not_above_equal = nae
    c = b
    carry = c

    nb = not_below
    ae = nb
    above_equal = ae
    nc = nb
    e = equal
    z = e
    zero = z
    ne = not_equal
    nz = ne
    not_zero = nz
    be = below_equal
    na = be
    s = sign
    ns = not_sign
    p = parity
    pe = p
    np = not_parity
    po = np
    l = less
    nge = l
    nl = not_less
    ge = nl
    g = greater
    nle = g


class Reg:
    """"Register codes"""
    al, cl, dl, bl, ah, ch, dh, bh = range(8)
    ax, cx, dx, bx, sp, bp, si, di = range(8)
    eax, ecx, edx, ebx, esp, ebp, esi, edi = range(8)
    es, cs, ss, ds, fs, gs = range(6)


class Prefix:
    """Prefix codes"""
    rep = 0xf3
    repe = rep
    repz = rep
    repne = 0xf2
    repnz = repne
    lock = 0xf0

    operand_size = 0x66
    address_size = 0x67

    seg_es = 0x26
    seg_cs = 0x2e
    seg_ss = 0x36
    seg_ds = 0x3e
    seg_fs = 0x64
    seg_gs = 0x65


jmp_near = 0xe9
jmp_short = jmp_near+2
jmp_indir = bytes([0xff, 0x20])
jcc_short = 0x70  # + cond
jcc_near = bytes([0x0f, 0x80])  # + {0,cond}

call_near = 0xe8,
call_indir = bytes([0xff, 0x10])

setcc = bytes([0x0f, 0x90])

cmp_rm_imm = 0x80
cmp_rm_reg = 0x38 # | dir<<1 | width

nop = 0x90

lea = 0x8d

ret_near = 0xc3
ret_far = 0xcb
ret_near_n = 0xc2
ret_far_d = 0xca
leave = 0xc9
int3 = 0xcc

push_reg = 0x50 # + reg
push_imm32 = 0x68
push_imm8 = push_imm32 + 2
push_indir = bytes([0xff, 0x30]) # + размер смещение * 40h + базовый регистр [& sib]
pushfd = 0x9c
popfd = 0x9d

pop_reg = 0x58 # + reg
pop_rm = 0x8f

pushad = 0x60
popad = 0x61