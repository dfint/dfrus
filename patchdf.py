
from disasm import *
from binio import *
from pe import rva_to_off


def patch_unicode_table(fn, off):
    upper_a_ya = [c for c in range(0x0410, 0x0430)]
    assert(len(upper_a_ya) == 0x20)
    ord_upper_a = int.from_bytes('А'.encode('cp1251'), 'little')
    fpoke4(fn, off+ord_upper_a*4, upper_a_ya)
    
    lower_a_ya = [c for c in range(0x0430, 0x0450)]
    assert(len(lower_a_ya) == 0x20)
    ord_lower_a = int.from_bytes('а'.encode('cp1251'), 'little')
    fpoke4(fn, off+ord_lower_a*4, lower_a_ya)
    
    upper_yo = 0x0401
    ord_upper_yo = int.from_bytes('Ё'.encode('cp1251'), 'little')
    fpoke4(fn, off+ord_upper_yo*4, upper_yo)
    
    lower_yo = 0x0451
    ord_lower_yo = int.from_bytes('ё'.encode('cp1251'), 'little')
    fpoke4(fn, off+ord_lower_yo*4, lower_yo)


def load_trans_file(fn):
    trans = {}
    for line in fn:
        line = line.replace('\\r', '\r')
        line = line.replace('\\t', '\t')
        parts = line.split('|')
        if len(parts) > 3 and len(parts[1]) > 0:
            trans[parts[1]] = parts[2]
    return trans

from collections import defaultdict

code = 0
rdata = 1
data = 2


def get_cross_references(fn, relocs, sections, image_base):
    xrefs = defaultdict(list)
    data_lower_bound = sections[rdata].rva
    data_upper_bound = sections[data].rva + sections[data].virtual_size
    # Read entire code section to the memory (about 9.2 MB for DF 0.40.13):
    code_section = fpeek(fn, sections[code].physical_offset, sections[code].physical_size)
    for reloc in relocs:
        reloc -= sections[code].rva
        if not (0 <= reloc < sections[code].virtual_size):
            # Relocation doesn't belong to the code section
            continue
        obj_rva = int.from_bytes(code_section[reloc:reloc+4], 'little') - image_base
        reloc += sections[code].physical_offset
        if data_lower_bound <= obj_rva <= data_upper_bound:
            obj_off = rva_to_off(obj_rva, sections)
            if obj_off is not None:
                xrefs[obj_off].append(reloc)
    
    return xrefs


def get_start(s):
    i = 0
    if s[-1-i] & 0xfe == mov_acc_mem:
        i += 1
    elif s[-1-i-1] & 0xf8 == mov_rm_reg and s[-1-i] & 0xc7 == 0x05:
        i += 2

    if s[-1-i] == Prefix.operand_size:
        i += 1

    return i


MAX_LEN = 0x80


def mach_strlen(code_chunk):
    return (bytes((push_reg | Reg.ecx,  # push ecx
                   xor_rm_reg | 1, join_byte(3, Reg.ecx, Reg.ecx),  # xor eax, eax
                   # @@:
                   cmp_rm_imm, join_byte(0, 7, 4), join_byte(0, Reg.ecx, Reg.eax), 0x00,  # cmp byte [eax+ecx], 0
                   jcc_short | Cond.z, 0x0b,  # jz success
                   cmp_rm_imm | 1, join_byte(3, 7, Reg.ecx), MAX_LEN, 0x00, 0x00, 0x00,  # cmp ecx, MAX_LEN
                   jcc_short | Cond.g, 3+len(code_chunk),  # jg skip
                   inc_reg | Reg.ecx,  # inc ecx
                   jmp_short, 0xef  # jmp @b
                   )) +
            # success:
            bytes(code_chunk) +
            # skip:
            bytes((pop_reg | Reg.ecx,)))


def find_instruction(s, instruction):
    for line in disasm(s):
        assert(line.mnemonic != 'db')
        if line.data[0] == instruction:
            return line.address
    return None


count_before = 0x20
count_after = 0x80


def fix_len(fn, offset, oldlen, newlen):
    next_off = offset+4
    pre = fpeek(fn, offset-count_before, count_before)
    aft = fpeek(fn, next_off, count_after)
    jmp = None
    oldnext = None
    if aft[0] in {jmp_short, jmp_near}:
        oldnext = next_off
        if aft[0] == jmp_short:
            disp = signed(aft[1], width=8)
            next_off += 2 + disp
        else:
            disp = signed(from_bytes(aft[1:5]), width=32)
            next_off += 5 + disp
        jmp = aft[0]
        aft = fpeek(fn, next_off, count_after)
    elif aft[0] == call_near or aft[0] & 0xf0 == jcc_short or (aft[0] == 0x0f and aft[1] == x0f_jcc_near):
        aft = None

    if pre[-1] == push_imm32:
        # push offset str
        return -1  # No need fixing
    elif pre[-1] & 0xF8 == (mov_reg_imm | 8):
        # mov reg32, offset str
        reg = pre[-1] & 7
        if reg == Reg.eax:
            # mov eax, offset str
            if from_bytes(pre[-5:-2]) == oldlen:
                fpoke4(fn, offset-5, newlen)
                if pre[-6] == mov_reg_imm | 8 | Reg.edi:
                    # mov edi, len before
                    if oldlen == 15 and aft:
                        # Trying to fix the case when the edi value is used as a stl-string cap size
                        mov_esp_edi = False

                        for line in disasm(aft):
                            assert(line.mnemonic != 'db')
                            if str(line) == 'mov [esp], edi':
                                mov_esp_edi = True
                            elif line.data[0] == call_near:
                                if mov_esp_edi:
                                    disp = signed(from_bytes(line.data[1:5]), 32)
                                    return (
                                        next_off+line.address,
                                        ((mov_rm_imm | 1), join_byte(1, 0, Reg.esi), 0x14, 0x15, 0, 0, 0),  # mov [esi+14h], 15
                                        next_off+line.address+4+disp,
                                        aft[line.address]
                                    )
                                else:
                                    break
                return 1  # Length fixed successfully
            elif pre[-3] == push_imm8 and pre[-2] == oldlen:
                # push len ; before
                fpoke(fn, offset-2, newlen)
                return 1
            elif aft and aft[0] == push_imm8 and aft[1] == oldlen:
                # push len ; after
                if not jmp:
                    fpoke(fn, next_off+1, newlen)
                    return 1
                elif jmp == jmp_near:
                    return (
                        oldnext+1,
                        (push_imm8, newlen),
                        next_off+2,
                        jmp
                    )
                else:
                    # jmp == jmp_short
                    i = find_instruction(aft, call_near)
                    if i is not None:
                        disp = signed(from_bytes(aft[i+1:i+5]), 32)
                        return (
                            next_off+i,
                            mach_strlen((mov_rm_reg+1, join_byte(1, Reg.ecx, 4), join_byte(0, 4, Reg.esp), 8)),  # mov [ESP+8], ECX
                            next_off+i+4+disp,
                            call_near
                        )
            elif pre[-2] == mov_reg_rm | 1 and pre[-1] & 0xf8 == join_byte(3, Reg.edi, 0):
                # mov edi, reg
                # There's no code in DF that passes this condition. Leaved just in case.
                i = find_instruction(aft, call_near)
                if i is not None:
                    disp = signed(from_bytes(aft[i+1:i+5]), 32)
                    return (
                        next_off+i,
                        mach_strlen((mov_reg_rm | 1, join_byte(3, Reg.edi, Reg.ecx))),  # mov edi, ecx
                        next_off+i+4+disp,
                        call_near
                    )
            elif aft and aft[0] == mov_reg_imm | 8 | Reg.edi and from_bytes(aft[1:5]) == oldlen:
                # mov edi, len ; after
                if not jmp:
                    fpoke4(fn, next_off+1, newlen)
                    return 1
                elif jmp == jmp_near:
                    return (
                        oldnext+1,
                        bytes((mov_reg_imm | 8 | Reg.edi,)) + newlen.to_bytes(length=4, byteorder='little'),
                        next_off+5,
                        jmp
                    )
                else:  # jmp == jmp_short
                    i = find_instruction(aft, call_near)
                    if i is not None:
                        disp = signed(from_bytes(aft[i+1:i+5]), 32)
                        return (
                            next_off+i,
                            mach_strlen((mov_reg_rm | 1, join_byte(3, Reg.edi, Reg.ecx))),  # mov edi, ecx
                            next_off+i+4+disp,
                            call_near
                        )
            elif pre[-4] == lea and pre[-3] & 0xf8 == join_byte(1, Reg.edi, 0):
                # lea edi, [reg+N] ; assume that reg+N == oldlen
                disp = signed(pre[-2], 8)
                if disp == oldlen:
                    # lea edi, [reg+oldlen]
                    fpoke(fn, offset-2, newlen)
                    return 1
                elif pre[-3] & 7 != Reg.esp:
                    fpoke(fn, offset-2, newlen-oldlen+disp)
                    return 1
            elif (aft and not jmp and aft[0] == mov_reg_rm | 1 and aft[1] & 0xf8 == join_byte(3, Reg.ecx, 0) and
                  aft[2] == push_imm8 and aft[3] == oldlen):
                fpoke(fn, next_off+3, newlen)
                return 1
        elif reg == Reg.esi:
            # mov esi, offset str
            if pre[-6] == mov_reg_imm | 8 | Reg.ecx and from_bytes(pre[-5:-1]) == (oldlen+1)//4:
                # mov ecx, (len+1)//4
                r = (oldlen+1) % 4
                fpoke4(fn, offset-5, (newlen+1-r+3)//4)
                return 1
            elif pre[-4] == lea and pre[-3] & 0xf8 == join_byte(1, Reg.ecx, 0) and pre[-2] == (oldlen+1)//4:
                # lea ecx, [reg+(len+1)//4]
                r = (newlen+1) % 4
                fpoke(fn, offset-2, (newlen+1-r+3)//4)
                return 1
            elif newlen > oldlen:
                return -2
        return -1
    elif pre[-1] == mov_acc_mem | 1 or pre[-2] == mov_reg_rm | 1:
        # mov eax, [addr] or mov reg, [addr]
        if newlen <= oldlen:
            return -1
        elif newlen+1 <= align(oldlen+1):
            r = (oldlen+1)//4
            next_off = offset - get_start(pre)
            aft = fpeek(fn, next_off, count_after)
            i = 0
            flag = 0
            reg = None
            move_to_reg = None
            while i < len(aft) and flag < 2:
                x, j = analyse_mach(aft, i)
                if r == 1:
                    if flag == 0:
                        if x['data'][0] == mov_reg_rm and 'modrm' in x:
                            modrm = x['modrm']
                            if modrm[0] == 0 and modrm[2] == 5:
                                reg = modrm[1]
                                move_to_reg = i
                                flag += 1
                        elif x['data'][0] == mov_acc_mem:
                            reg = Reg.eax
                            move_to_reg = i
                            flag += 1
                    else:
                        if x['data'][0] == mov_rm_reg and 'modrm' in x:
                            modrm = x['modrm']
                            if modrm[0] != 3 and modrm[2] == reg:
                                move_to_mem = i
                                opcode = aft[move_to_reg]
                                fpoke(fn, next_off+move_to_reg, opcode | 1)  # set size flag of the opcode
                                opcode = aft[move_to_mem]
                                fpoke(fn, next_off+move_to_mem, opcode | 1)  # set size flag of the opcode
                                return 1
                else:
                    if x['data'][0] == Prefix.operand_size:
                        if flag == 0:
                            move_to_reg = i
                            flag += 1
                        else:
                            move_to_mem = i
                            fpoke(fn, next_off+move_to_reg, nop)  # clear operand size prefix
                            fpoke(fn, next_off+move_to_mem, nop)  # clear operand size prefix
                            return 1
                i = j
                assert(flag < 2)
        else:
            return 0

    return -1  # Assume that there's no need to fix


def get_length(s, oldlen):
    i = 0
    curlen = 0
    regs = [None, None, None]
    deleted = set()
    dest = None
    _lea = None
    while curlen < oldlen:
        size = 4
        if s[i] == Prefix.operand_size:
            size = 2
            i += 1

        op = s[i]
        i += 1
        if op & 0xfe == mov_acc_mem:
            # mov eax/ax/al, [mem]
            assert(regs[Reg.ax] is None)
            if op & 1 == 0:
                size = 1
            regs[Reg.ax] = size
            deleted.add(i)
            i += 4
        elif op & 0xfc == mov_rm_reg:
            if op & 1 == 0:
                size = 1
            x, j = analyse_modrm(s, i)
            modrm = x['modrm']
            reg = modrm[1]
            assert(reg <= Reg.dx)  # reg in {Reg.ax, Reg.cx, Reg.dx})
            i += 1  # assume there's no sib byte
            if op & 2:
                # mov reg, [mem]
                assert(modrm[0] == 0 and modrm[2] == 5)  # move from explicit address to register
                assert(regs[reg] is None)  # register value was not saved
                regs[reg] = size
                deleted.add(i)
            else:
                # mov [mem], reg
                assert(modrm[0] == 3 or (modrm[0] == 0 and modrm[2] == 5))  # move to register or explicit address
                assert(regs[reg] == size)  # get a value with the same size as stored
                regs[reg] = None
                x = process_operands(x)
                if dest is None:
                    dest = x
                elif dest[0] == x[0] and dest[1] > x[1]:
                    dest[1] = x[1]
                curlen += size
            i = j
        elif op == lea:
            x, j = analyse_modrm(s, i)
            modrm = x['modrm']
            assert(modrm[0] != 3)
            reg = modrm[1]
            if reg <= Reg.dx:
                regs[reg] = -1  # mark register as occupied
            x = process_operands(x)
            if dest is None:
                dest = x
            elif dest[0] == x[0] and dest[1] > x[1]:
                dest[1] = x[1]
            _lea = dict(dest=modrm[1], src=Operand(base_reg=x[0], disp=x[1]))
            i = j
        else:
            raise AssertionError
    return dict(length=i, dest=dest, deleted=deleted, lea=_lea)


def mach_memcpy(src, dest, count):
    mach = bytearray()
    mach.append(pushad)  # pushad
    mach += bytearray((xor_rm_reg | 1, join_byte(3, Reg.ecx, Reg.ecx)))  # xor ecx, ecx
    mach += bytearray((mov_reg_imm | Reg.cl, (count+3)//4))  # mov cl, (count+3)//4

    # If the destination address is not in edi yet, put it there
    if dest != (Reg.edi, 0):
        if dest[1] == 0:
            # mov edi, reg
            mach += bytearray((mov_rm_reg | 1, join_byte(3, dest[0], Reg.edi)))
        else:
            # lea edi, [reg+imm]
            mach += mach_lea(Reg.edi, Operand(base_reg=dest[0], disp=dest[1]))

    mach.append(mov_reg_imm | 8 | Reg.esi)  # mov esi, ...
    new_reference = len(mach)
    mach += to_bytes(src, 4)  # imm32
    mach += bytearray((Prefix.rep, movsd))  # rep movsd
    mach.append(popad)  # popad

    return mach, new_reference


def add_to_new_section(fn, dest, s, alignment=4):
    aligned = align(len(s), alignment)
    s = pad_tail(s, aligned, b'\0')
    fpoke(fn, dest, s)
    return dest + aligned


if __name__ == '__main__':
    from binio import TestFileObject
    patch_unicode_table(TestFileObject(), 0)
    print(load_trans_file(['|12\\t3|as\\rd|', '|dfg|345y|', ' ', '|||']))
