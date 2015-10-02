
from disasm import *
from binio import fpeek, fpoke4, fpoke, pad_tail
from opcodes import *


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
    for line in fn:
        line = line.replace('\\r', '\r')
        line = line.replace('\\t', '\t')
        parts = line.split('|')
        if len(parts) > 3 and len(parts[1]) > 0:
            yield parts[1], parts[2]

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
            # obj_off = rva_to_off(obj_rva, sections)
            obj_off = sections.rva_to_offset(obj_rva)
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
            disp = to_signed(aft[1], width=8)
            next_off += 2 + disp
        else:
            disp = int.from_bytes(aft[1:5], byteorder='little', signed=True)
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
            if int.from_bytes(pre[-5:-1], byteorder='little') == oldlen:
                fpoke4(fn, offset-5, newlen)
                if pre[-6] == mov_reg_imm | 8 | Reg.edi:
                    # mov edi, len before
                    if oldlen == 15 and aft:
                        # Trying to fix the case when the edi value is used as a stl-string cap size
                        # Sample code for this case:
                        # mov edi, 0fh
                        # mov eax, strz_You_last_spoke__db24d8
                        # lea esi, [esp+40h]
                        # mov [esp+54h], edi  ; Equivalent to mov [esi+14h], edi
                        # mov dword ptr [esp+50h], 0
                        # mov byte ptr [esp+40h], 0
                        # call sub_40f650
                        
                        mov_esp_edi = False
                        
                        for line in disasm(aft):
                            assert(line.mnemonic != 'db')
                            if str(line).startswith('mov [esp') and str(line).endswith('], edi'):
                                mov_esp_edi = True
                            elif line.data[0] == call_near:
                                if mov_esp_edi:
                                    disp = int.from_bytes(line.data[1:5], byteorder='little', signed=True)
                                    return (
                                        next_off+line.address,
                                        ((mov_rm_imm | 1), join_byte(1, 0, Reg.esi), 0x14, 0x0f, 0, 0, 0),  # mov [esi+14h], 0fh
                                        next_off+line.address+5+disp,  # call_near - 1 byte, displacement - 4 bytes
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
                        oldnext,
                        (push_imm8, newlen),
                        next_off+2,
                        jmp
                    )
                else:
                    # jmp == jmp_short
                    i = find_instruction(aft, call_near)
                    if i is not None:
                        disp = int.from_bytes(aft[i+1:i+5], byteorder='little', signed=True)
                        return (
                            next_off+i,
                            mach_strlen((mov_rm_reg+1, join_byte(1, Reg.ecx, 4), join_byte(0, 4, Reg.esp), 8)),  # mov [ESP+8], ECX
                            next_off+i+5+disp,
                            aft[i]
                        )
            elif pre[-2] == mov_reg_rm | 1 and pre[-1] & 0xf8 == join_byte(3, Reg.edi, 0):
                # mov edi, reg
                # There's no code in DF that passes this condition. Leaved just in case.
                i = find_instruction(aft, call_near)
                if i is not None:
                    disp = int.from_bytes(aft[i+1:i+5], byteorder='little', signed=True)
                    return (
                        next_off+i,
                        mach_strlen((mov_reg_rm | 1, join_byte(3, Reg.edi, Reg.ecx))),  # mov edi, ecx
                        next_off+i+5+disp,
                        aft[i]
                    )
            elif aft and aft[0] == mov_reg_imm | 8 | Reg.edi and int.from_bytes(aft[1:5], byteorder='little') == oldlen:
                # mov edi, len ; after
                if not jmp:
                    fpoke4(fn, next_off+1, newlen)
                    return 1
                elif jmp == jmp_near:
                    return (
                        oldnext,
                        bytes((mov_reg_imm | 8 | Reg.edi,)) + newlen.to_bytes(length=4, byteorder='little'),
                        next_off+5,
                        jmp
                    )
                else:  # jmp == jmp_short
                    i = find_instruction(aft, call_near)
                    if i is not None:
                        disp = int.from_bytes(aft[i+1:i+5], byteorder='little', signed=True)
                        return (
                            next_off+i,
                            mach_strlen((mov_reg_rm | 1, join_byte(3, Reg.edi, Reg.ecx))),  # mov edi, ecx
                            next_off+i+5+disp,
                            aft[i]
                        )
            elif pre[-4] == lea and pre[-3] & 0xf8 == join_byte(1, Reg.edi, 0):
                # lea edi, [reg+N] ; assume that reg+N == oldlen
                disp = to_signed(pre[-2], 8)
                if disp == oldlen:
                    # lea edi, [reg+oldlen]
                    fpoke(fn, offset-2, newlen)
                    return 1
                elif pre[-3] & 7 != Reg.esp:
                    # lea edi, [reg+oldlen+N]
                    fpoke(fn, offset-2, newlen-oldlen+disp)
                    return 1
            elif (aft and not jmp and aft[0] == mov_reg_rm | 1 and aft[1] & 0xf8 == join_byte(3, Reg.ecx, 0) and
                  aft[2] == push_imm8 and aft[3] == oldlen):
                # mov ecx, reg; push imm8
                fpoke(fn, next_off+3, newlen)
                return 1
        elif reg == Reg.esi:
            # Sample code:
            # ; oldlen = 22
            # ; r = (oldlen+1) % 4 = 3 (3 bytes moved with 1 movsw and 1 movsb)
            # mov ecx, 5 ; 5 = (oldlen + 1) // 4
            # mov esi, strz_Store_Item_in_Hospital_dc4f40
            # lea edi, [dest]
            # repz movsd
            # movsw
            # movsb
            r = (oldlen+1) % 4
            dword_count = (newlen-r)//4 + 1
            if pre[-6] == mov_reg_imm | 8 | Reg.ecx and int.from_bytes(pre[-5:-1], byteorder='little') == (oldlen+1)//4:
                # mov ecx, dword_count
                fpoke4(fn, offset-5, dword_count)
                return 1
            elif pre[-4] == lea and pre[-3] & 0xf8 == join_byte(1, Reg.ecx, 0) and pre[-2] == (oldlen+1)//4:
                # lea ecx, [reg+dword_count]  ; assuming that reg value == 0
                fpoke(fn, offset-2, dword_count)
                return 1
            elif newlen > oldlen:
                # ecx modification code was not found. TODO: handle this case properly.
                return -2
        return -1
    elif pre[-1] == mov_acc_mem | 1 or pre[-2] == mov_reg_rm | 1:
        # mov eax, [addr] or mov reg, [addr]
        if newlen <= oldlen:
            return -1
        elif newlen+1 <= align(oldlen+1):
            r = (oldlen+1) % 4
            next_off = offset - get_start(pre)
            aft = fpeek(fn, next_off, count_after)
            flag = 0
            reg = None
            move_to_reg = None
            for x, i in analyse_mach(aft):
                if r == 1:
                    if flag == 0:
                        if x['data'][0] == mov_reg_rm and 'modrm' in x:
                            # Copying 1 byte from memory to a register
                            modrm = x['modrm']
                            if modrm.mode == 0 and modrm.regmem == 5:
                                reg = modrm.reg
                                move_to_reg = i
                                flag += 1
                        elif x['data'][0] == mov_acc_mem:
                            # Copying 1 byte from memory to accumulator (al)
                            reg = Reg.eax
                            move_to_reg = i
                            flag += 1
                    else:
                        if x['data'][0] == mov_rm_reg and 'modrm' in x:
                            # Copying from register to memory
                            modrm = x['modrm']
                            if modrm.mode != 3 and modrm.reg == reg:
                                move_to_mem = i
                                # Make code move 4 bytes instead of 1:
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
                assert(flag < 2)
        else:
            return 0

    return -1  # Assume that there's no need to fix


def get_length(s, oldlen):
    # TODO: Rewrite to use disasm
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
            reg = modrm.reg
            assert(reg <= Reg.dx)  # reg in {Reg.ax, Reg.cx, Reg.dx})
            i += 1  # assume there's no sib byte
            if op & 2:
                # mov reg, [mem]
                assert(modrm.mode == 0 and modrm.regmem == 5)  # move from explicit address to register
                assert(regs[reg] is None)  # register value was not saved
                regs[reg] = size
                deleted.add(i)
            else:
                # mov [reg+N], reg
                assert(modrm.mode != 3)  # move to register disallowed
                assert(not (modrm.mode == 0 and modrm.regmem == 5))  # move to explicit address disallowed
                assert(regs[reg] == size)  # get a value with the same size as stored
                regs[reg] = None
                x = process_operands(x)
                if dest is None or dest[0] == x[0] and dest[1] > x[1]:
                    dest = x
                curlen += size
            i = j
        elif op == lea:
            x, j = analyse_modrm(s, i)
            modrm = x['modrm']
            assert(modrm.mode != 3)
            reg = modrm.reg
            if reg <= Reg.dx:
                regs[reg] = -1  # mark register as occupied
            x = process_operands(x)
            if dest is None or dest[0] == x[0] and dest[1] > x[1]:
                dest = x
            _lea = dict(dest=modrm.reg, src=Operand(base_reg=x[0], disp=x[1]))
            i = j
        else:
            raise ValueError('Unallowed operation (not mov, nor lea)')
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
    mach += src.to_bytes(4, byteorder='little')  # imm32
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
