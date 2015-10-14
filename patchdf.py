
from disasm import *
from binio import fpeek, fpoke4, fpoke, pad_tail, from_dword, to_dword
from opcodes import *
from collections import defaultdict


def ord_utf16(c):
    return int.from_bytes(c.encode('utf-16')[2:], 'little')


def patch_unicode_table(fn, off):
    ord_upper_a = ord('А'.encode('cp1251'))
    fpoke4(fn, off+ord_upper_a*4, range(ord_utf16('А'), ord_utf16('Я') + 1))
    
    ord_lower_a = ord('а'.encode('cp1251'))
    fpoke4(fn, off+ord_lower_a*4, range(ord_utf16('а'), ord_utf16('я') + 1))
    
    ord_upper_yo = ord('Ё'.encode('cp1251'))
    fpoke4(fn, off+ord_upper_yo*4, ord_utf16('Ё'))
    
    ord_lower_yo = ord('ё'.encode('cp1251'))
    fpoke4(fn, off+ord_lower_yo*4, ord_utf16('ё'))


def load_trans_file(fn):
    for line in fn:
        line = line.replace('\\r', '\r')
        line = line.replace('\\t', '\t')
        parts = line.split('|')
        if len(parts) > 3 and len(parts[1]) > 0:
            yield parts[1], parts[2]


code, rdata, data = range(3)


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
        obj_rva = from_dword(code_section[reloc:reloc+4]) - image_base
        reloc += sections[code].physical_offset
        if data_lower_bound <= obj_rva <= data_upper_bound:
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
    return (bytes((
                push_reg | Reg.ecx,  # push ecx
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


class Trace:
    not_follow = 0
    follow = 1
    stop = 2
    forward_only = 3


def trace_code(fn, offset, func, trace_jmp = Trace.follow, trace_jcc = Trace.forward_only, trace_call = Trace.stop):
    s = fpeek(fn, offset, count_after)
    for line in disasm(s, offset):
        # print('%-8x\t%-16s\t%s' % (line.address, ' '.join('%02x' % x for x in line.data), line))
        if line.mnemonic == 'db':
            raise ValueError('Disassembler returned db at offset %xh' % offset)
        elif not func(line):  # Stop when the func returns False
            return line
        elif line.mnemonic.startswith('jmp'):
            if trace_jmp == Trace.not_follow:
                pass
            elif trace_jmp == Trace.follow:
                return trace_code(fn, int(line.operands[0]), func, trace_jmp, trace_jcc, trace_call)
            elif trace_jmp == Trace.stop:
                return line
            elif trace_jmp == Trace.forward_only:
                if int(line.operands[0]) > line.address:
                    return trace_code(fn, int(line.operands[0]), func, trace_jmp, trace_jcc, trace_call)
        elif line.mnemonic.startswith('j'):
            if trace_jcc == Trace.not_follow:
                pass
            elif trace_jcc == Trace.follow:
                return trace_code(fn, int(line.operands[0]), func, trace_jmp, trace_jcc, trace_call)
            elif trace_jcc == Trace.stop:
                return line
            elif trace_jcc == Trace.forward_only:
                if int(line.operands[0]) > line.address:
                    return trace_code(fn, int(line.operands[0]), func, trace_jmp, trace_jcc, trace_call)
        elif line.mnemonic.startswith('call'):
            if trace_call == Trace.not_follow:
                pass
            elif trace_call == Trace.follow:
                returned = trace_code(fn, int(line.operands[0]), func, trace_jmp, trace_jcc, trace_call)
                if returned is None or not returned.mnemonic.startswith('ret'):
                    return returned
            elif trace_call == Trace.stop:
                return line
            elif trace_call == Trace.forward_only:
                if int(line.operands[0]) > line.address:
                    return trace_code(fn, int(line.operands[0]), func, trace_jmp, trace_jcc, trace_call)
        elif line.mnemonic.startswith('ret'):
            return line
    return None


def match_mov_reg_imm32(b, reg, imm):
    assert len(b) == 5, b
    return b[0] == mov_reg_imm | 8 | reg and from_dword(b[1:]) == imm


count_before = 0x20
count_after = 0x80


def fix_len(fn, offset, oldlen, newlen, new_str_rva):
    def which_func(offset):
        line = trace_code(fn, next_off, func=lambda line: not line.mnemonic.startswith('rep'))
        if line is None:
            func = ('not reached',)
        elif line.mnemonic.startswith('rep'):
            func = (line.mnemonic,)
        elif line.mnemonic.startswith('call'):
            try:
                func = (line.mnemonic, line.address, int(line.operands[0]))
            except ValueError:
                func = (line.mnemonic + ' indirect', line.address, str(line.operands))
        else:
            func = str(line)
        return func
    
    next_off = offset+4
    
    pre = fpeek(fn, offset-count_before, count_before)
    aft = fpeek(fn, next_off, count_after)
    jmp = None
    oldnext = next_off
    if aft[0] in {jmp_short, jmp_near} or aft[0] & 0xf0 == jcc_short:
        if aft[0] == jmp_short or aft[0] & 0xf0 == jcc_short:
            disp = to_signed(aft[1], width=8)
            next_off += 2 + disp
        elif aft[0] == jmp_near:
            disp = from_dword(aft[1:5], signed=True)
            next_off += 5 + disp
        jmp = aft[0]
        aft = fpeek(fn, next_off, count_after)
    elif aft[0] == call_near or (aft[0] == 0x0f and aft[1] == x0f_jcc_near):
        aft = None

    func = which_func(oldnext)
    meta = dict(func=func, len='unknown')
    if pre[-1] == push_imm32:
        # push offset str
        meta['fixed'] = 'not needed'
        meta['len'] = 'no'
        return meta  # No need fixing
    elif pre[-1] & 0xF8 == (mov_reg_imm | 8):
        # mov reg32, offset str
        reg = pre[-1] & 7
        if reg == Reg.eax:
            # mov eax, offset str
            meta['str'] = 'eax'
            if from_dword(pre[-5:-1]) == oldlen:
                fpoke4(fn, offset-5, newlen)
                meta['fixed'] = 'yes'
                if pre[-6] == mov_reg_imm | 8 | Reg.edi:
                    meta['len'] = 'edi'
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
                                    disp = from_dword(line.data[1:5], signed=True)
                                    retvalue = dict(
                                        src_off=next_off+line.address+1,
                                        new_code=bytes(((mov_rm_imm | 1), join_byte(1, 0, Reg.esi), 0x14)) + to_dword(0xf),  # mov [esi+14h], 0fh
                                        dest_off=next_off+line.address+5+disp,  # call_near opcode - 1 byte, displacement - 4 bytes
                                        op=call_near
                                    )
                                    retvalue.update(meta)
                                    return retvalue
                                else:
                                    break
                return meta  # Length fixed successfully
            elif pre[-3] == push_imm8 and pre[-2] == oldlen:
                # push len ; before
                fpoke(fn, offset-2, newlen)
                meta.update(dict(len='push imm8', fixed='yes'))
                return meta
            elif aft and aft[0] == push_imm8 and aft[1] == oldlen:
                # push len ; after
                meta['len'] = 'push'
                if not jmp:
                    fpoke(fn, next_off+1, newlen)
                    meta['fixed'] = 'yes'
                    return meta
                elif jmp == jmp_near:
                    retvalue = dict(
                        src_off=oldnext+1,
                        new_code=bytes((push_imm8, newlen)),
                        dest_off=next_off+2
                    )
                    retvalue.update(meta)
                    return retvalue
                else:  # jmp == jmp_short
                    i = find_instruction(aft, call_near)
                    if i is not None:
                        disp = from_dword(aft[i+1:i+5], signed=True)
                        retvalue = dict(
                            src_off=next_off+i+1,
                            new_code=mach_strlen((mov_rm_reg+1, join_byte(1, Reg.ecx, 4), join_byte(0, 4, Reg.esp), 8)),  # mov [ESP+8], ECX
                            dest_off=next_off+i+5+disp
                        )
                        retvalue.update(meta)
                        return retvalue
            elif pre[-2] == mov_reg_rm | 1 and pre[-1] & 0xf8 == join_byte(3, Reg.edi, 0):
                # mov edi, reg
                meta['len'] = 'edi'
                # There's no code in DF that passes this condition. Leaved just in case.
                # TODO: Drop it
                i = find_instruction(aft, call_near)
                if i is not None:
                    disp = from_dword(aft[i+1:i+5], signed=True)
                    retvalue = dict(
                        src_off=next_off+i+1,
                        new_code=mach_strlen((mov_reg_rm | 1, join_byte(3, Reg.edi, Reg.ecx))),  # mov edi, ecx
                        dest_off=next_off+i+5+disp,
                        op=call_near
                    )
                    retvalue.update(meta)
                    return retvalue
            elif aft and match_mov_reg_imm32(aft[:5], Reg.edi, oldlen):
                # mov edi, len ; after
                meta['len'] = 'edi'
                if not jmp:
                    fpoke4(fn, next_off+1, newlen)
                    meta['fixed'] = 'yes'
                    return meta
                elif jmp == jmp_near:
                    retvalue = dict(
                        src_off=oldnext+1,
                        new_code=bytes((mov_reg_imm | 8 | Reg.edi,)) + to_dword(newlen),
                        dest_off=next_off+5
                    )
                    retvalue.update(meta)
                    return retvalue
                else:  # jmp == jmp_short
                    i = find_instruction(aft, call_near)
                    if i is not None:
                        disp = from_dword(aft[i+1:i+5], signed=True)
                        retvalue = dict(
                            src_off=next_off+i+1,
                            new_code=mach_strlen((mov_reg_rm | 1, join_byte(3, Reg.edi, Reg.ecx))),  # mov edi, ecx
                            dest_off=next_off+i+5+disp,
                            op=call_near
                        )
                        retvalue.update(meta)
                        return retvalue
            elif pre[-4] == lea and pre[-3] & 0xf8 == join_byte(1, Reg.edi, 0):
                # lea edi, [reg+N] ; assume that reg+N == oldlen
                meta['len'] = 'edi'
                disp = to_signed(pre[-2], 8)
                if disp == oldlen:
                    # lea edi, [reg+oldlen]
                    fpoke(fn, offset-2, newlen)
                    meta['fixed'] = 'yes'
                    return meta
                elif pre[-3] & 7 != Reg.esp:
                    # lea edi, [reg+oldlen+N]
                    fpoke(fn, offset-2, newlen-oldlen+disp)
                    meta['fixed'] = 'yes'
                    return meta
            elif (aft and aft[0] == mov_reg_rm | 1 and aft[1] & 0xf8 == join_byte(3, Reg.ecx, 0) and
                  aft[2] == push_imm8 and aft[3] == oldlen):
                # mov ecx, reg; push imm8
                meta['len'] = 'push'
                if not jmp:
                    fpoke(fn, next_off+3, newlen)
                    meta['fixed'] = 'yes'
                    return meta
                elif jmp == jmp_near:
                    # TODO: Handle this case
                    meta['fixed'] = 'not implemented'
                    return meta
                else:
                    meta['fixed'] = 'no'
                    return meta
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
            meta['str'] = 'esi'
            meta['len'] = 'ecx*4'
            r = (oldlen+1) % 4
            dword_count = (oldlen+1)//4
            new_dword_count = (newlen-r)//4 + 1
            mod_1_ecx_0 = join_byte(1, Reg.ecx, 0)
            if match_mov_reg_imm32(pre[-6:-1], Reg.ecx, dword_count):
                # mov ecx, dword_count
                fpoke4(fn, offset-5, new_dword_count)
                meta['fixed'] = 'yes'
                return meta
            elif pre[-4] == lea and pre[-3] & 0xf8 == mod_1_ecx_0 and pre[-2] == dword_count:
                # lea ecx, [reg+dword_count]  ; assuming that reg value == 0
                fpoke(fn, offset-2, new_dword_count)
                meta['fixed'] = 'yes'
                return meta
            elif newlen > oldlen:
                # ecx modification code was not found. TODO: handle this case properly.
                if jmp:
                    meta['fixed'] = 'no'
                    return meta
                else:
                    for line in disasm(aft, start_address=next_off):
                        assert(line.mnemonic != 'db')
                        offset = line.address
                        data = line.data
                        if data[0] == Prefix.rep:
                            meta['fixed'] = 'no'
                            return meta
                        elif data[0] == jmp_near:
                            next_off_2 = line.address
                            jmp = data[0]
                            next_off_2 = line.operands[0].value
                            aft = fpeek(fn, next_off_2, count_after)
                            
                            skip = None
                            if match_mov_reg_imm32(aft[:5], Reg.ecx, dword_count):
                                skip = 5
                            elif aft[0] == lea and aft[1] & 0xf8 == mod_1_ecx_0 and aft[2] == dword_count:
                                skip = 3
                            
                            if skip is not None:
                                retvalue = dict(
                                    src_off=line.address+1,
                                    new_code=bytes((mov_reg_imm | 8 | Reg.ecx,)) + to_dword(dword_count),
                                    dest_off=next_off_2 + skip
                                )
                                retvalue.update(meta)
                                return retvalue
                            
                            meta['fixed'] = 'no'
                            return meta
                        elif len(data) == 5 and match_mov_reg_imm32(data, Reg.ecx, dword_count):
                            fpoke4(fn, line.address + 1, new_dword_count)
                            meta['fixed'] = 'yes'
                            return meta
                        elif data[0] == lea and data[1] & 0xf8 == mod_1_ecx_0 and data[2] == dword_count:
                            fpoke(fn, line.address + 2, new_dword_count)
                            meta['fixed'] = 'yes'
                            return meta
                    meta['fixed'] = 'no'
                    return meta
        return meta
    elif pre[-1] == mov_acc_mem | 1 or pre[-2] == mov_reg_rm | 1:
        # mov eax, [addr] or mov reg, [addr]
        meta['func'] = ('mov',)
        meta['str'] = 'mov'
        meta['len'] = 'no'
        if newlen <= oldlen:
            meta['fixed'] = 'not needed'
            return meta
        else:
            next_off = offset - get_start(pre)
            aft = fpeek(fn, next_off, count_after)
            if newlen+1 <= align(oldlen+1):
                r = (oldlen+1) % 4
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
                                    meta['fixed'] = 'yes'
                                    return meta
                    else:
                        if x['data'][0] == Prefix.operand_size:
                            if flag == 0:
                                move_to_reg = i
                                flag += 1
                            else:
                                move_to_mem = i
                                fpoke(fn, next_off+move_to_reg, nop)  # clear operand size prefix
                                fpoke(fn, next_off+move_to_mem, nop)  # clear operand size prefix
                                meta['fixed'] = 'yes'
                                return meta
                    assert(flag < 2)
                return meta
            else:
                x = get_length(aft, oldlen + 1)
                mach, new_ref_off = mach_memcpy(new_str_rva, x['dest'], newlen + 1)
                if x['lea'] is not None:
                    mach += mach_lea(**x['lea'])

                proc = None
                if len(mach) > x['length']:
                    # if memcpy code is to long, try to write it into the new section and make call to it
                    mach.append(ret_near)
                    proc = mach
                    
                    mach = bytes((call_near,)) + bytes(4)  # leave zeros instead of displacement for now
                    if len(mach) > x['length']:
                        # Too here there, even for just a procedure call
                        meta[fixed] = 'no'
                        return meta
                
                # Write replacement code
                mach = pad_tail(mach, x['length'], nop)
                fpoke(fn, next_off, mach)
                
                # Make deleted relocs offsets relative to the given offset
                deleted_relocs = [next_off + item - offset for item in x['deleted']]
                
                if not proc:
                    # Make new_ref relative to the given offset
                    new_ref = next_off + new_ref_off - offset
                    meta['fixed'] = 'yes'
                    retvalue = dict(deleted_relocs=deleted_relocs, new_ref=new_ref)
                    retvalue.update(meta)
                    return retvalue
                else:
                    retvalue = dict(src_off=next_off + 1, new_code=proc, deleted_relocs=deleted_relocs, new_ref=new_ref_off)
                    retvalue.update(meta)
                    return retvalue

    return meta


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
    mach += bytes((xor_rm_reg | 1, join_byte(3, Reg.ecx, Reg.ecx)))  # xor ecx, ecx
    mach += bytes((mov_reg_imm | Reg.cl, (count+3)//4))  # mov cl, (count+3)//4

    # If the destination address is not in edi yet, put it there
    if dest != (Reg.edi, 0):
        if dest[1] == 0:
            # mov edi, reg
            mach += bytes((mov_rm_reg | 1, join_byte(3, dest[0], Reg.edi)))
        else:
            # lea edi, [reg+imm]
            mach += mach_lea(Reg.edi, Operand(base_reg=dest[0], disp=dest[1]))

    mach.append(mov_reg_imm | 8 | Reg.esi)  # mov esi, ...
    new_reference = len(mach)
    mach += to_dword(src)  # imm32
    mach += bytes((Prefix.rep, movsd))  # rep movsd
    mach.append(popad)  # popad

    return mach, new_reference


def add_to_new_section(fn, dest, s, alignment=4, padding_byte=b'\0'):
    aligned = align(len(s), alignment)
    s = pad_tail(s, aligned, padding_byte)
    fpoke(fn, dest, s)
    return dest + aligned


if __name__ == '__main__':
    # from binio import TestFileObject
    # patch_unicode_table(TestFileObject(), 0)
    # print(load_trans_file(['|12\\t3|as\\rd|', '|dfg|345y|', ' ', '|||']))
    assert match_mov_reg_imm32(b'\xb9\x0a\x00\x00\x00', Reg.ecx, 0x0a)
    
