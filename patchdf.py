
from binio import fpoke4, fpeek4u, fpeek
from pe import rva_to_off
from opcodes import *
from disasm import *


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
            disp = signed(int.from_bytes(aft[1:5], byteorder='little'), 32)
            next_off += 5 + disp
        jmp = aft[0]
        aft = fpeek(fn, next_off, count_after)
    elif aft[0] == call_near or aft[0] & 0xf0 == jcc_short or (aft[0] == 0x0f and aft[1] == x0f_jcc_near):
        aft = None

    if pre[-1] == push_imm32:
        # push offset str
        pass
    elif pre[-1] & 0xF8 == (mov_reg_imm | 8):
        # mov reg32, offset str
        reg = pre[-1] & 7
        if reg == Reg.eax:
            if int.from_bytes(pre[-5:-2], byteorder='little') == oldlen:
                pass
            elif pre[-3] == push_imm8 and pre[-2] == oldlen:
                pass
            elif aft and aft[0] == push_imm8 and aft[1] == oldlen:
                pass
            elif pre[-2] == mov_reg_rm+1 and pre[-1] & 0xf8 == join_byte(3, Reg.edi, 0):
                pass
            elif aft and aft[0] == mov_reg_imm | 8 | Reg.edi and int.from_bytes(aft[1:5], byteorder='little') == oldlen:
                pass
            elif pre[-4] == lea and pre[-3] & 0xf8 == join_byte(1, Reg.edi, 0):
                pass
            elif aft and aft[0] == mov_reg_rm | 1 and aft[1] & 0xf8 == join_byte(3, Reg.ecx, 0):
                pass
        elif reg == Reg.esi:
            pass
        return -1  # Assume that there no need to fix
    elif pre[-1] == mov_acc_mem | 1 or pre[-2] == mov_reg_rm | 1:
        pass

    return -1

if __name__ == '__main__':
    from binio import TestFileObject
    patch_unicode_table(TestFileObject(), 0)
    print(load_trans_file(['|12\\t3|as\\rd|', '|dfg|345y|', ' ', '|||']))
