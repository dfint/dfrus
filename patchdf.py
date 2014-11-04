
from binio import fpoke4, fpeek4u
from pe import rva_to_off

def patch_unicode_table(fn, off):
    upper_a_ya = [c for c in range(0x0410, 0x0430)]
    assert(len(upper_a_ya)==0x20)
    ord_upper_a = int.from_bytes('А'.encode('cp1251'),'little')
    fpoke4(fn, off+ord_upper_a*4, upper_a_ya)
    
    lower_a_ya = [c for c in range(0x0430, 0x0450)]
    assert(len(lower_a_ya)==0x20)
    ord_lower_a = int.from_bytes('а'.encode('cp1251'),'little')
    fpoke4(fn, off+ord_lower_a*4, lower_a_ya)
    
    upper_yo = 0x0401
    ord_upper_yo = int.from_bytes('Ё'.encode('cp1251'),'little')
    fpoke4(fn, off+ord_upper_yo*4, upper_yo)
    
    lower_yo = 0x0451
    ord_lower_yo = int.from_bytes('ё'.encode('cp1251'),'little')
    fpoke4(fn, off+ord_lower_yo*4, lower_yo)

def load_trans_file(fn):
    trans = {}
    for line in fn:
        line = line.replace('\\r','\r')
        line = line.replace('\\t','\t')
        parts = line.split('|')
        if len(parts)>3 and len(parts[1])>0:
            trans[parts[1]]=parts[2]
    return trans

from collections import defaultdict

code = 0
rdata = 1
data = 2
def get_cross_references(fn, relocs, sections, image_base):
    xrefs = defaultdict(list)
    for reloc in relocs:
        reloc -= sections[code].rva
        if reloc < 0 and reloc >= sections[code].virtual_size:
            continue
        reloc += sections[code].physical_offset
        obj_rva = fpeek4u(fn, reloc) - image_base
        obj_off = rva_to_off(obj_rva, sections)
        if obj_off is None:
            continue
        if (obj_off >= sections[rdata].physical_offset and
            obj_off < sections[data].physical_offset+sections[data].physical_size):
                xrefs[obj_off].append(reloc)
    return xrefs

if __name__ == '__main__':
    from binio import TestFileObject
    patch_unicode_table(TestFileObject(), 0)
    print(load_trans_file(['|12\\t3|as\\rd|', '|dfg|345y|', ' ', '|||']))
