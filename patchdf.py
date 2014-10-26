
import binio

def patch_unicode_table(fn, off):
    upper_a_ya = [c for c in range(0x0410, 0x0430)]
    ord_upper_a = int.from_bytes('А'.encode('cp1251'),'little')
    binio.fpoke4(fn, off+ord_upper_a*4, upper_a_ya)
    
    lower_a_ya = [c for c in range(0x0430, 0x0460)]
    ord_lower_a = int.from_bytes('а'.encode('cp1251'),'little')
    binio.fpoke4(fn, off+ord_lower_a*4, lower_a_ya)
    
    upper_yo = 0x0401
    ord_upper_yo = int.from_bytes('Ё'.encode('cp1251'),'little')
    binio.fpoke4(fn, off+ord_upper_yo*4, upper_yo)
    
    lower_yo = 0x0451
    ord_lower_yo = int.from_bytes('ё'.encode('cp1251'),'little')
    binio.fpoke4(fn, off+ord_lower_yo*4, lower_yo)

def load_trans_file(fn):
    trans = {}
    for line in fn:
        line = line.replace('\\r','\r')
        line = line.replace('\\t','\t')
        parts = line.split('|')
        if len(parts)>3 and len(parts[1])>0:
            trans[parts[1]]=parts[2]
    return trans

if __name__ == '__main__':
    patch_unicode_table(binio.TestFileObject(), 0)
    print(load_trans_file(['|12\\t3|as\\rd|', '|dfg|345y|', ' ', '|||']))
