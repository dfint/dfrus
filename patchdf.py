
from binio import fpoke4

def patch_unicode_table(fn, off):
    upper_a_ya = [c for c in range(0x0410, 0x0430)]
    ord_upper_a = int.from_bytes('А'.encode('cp1251'),'little')
    fpoke4(fn, off+ord_upper_a*4, upper_a_ya)
    
    lower_a_ya = [c for c in range(0x0430, 0x0460)]
    ord_lower_a = int.from_bytes('а'.encode('cp1251'),'little')
    fpoke4(fn, off+ord_lower_a*4, lower_a_ya)
    
    upper_yo = 0x0401
    ord_upper_yo = int.from_bytes('Ё'.encode('cp1251'),'little')
    fpoke4(fn, off+ord_upper_yo*4, upper_yo)
    
    lower_yo = 0x0451
    ord_lower_yo = int.from_bytes('ё'.encode('cp1251'),'little')
    fpoke4(fn, off+ord_lower_yo*4, lower_yo)

if __name__ == '__main__':
    patch_unicode_table(binio.TestFileObject(), 0)
    