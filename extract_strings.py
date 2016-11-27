#! python3

import sys
from peclasses import PortableExecutable
from patchdf import get_cross_references
from collections import Counter
from disasm import align

forbidden = set(b'$^')

allowed = set(b'\r\t')


def is_allowed(x):
    return x in allowed or (ord(' ') <= x and x not in forbidden)


def possible_to_decode(c, encoding):
    try:
        c.decode(encoding=encoding)
    except UnicodeDecodeError:
        return False
    else:
        return True


def check_string_array(buf, offset, encoding='cp437'):
    start = None
    end = None
    for i, c in enumerate(buf):
        if c:
            if end:
                yield (offset + start, buf[start:end], i - start - 1)
                start = None
                end = None
            
            if not is_allowed(c) or not possible_to_decode(buf[i:i+1], encoding):
                if start:
                    start = None
                continue
            
            if start is None:
                start = i
                end = None
        elif start is not None and not end:
            end = i
    
    if end:
        yield (offset + start, buf[start:end], len(buf) - start - 1)


def count_zeros(buf):
    for i, item in enumerate(buf):
        if item:
            return i
    
    return len(buf)


def find_next_string_xref(s_xrefs, i, obj_off):
    i += 1
    if i >= len(s_xrefs):
        return -1
    
    while s_xrefs[i] <= obj_off:
        i += 1
        if i >= len(s_xrefs):
            return -1
    
    return s_xrefs[i]


def extract_strings(fn, xrefs, blocksize=4096, encoding='cp437', arrays=False):
    prev_string = None
    s_xrefs = sorted(xrefs)
    for i, obj_off in enumerate(s_xrefs):
        if prev_string is not None and obj_off <= prev_string[0]+len(prev_string[1]):
            continue  # it's not the beginning of the string
        
        fn.seek(obj_off)
        buf = fn.read(blocksize)
        
        s_len = None
        letters = 0
        for i, c in enumerate(buf):
            if c == 0:
                s_len = i
                break
            
            if not is_allowed(c) or not possible_to_decode(buf[i:i+1], encoding):
                break
            elif buf[i:i+1].isalpha():
                letters += 1
        
        if s_len and letters > 0:
            s = buf[:s_len].decode(encoding=encoding)
            
            if not arrays:
                cap_len = align(len(s) + 1)
                current_string = (obj_off, s, cap_len)
                yield current_string
            else:
                upper_bound = find_next_string_xref(s_xrefs, i, obj_off + s_len)
                buf = buf[s_len:upper_bound]
                cap_len = s_len + count_zeros(buf) - 1
                current_string = (obj_off, s, cap_len)
                yield current_string

                for off, s, cap_len in check_string_array(buf, obj_off + s_len, encoding):
                    current_string = (off, s.decode(encoding=encoding), cap_len)
                    yield current_string
            
            prev_string = current_string


def myrepr(s):
    text = repr(s)
    if sys.stdout:
        b = text.encode(sys.stdout.encoding, 'backslashreplace')
        text = b.decode(sys.stdout.encoding, 'strict')
    return text


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print('Usage:\nextract_strings.py "Dwarf Fortress.exe" output.txt [encoding]', file=sys.stderr)
    else:
        try:
            with open(sys.argv[1], "r+b") as fn:
                pe = PortableExecutable(fn)
                image_base = pe.optional_header.image_base
                sections = pe.section_table
                relocs = pe.relocation_table
                xrefs = get_cross_references(fn, relocs, sections, image_base)
                encoding = 'cp437' if len(sys.argv)<=3 else sys.argv[3]
                strings = list(extract_strings(fn, xrefs, encoding=encoding))
                count = Counter(x[1] for x in strings)
                with open(sys.argv[2], 'wt', encoding=encoding, errors='strict') as dump:
                    for offset, s, cap_len in strings:
                        if count[s] >= 1:
                            assert cap_len >= len(s)
                            s = s.replace('\r', '\\r')
                            s = s.replace('\t', '\\t')
                            print(hex(offset), myrepr(s), cap_len)
                            print(s, file=dump)
                            count[s] = 0
        except OSError:
            print("Failed to open '%s'" % sys.argv[1], file=sys.stderr)
            input("Press Enter...", file=sys.stderr)
            sys.exit()
