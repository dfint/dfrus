#! python3

import sys
from peclasses import PortableExecutable
from patchdf import get_cross_references
from collections import Counter

forbidden = set("$;@^{}")

allowed = set("\r\t")


def is_allowed(x):
    return x in allowed or (' ' <= x < chr(127) or x.isalpha() and x not in forbidden)


def check_string_array(buf, offset):
    start = None
    for i, c in enumerate(buf):
        if c != 0:
            if not is_allowed(chr(c)):
                break
            if not start:
                start = i
        elif start:
            yield (offset + start, buf[start:i])
            start = None


def extract_strings(fn, xrefs, blocksize=4096, encoding='cp437'):
    prev_string = None
    s_xrefs = sorted(xrefs)
    for j, obj_off in enumerate(s_xrefs):
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
            c = buf[i:i+1].decode(encoding=encoding, errors='ignore')
            if not is_allowed(c):
                break
            elif c.isalpha():
                letters += 1
        
        if s_len and letters > 0:
            current_string = (obj_off, buf[:s_len].decode(encoding=encoding))
            yield current_string
            
            upper_bound = (s_xrefs[j + 1] - obj_off) if j < len(s_xrefs) - 1 else -1
            buf = buf[:upper_bound]
            for off, s in check_string_array(buf[s_len:], obj_off + s_len):
                prev_string = current_string
                current_string = (off, s.decode(encoding=encoding))
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
                print(encoding)
                strings = list(extract_strings(fn, xrefs, encoding=encoding))
                count = Counter(x[1] for x in strings)
                with open(sys.argv[2], 'wt', encoding=encoding, errors='strict') as dump:
                    for _, s in strings:
                        if count[s] >= 1:
                            s = s.replace('\r', '\\r')
                            s = s.replace('\t', '\\t')
                            print(myrepr(s))
                            print(s, file=dump)
                            count[s] = 0
        except OSError:
            print("Failed to open '%s'" % sys.argv[1], file=sys.stderr)
            input("Press Enter...", file=sys.stderr)
            sys.exit()
