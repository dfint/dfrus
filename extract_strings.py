#! python3

forbidden = set("$;@^{}")

allowed = set("\r\t")


def is_allowed(x):
    return x in allowed or (' ' <= x < chr(127) and x not in forbidden)


def extract_strings(fn, xrefs, blocksize=1024):
    prev_string = None
    for obj_off in sorted(xrefs):
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
            elif not is_allowed(chr(c)):
                break
            elif chr(c).isalpha():
                letters += 1
        
        if s_len and letters > 0:
            current_string = (obj_off, buf[:s_len].decode())
            yield current_string
            prev_string = current_string

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print('Usage:\nextract_strings.py "Dwarf Fortress.exe" > stringdump.txt', file=sys.stderr)
    else:
        try:
            fn = open(sys.argv[1], "r+b")
        except OSError:
            print("Failed to open '%s'" % sys.argv[1], file=sys.stderr)
            input("Press Enter...")
            sys.exit()
        from peclasses import PortableExecutable
        from patchdf import get_cross_references
        from collections import Counter
        pe = PortableExecutable(fn)
        image_base = pe.optional_header.image_base
        sections = pe.section_table
        relocs = pe.relocation_table
        xrefs = get_cross_references(fn, relocs, sections, image_base)
        strings = list(extract_strings(fn, xrefs))
        count = Counter(x[1] for x in strings)
        for _, s in strings:
            if count[s] == 1:
                s = s.replace('\r', '\\r')
                s = s.replace('\t', '\\t')
                print(s)
