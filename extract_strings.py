
forbidden = set("$;@^`{|}")

allowed = set("\r\t")


def is_allowed(x):
    return x in allowed or (x >= ' ' and x < chr(127) and x not in forbidden)


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
        from binio import fpeek4u
        from pe import *
        from patchdf import get_cross_references
        pe_offset = check_pe(fn)
        image_base = fpeek4u(fn, pe_offset+PE_IMAGE_BASE)
        sections = get_section_table(fn, pe_offset)
        relocs = get_relocations(fn, sections)
        xrefs = get_cross_references(fn, relocs, sections, image_base)
        strings = extract_strings(fn, xrefs)
        for _, s in strings:
            s = s.replace('\r', '\\r')
            s = s.replace('\t', '\\t')
            print('|%s|' % s)
