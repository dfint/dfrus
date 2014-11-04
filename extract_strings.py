
blocksize = 1024

forbidden = set("$;@^`{|}")

allowed = set("\r\t")

def is_allowed(x):
    return x in allowed or (x>' ' and x<chr(127) and x not in forbidden)

def extract_strings(fn, xrefs):
    strings = []
    for obj_off in sorted(xrefs):
        if strings and obj_off <= strings[-1][0]+len(strings[-1][1]):
            continue # it's not the beginning of the string
        
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
                letters+=1
        
        if s_len and letters > 0:
            strings.append((obj_off, buf[:s_len].decode()))
    
    return strings
