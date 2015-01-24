import sys
import pe

cmd = sys.argv

cmd.extend(["d:\Games\df_40_13_win_s\Dwarf Fortress 1.exe", "-*", "0x3fdaa0", "0x3fdb1f"])
print(cmd)

if len(cmd) < 3:
    print('Usage:')
    print('python file.exe + 0x123 0x345 0x567 # add relocations')
    print('python file.exe - 0x123 0x345 0x567 # remove specific relocations')
    print('python file.exe -* 0x123 0x567 # remove relocations from the range')
else:
    # Check args for safety
    for item in cmd[3:]:
        litem = item.lower()
        if not(all(x>='0' and x<='9' for x in litem) or (item.startswith('0x') and all((x>='0' and x<='9') or
                (x>='a' and x<='f') for x in litem[3:]))):
            print('"%s" is not decimal or hexadecimal number' % item)
            break
    else:
        with open(cmd[1], 'r+b') as fn:
            dd = pe.get_data_directory(fn)
            sections = pe.get_section_table(fn)
            reloc_off = pe.rva_to_off(dd[pe.DD_BASERELOC][0], sections)
            reloc_size = dd[pe.DD_BASERELOC][1]
            relocs = pe.get_relocations(fn, offset=reloc_off, size=reloc_size)
            
            if cmd[2] == '+':
                relocs.update(eval(x) for x in cmd[3:])
            elif cmd[2] == '-':
                relocs.discard(eval(x) for x in cmd[3:])
            elif cmd[2] == '-*':
                lower_bound = eval(cmd[3])
                upper_bound = eval(cmd[4])
                relocs = set(filter(lambda x: not (x>=lower_bound and x<=upper_bound), relocs))
            else:
                print('Wrong operation: "%s"' % cmd[2])
                sys.abort(0)
            
            size, reloc_table = pe.relocs_to_table(relocs)
            pe.write_relocation_table(fn, reloc_off, reloc_table)
            dd[pe.DD_BASERELOC][1] = size
            pe.update_data_directory(fn, dd)
            
            assert(pe.get_relocations(fn) == relocs)


