import sys
import pe

cmd = sys.argv

# cmd.extend(["d:\Games\df_40_13_win_s\Dwarf Fortress 1.exe", "-*", "0x3fdaa0", "0x3fdb1f"])
# print(cmd)

if len(cmd) < 3:
    print('Usage:')
    print('python file.exe + 0x123 0x345 0x567 # add relocations')
    print('python file.exe - 0x123 0x345 0x567 # remove specific relocations')
    print('python file.exe -* 0x123 0x567 # remove relocations from the range')
else:
    def check_arg(item):
        # Check args for eval safety
        litem = item.lower()
        return (all(x.isdigit() for x in litem) or
                (item.startswith('0x') and all((x.isdigit() or ('a' <= x <= 'f')) for x in litem[3:])))

    def group_args(args):
        operators = {'+', '-', '-*'}
        op = None
        list_start = None
        for i, item in enumerate(args):
            if op is None or item in operators:
                if list_start is not None:
                    yield op, args[list_start:i]
                op = item
                list_start = i + 1
            elif not check_arg(item):
                print('"%s" is not decimal or hexadecimal number' % item)
                sys.exit()
            else:
                args[i] = eval(item)

        yield op, args[list_start:]

    args = list(group_args(cmd[2:]))

    with open(cmd[1], 'r+b') as fn:
        dd = pe.get_data_directory(fn)
        sections = pe.get_section_table(fn)
        reloc_off = pe.rva_to_off(dd[pe.DD_BASERELOC][0], sections)
        reloc_size = dd[pe.DD_BASERELOC][1]
        relocs = set(pe.get_relocations(fn, offset=reloc_off, size=reloc_size))

        for op, items in args:
            if op == '+':
                relocs.update(items)
            elif op == '-':
                relocs.discard(items)
            elif op == '-*':
                if len(items) < 2:
                    print('"-*" operation needs at least 2 arguments. Operation skipped.')
                    continue
                lower_bound = items[0]
                upper_bound = items[1]
                relocs = set(filter(lambda x: not (lower_bound <= x <= upper_bound), relocs))
            else:
                print('Wrong operation: "%s". Skipped.' % cmd[2])

        new_size, reloc_table = pe.relocs_to_table(relocs)
        pe.write_relocation_table(fn, reloc_off, reloc_table)
        dd[pe.DD_BASERELOC][1] = new_size
        pe.update_data_directory(fn, dd)

        if new_size < reloc_size:
            fn.seek(reloc_off + new_size)
            fn.write(b'\0' * (reloc_size - new_size))

        assert (set(pe.get_relocations(fn)) == relocs)
