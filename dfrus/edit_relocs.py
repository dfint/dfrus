#! python3
import sys
from peclasses import PortableExecutable, RelocationTable

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

    def to_int(s):
        if s.startswith('0x'):
            return int(s[2:], 16)
        elif s.startswith('0o'):
            return int(s[2:], 8)
        else:
            return int(s)

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
                args[i] = to_int(item)

        yield op, args[list_start:]

    args = list(group_args(cmd[2:]))

    with open(cmd[1], 'r+b') as fn:
        peobj = PortableExecutable(fn)
        dd = peobj.data_directory
        sections = peobj.section_table
        reloc_rva, reloc_size = dd.basereloc
        reloc_off = sections.rva_to_offset(reloc_rva)
        relocs = set(peobj.relocation_table)

        for op, items in args:
            if op == '+':
                relocs.update(items)
            elif op == '-':
                relocs.discard(items)
            elif op == '-*':
                if len(items) < 2:
                    print('"-*" operation needs 2 arguments. Operation skipped.')
                    continue
                elif len(items) > 2:
                    print('"-*" operation needs only 2 arguments. Using only two of them: 0x%x, 0x%x.' %
                          tuple(items[:2]))
                lower_bound, upper_bound = items[:2]
                relocs_in_range = list(filter(lambda x: lower_bound <= x <= upper_bound, relocs))
                if not relocs_in_range:
                    print("No relocations in range.")
                else:
                    print("These relocations will be removed: %s" % ', '.join(hex(x) for x in sorted(relocs_in_range)))
                    relocs = set(filter(lambda x: not (lower_bound <= x <= upper_bound), relocs))
            else:
                print('Wrong operation: "%s". Skipped.' % cmd[2])

        new_reloc_table = RelocationTable.build(relocs)
        new_size = new_reloc_table.size
        assert new_size <= reloc_size

        fn.seek(reloc_off)
        new_reloc_table.to_file(fn)

        if new_size < reloc_size:
            fn.seek(reloc_off + new_size)
            fn.write(bytes(reloc_size - new_size))

        # Update data directory table
        dd.basereloc.size = new_size
        dd.rewrite()

        peobj.reread()
        assert set(peobj.relocation_table) == relocs
