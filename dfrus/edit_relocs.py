import sys
from ast import literal_eval

from .peclasses import PortableExecutable, RelocationTable


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
        else:
            try:
                arg = literal_eval(item)
                assert isinstance(arg, int)
            except (ValueError, AssertionError):
                print(f'{item!r} is not an integer number')
                raise

            args[i] = arg

    yield op, args[list_start:]


def main():
    cmd = sys.argv

    # cmd.extend(["d:\Games\df_40_13_win_s\Dwarf Fortress 1.exe", "-*", "0x3fdaa0", "0x3fdb1f"])
    # print(cmd)

    if len(cmd) < 3:
        print('Usage:')
        print('python file.exe + 0x123 0x345 0x567 # add relocations')
        print('python file.exe - 0x123 0x345 0x567 # remove specific relocations')
        print('python file.exe -* 0x123 0x567 # remove relocations from the range')
    else:
        args = list(group_args(cmd[2:]))

        with open(cmd[1], 'r+b') as fn:
            peobj = PortableExecutable(fn)
            data_directory = peobj.data_directory
            sections = peobj.section_table
            reloc_rva, reloc_size = data_directory.basereloc
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
                        print('"-*" operation needs only 2 arguments. Using only two of them: 0x{:X}, 0x{:X}.'.format(
                            *items[:2]))
                    lower_bound, upper_bound = items[:2]
                    relocs_in_range = list(filter(lambda x: lower_bound <= x <= upper_bound, relocs))
                    if not relocs_in_range:
                        print("No relocations in range.")
                    else:
                        print("These relocations will be removed: %s" % ', '
                              .join(hex(x)for x in sorted(relocs_in_range)))
                        relocs = set(filter(lambda x: not (lower_bound <= x <= upper_bound), relocs))
                else:
                    print('Wrong operation: "%s". Skipped.' % cmd[2])

            new_relocation_table = RelocationTable.build(relocs)
            new_size = new_relocation_table.size
            assert new_size <= reloc_size

            fn.seek(reloc_off)
            new_relocation_table.to_file(fn)

            if new_size < reloc_size:
                # Clear empty bytes after the relocation table
                fn.seek(reloc_off + new_size)
                fn.write(bytes(reloc_size - new_size))

            # Update data directory table
            data_directory.basereloc.size = new_size
            data_directory.rewrite()

            peobj.reread()
            assert set(peobj.relocation_table) == relocs


if __name__ == '__main__':
    main()
