import sys
from ast import literal_eval
from functools import partial
from typing import Callable, Set, BinaryIO, Mapping, Sequence, Iterable

from .peclasses import PortableExecutable, RelocationTable


def group_args(args) -> Mapping[str, Sequence[int]]:
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


def common(file: BinaryIO, functions: Iterable[Callable[[Set[int]], Set[int]]]):
    pe = PortableExecutable(file)
    data_directory = pe.data_directory
    sections = pe.section_table
    reloc_rva, reloc_size = data_directory.basereloc
    reloc_off = sections.rva_to_offset(reloc_rva)
    relocs = set(pe.relocation_table)

    for function in functions:
        relocs = function(relocs)

    new_relocation_table = RelocationTable.build(relocs)
    new_size = new_relocation_table.size
    assert new_size <= reloc_size

    file.seek(reloc_off)
    new_relocation_table.to_file(file)

    if new_size < reloc_size:
        # Clear empty bytes after the relocation table
        file.seek(reloc_off + new_size)
        file.write(bytes(reloc_size - new_size))

    # Update data directory table
    data_directory.basereloc.size = new_size
    data_directory.rewrite()

    pe.reread()
    assert set(pe.relocation_table) == relocs


def add_items(items: Sequence[int], relocs: Set[int]) -> Set[int]:
    relocs.update(items)
    return relocs


def remove_items(items: Sequence[int], relocs: Set[int]) -> Set[int]:
    relocs.difference(items)
    return relocs


def remove_range(items: Sequence[int], relocs: Set[int]) -> Set[int]:
    if len(items) < 2:
        print('"-*" operation needs 2 arguments. Operation skipped.')
        return relocs
    elif len(items) > 2:
        print('"-*" operation needs only 2 arguments. Using only two of them: 0x{:X}, 0x{:X}.'.format(
            *items[:2]))
    lower_bound, upper_bound = items[:2]
    relocs_in_range = list(filter(lambda x: lower_bound <= x <= upper_bound, relocs))
    if not relocs_in_range:
        print("No relocations in range.")
        return relocs
    else:
        print("These relocations will be removed: %s" % ', '
              .join(hex(x) for x in sorted(relocs_in_range)))
        return set(filter(lambda x: not (lower_bound <= x <= upper_bound), relocs))


def _main():
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

        functions = []
        for op, items in args:
            if op == '+':
                functions.append(partial(add_items, items))
            elif op == '-':
                functions.append(partial(remove_items, items))
            elif op == '-*':
                functions.append(partial(remove_range, items))
            else:
                print('Wrong operation: "%s". Skipped.' % cmd[2])

        with open(cmd[1], 'r+b') as fn:
            common(fn, functions)


if __name__ == '__main__':
    _main()
