from ast import literal_eval
from functools import partial
from typing import BinaryIO, Callable, List, Sequence, Set

import click
from peclasses.portable_executable import PortableExecutable
from peclasses.relocation_table import RelocationTable


def int_literal_converter(value: str) -> int:
    try:
        arg = literal_eval(value)
        assert isinstance(arg, int)
        return arg
    except (ValueError, AssertionError):
        print(f"{value!r} is not an integer number")
        raise


def list_int_literal_converter(values: List[str]) -> List[int]:
    return list(map(int_literal_converter, values))


def common(file: BinaryIO, function: Callable[[Set[int]], Set[int]]):
    pe = PortableExecutable(file)
    data_directory = pe.data_directory
    sections = pe.section_table
    reloc_rva, reloc_size = data_directory.basereloc
    reloc_off = sections.rva_to_offset(reloc_rva)
    relocs = set(pe.relocation_table)

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
    pe.rewrite_data_directory()

    pe.reread()
    assert set(pe.relocation_table) == relocs


def add_items(items: Sequence[int], relocs: Set[int]) -> Set[int]:
    return relocs | set(items)


def remove_items(items: Sequence[int], relocs: Set[int]) -> Set[int]:
    return relocs - set(items)


def remove_range(items: Sequence[int], relocs: Set[int]) -> Set[int]:
    if len(items) < 2:
        print("Range remove operation needs 2 arguments. Operation skipped.")
        return relocs
    elif len(items) > 2:
        print(
            "Range remove operation needs only 2 arguments. Using only two of them: 0x{:X}, 0x{:X}.".format(*items[:2])
        )
    lower_bound, upper_bound = items[:2]
    relocs_in_range = list(filter(lambda x: lower_bound <= x <= upper_bound, relocs))
    if not relocs_in_range:
        print("No relocations in range.")
        return relocs
    else:
        print("These relocations will be removed:", ", ".join(hex(x) for x in sorted(relocs_in_range)))
        return set(filter(lambda x: not (lower_bound <= x <= upper_bound), relocs))


@click.command()
@click.argument("file", type=click.File(mode="rb+"))
@click.argument("command", type=click.Choice(["add", "remove", "remove_range"]))
@click.argument(
    "items", nargs=-1, type=str, required=True, callback=lambda _, __, values: list_int_literal_converter(values)
)
def _main(file: BinaryIO, command: str, items: List[int]):
    function = None
    if command == "add":
        function = partial(add_items, items)
    elif command == "remove":
        function = partial(remove_items, items)
    elif command == "remove_range":
        function = partial(remove_range, items)

    if function:
        common(file, function)


if __name__ == "__main__":
    _main()
