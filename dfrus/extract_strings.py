from collections import Counter
from typing import Tuple, cast, NamedTuple, Optional, List, Iterator

import click
from peclasses.portable_executable import PortableExecutable

from dfrus.cross_references import get_cross_references
from dfrus.disasm import align
from dfrus.pretty_printing import myrepr
from dfrus.type_aliases import Offset

forbidden = set(b"$^")

allowed = set(b"\r\t")


def is_allowed(x):
    return x in allowed or (ord(" ") <= x and x not in forbidden)


def possible_to_decode(c, encoding):
    try:
        c.decode(encoding=encoding)
    except UnicodeDecodeError:
        return False
    else:
        return True


def check_string(buf: bytes, encoding: str) -> Tuple[int, int]:
    """
    Try to decode bytes as a string in the given encoding
    :param buf: byte buffer
    :param encoding: string encoding
    :return: (string_length: int, number_of_letters: int)
    """
    string_length = 0
    number_of_letters = 0
    for i, c in enumerate(buf):
        if c == 0:
            string_length = i
            break

        current_byte = bytes(buf[i : i + 1])
        if not is_allowed(c) or not possible_to_decode(current_byte, encoding):
            break
        elif current_byte.isalpha():
            number_of_letters += 1

    return string_length, number_of_letters


def check_string_array(buf, offset, encoding="cp437"):
    start = None
    end = None
    for i, c in enumerate(buf):
        if c:
            if end:
                yield offset + start, buf[start:end], i - start - 1
                start = None
                end = None

            if not is_allowed(c) or not possible_to_decode(buf[i : i + 1], encoding):
                if start:
                    start = None
                continue

            if start is None:
                start = i
                end = None
        elif start is not None and not end:
            end = i
    else:
        if end:
            assert start is not None
            yield offset + start, buf[start:end], len(buf) - start - 1


def find_next_string_xref(s_xrefs, i, obj_off):
    i += 1
    if i >= len(s_xrefs):
        return -1

    while s_xrefs[i] <= obj_off:
        i += 1
        if i >= len(s_xrefs):
            return -1

    return s_xrefs[i]


class ExtractedStringInfo(NamedTuple):
    offset: Offset
    string: str
    cap_length: int


def extract_strings(fn, xrefs, block_size=4096, encoding="cp437", arrays=False) -> Iterator[ExtractedStringInfo]:
    prev_string: Optional[ExtractedStringInfo] = None
    current_string: Optional[ExtractedStringInfo] = None
    s_xrefs = sorted(xrefs)
    for i, obj_off in enumerate(s_xrefs):
        if prev_string is not None and obj_off <= prev_string.offset + len(prev_string.string):
            continue  # it's not the beginning of the string

        fn.seek(obj_off)
        buf = fn.read(block_size)

        s_len, letters = check_string(buf, encoding)

        if s_len and letters > 0:
            if not arrays:
                s = buf[:s_len].decode(encoding=encoding)
                cap_len = align(len(s) + 1)
                current_string = ExtractedStringInfo(obj_off, s, cap_len)
                yield current_string
            else:
                upper_bound = find_next_string_xref(s_xrefs, i, obj_off + s_len) - obj_off
                buf = buf[:upper_bound]

                string_array = list(check_string_array(buf, obj_off, encoding))
                if not all(cap_len == string_array[0][2] for _, _, cap_len in string_array):
                    # cap_len = align(len(s) + 1)
                    s = buf[:s_len].decode(encoding=encoding)
                    cap_len = align(len(s) + 1)
                    current_string = ExtractedStringInfo(obj_off, s, cap_len)
                    yield current_string
                else:
                    for off, s, cap_len in string_array:
                        current_string = ExtractedStringInfo(off, s.decode(encoding=encoding), cap_len)
                        yield current_string

            prev_string = current_string


@click.command()
@click.option("--ascii", "ascii_only", is_flag=True, default=False, help="Extract only ascii based strings")
@click.option(
    "--sort-by-xref", "sort_by_xref", is_flag=True, default=False, help="Sort extracted strings by cross-reference"
)
@click.argument("executable", type=click.File("rb"))
@click.argument("output_file", type=click.Path(exists=False))
@click.argument("encoding", default="cp437")
def _main(ascii_only, executable, output_file, encoding, sort_by_xref):
    """
    Extract strings embedded into a portable executable file (exe)
    """
    pe = PortableExecutable(executable)

    xrefs = get_cross_references(
        executable, pe.relocation_table, pe.section_table, cast(int, pe.optional_header.image_base)
    )

    strings: List[ExtractedStringInfo] = list(extract_strings(executable, xrefs, encoding=encoding, arrays=True))
    count = Counter(x.string for x in strings)

    if sort_by_xref:
        strings = sorted(strings, key=lambda s: min(xrefs.get(s.offset, [0])))

    with open(output_file, "wt", encoding=encoding, errors="strict") as dump:
        for offset, string, cap_len in strings:
            if count[string] >= 1:
                if ascii_only and any(ord(c) >= 0x80 for c in string):
                    # Skip non-ascii characters
                    continue

                assert cap_len >= len(string)
                string = string.replace("\r", "\\r")
                string = string.replace("\t", "\\t")
                print(hex(offset), myrepr(string), cap_len, xrefs[offset])
                print(string, file=dump)
                count[string] = 0


if __name__ == "__main__":
    _main()
