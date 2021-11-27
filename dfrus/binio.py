from typing import Iterable, BinaryIO, Optional, Union

from .type_aliases import Offset


def write_dword(file_object: BinaryIO, val: int) -> None:
    file_object.write(val.to_bytes(4, byteorder="little"))


def read_bytes(file_object: BinaryIO, offset: Offset, count: int = 1) -> bytes:
    file_object.seek(offset)
    return file_object.read(count)


def write_dwords(file_object: BinaryIO, dwords: Iterable[int]) -> None:
    for x in dwords:
        write_dword(file_object, x)


def write_string(file_object: BinaryIO,
                 string: str,
                 offset: Optional[int] = None,
                 new_len: Optional[int] = None,
                 encoding: Optional[str] = None) -> None:
    
    if offset is not None:
        file_object.seek(offset)

    if new_len is None:
        new_len = len(string) + 1

    if encoding is None:
        bs = string.encode()
    else:
        bs = string.encode(encoding)

    file_object.write(bs.ljust(new_len, b"\0"))


def fpoke4(file_object: BinaryIO,
           offset: Offset,
           x: Union[int, Iterable[int]]) -> None:

    file_object.seek(offset)
    if isinstance(x, int):
        write_dword(file_object, x)
    else:
        write_dwords(file_object, x)


def fpoke(file_object: BinaryIO,
          offset: Offset,
          x: Union[int, Iterable[int]]):

    assert offset >= 0, offset
    file_object.seek(offset)
    if isinstance(x, int):
        file_object.write(bytes([to_unsigned(x, 8)]))
    else:
        file_object.write(bytes(to_unsigned(item, 8) for item in x))


def to_signed(x: int, width: int) -> int:
    pow2w = 2 ** width
    assert (x < pow2w)
    if x & (pow2w // 2):
        x -= pow2w
    return x


def to_unsigned(x: int, width: int) -> int:
    """
    Convert signed value into unsigned
    :param x: original value
    :param width in bits
    """
    pow2w = 2 ** width
    if x < 0:
        x += pow2w
    assert 0 <= x < pow2w
    return x


def from_dword(b: bytes, signed=False, byteorder="little") -> int:
    assert len(b) == 4
    return int.from_bytes(b, byteorder=byteorder, signed=signed)


def to_dword(x: int, signed=False, byteorder="little") -> bytes:
    return x.to_bytes(length=4, byteorder=byteorder, signed=signed)
