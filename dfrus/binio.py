from typing import Iterable, BinaryIO, Optional, Union


def put_integer32(file_object: BinaryIO, val: int):
    file_object.write(val.to_bytes(4, byteorder='little'))


def read_bytes(file_object: BinaryIO, offset: int, count: int = 1):
    if count == 1:
        file_object.seek(offset)
        return file_object.read(1)[0]
    elif count > 1:
        file_object.seek(offset)
        return file_object.read(count)


def write_dwords(file_object: BinaryIO, dwords: Iterable[int]):
    for x in dwords:
        put_integer32(file_object, x)


def write_string(file_object: BinaryIO,
                 string: str,
                 offset: Optional[int] = None,
                 new_len: Optional[int] = None,
                 encoding: Optional[str] = None):
    
    if offset is not None:
        file_object.seek(offset)

    if new_len is None:
        new_len = len(string) + 1

    if encoding is None:
        bs = string.encode()
    else:
        bs = string.encode(encoding)

    file_object.write(bs.ljust(new_len, b'\0'))


def fpoke4(file_object: BinaryIO,
           offset: int,
           x: Union[Iterable[int], int]):
    if isinstance(x, Iterable):
        file_object.seek(offset)
        write_dwords(file_object, x)
    else:
        file_object.seek(offset)
        put_integer32(file_object, x)


def fpoke(file_object: BinaryIO,
          offset: int,
          x: Union[Iterable[int], int]):

    assert offset >= 0, offset
    if isinstance(x, Iterable):
        file_object.seek(offset)
        file_object.write(bytes(to_unsigned(item, 8) for item in x))
    else:
        file_object.seek(offset)
        file_object.write(bytes([to_unsigned(x, 8)]))


def to_signed(x: int, width: int) -> int:
    pow2w = 2 ** width
    assert (x < pow2w)
    if x & (pow2w // 2):
        x -= pow2w
    return x


def to_unsigned(x: int, width: int) -> int:
    pow2w = 2 ** width
    if x < 0:
        x += pow2w
    assert (x < pow2w)
    return x


def from_dword(b: bytes, signed=False, byteorder='little'):
    assert len(b) == 4
    return int.from_bytes(b, byteorder=byteorder, signed=signed)


def to_dword(x: int, signed=False, byteorder='little'):
    return x.to_bytes(length=4, byteorder=byteorder, signed=signed)
