
def get_integer32(file_object):
    return int.from_bytes(file_object.read(4), byteorder='little')


def get_integer16(file_object):
    return int.from_bytes(file_object.read(2), byteorder='little')


def put_integer32(file_object, val):
    file_object.write(val.to_bytes(4, byteorder='little'))


def put_integer16(file_object, val):
    file_object.write(val.to_bytes(2, byteorder='little'))


def put_integer8(file_object, val):
    file_object.write(val.to_bytes(1, byteorder='little'))


def fpeek(file_object, off, count=1):
    if count == 1:
        file_object.seek(off)
        return file_object.read(1)[0]
    elif count > 1:
        file_object.seek(off)
        return file_object.read(count)


def get_dwords(file_object, count):
    return [get_integer32(file_object) for _ in range(count)]


def get_words(file_object, count):
    return [get_integer16(file_object) for _ in range(count)]


def write_dwords(file_object, dwords):
    for x in dwords:
        put_integer32(file_object, x)


def write_words(file_object, words):
    for x in words:
        put_integer16(file_object, x)


def pad_tail(target, size, ch=None):
    if ch is None:
        if type(target) is str:
            ch = ' '
        else:
            ch = b'\0'
    elif type(ch) is int:
        if type(target) is str:
            ch = chr(ch)
        else:
            ch = bytes((ch,))
            
    if len(target) < size:
        target += ch*(size-len(target))
    return target


def write_string(file_object, s, off=None, new_len=None, encoding=None):
    if off is not None:
        file_object.seek(off)
    
    if new_len is None:
        new_len = len(s)+1

    if encoding is None:
        s = s.encode()
    else:
        s = s.encode(encoding)

    file_object.write(pad_tail(s, new_len, b'\0'))


def fpeek4u(file_object, off, count=1):
    if count == 1:
        file_object.seek(off)
        return get_integer32(file_object)
    elif count > 1:
        file_object.seek(off)
        return [get_integer32(file_object) for _ in range(count)]


def fpeek2u(file_object, off, count=1):
    if count == 1:
        file_object.seek(off)
        return get_integer16(file_object)
    elif count > 1:
        file_object.seek(off)
        return [get_integer16(file_object) for _ in range(count)]

import collections


def fpoke4(file_object, off, x):
    if isinstance(x, collections.Iterable):
        file_object.seek(off)
        write_dwords(file_object, x)
    else:
        file_object.seek(off)
        put_integer32(file_object, x)


def fpoke2(file_object, off, x):
    if isinstance(x, collections.Iterable):
        file_object.seek(off)
        write_words(file_object, x)
    else:
        file_object.seek(off)
        put_integer16(file_object, x)


def fpoke(file_object, off, x):
    if isinstance(x, collections.Iterable):
        file_object.seek(off)
        file_object.write(bytes(to_unsigned(item, 8) for item in x))
    else:
        file_object.seek(off)
        file_object.write(bytes([to_unsigned(x, 8)]))


import random


class TestFileObject(object):
    def __init__(self):
        self.position = 0
        
    def read(self, n):
        self.position += n
        return bytes(int(random.random()*256) for _ in range(n))
    
    def write(self, s):
        print('Writing %d bytes at position 0x%X:' % (len(s), self.position))
        print(' '.join('0x%02X' % x for x in s))
        self.position += len(s)
    
    def seek(self, n):
        self.position = n
        return n
        
    def tell(self):
        return self.position


def to_signed(x, width):
    pow2w = 2**width
    assert(x < pow2w)
    if x & (pow2w//2):
        x -= pow2w
    return x


def to_unsigned(x, width):
    pow2w = 2**width
    if x < 0:
        x += pow2w
    assert(x < pow2w)
    return x


def from_dword(b, signed=False, byteorder='little'):
    assert len(b) == 4
    return int.from_bytes(b, byteorder=byteorder, signed=signed)


def to_dword(x, byteorder='little'):
    return x.to_bytes(length=4, byteorder=byteorder)


if __name__ == "__main__":
    fn = TestFileObject()
    # fn = open("test.bin","r+b")
    put_integer32(fn, 0xDEADBEEF)
    put_integer16(fn, 0xBAAD)
    put_integer8(fn, 0xAB)
    write_string(fn, "1234")
    # fn.seek(0)
    print(get_dwords(fn, 2))
    print(get_words(fn, 3))
