
def from_bytes(s):
    assert(len(s)<=4)
    x = 0
    for i in s:
        x <<= 8
        x += i
    return x


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
        return int(file_object.read(1))
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


def write_string(file_object, s, off=None, new_len=None, encoding=None):
    if off is not None:
        file_object.seek(off)
    
    if new_len is None:
        new_len = len(s)+1
    
    if new_len > len(s):
        s += '\0'*(len(s)-new_len)
    
    if encoding is None:
        file_object.write(s.encode())
    else:
        file_object.write(s.encode(encoding))


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


def fpoke(file_object, off, x):
    if isinstance(x, collections.Iterable):
        file_object.seek(off)
        for item in x:
            file_object.write(item)
    else:
        file_object.seek(off)
        file_object.write(x)

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
