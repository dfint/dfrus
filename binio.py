
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

def fpeek(file_object, off, count = 1):
    if count == 1:
        file_object.seek(off)
        return int(file_object.read(1))
    elif count > 1:
        file_object.seek(off)
        return file_object.read(count)

def get_dwords(file_object, count):
    return [get_integer32(file_object) for i in range(count)]
    
def get_words(file_object, count):
    return [get_integer16(file_object) for i in range(count)]

def write_dwords(file_object, dwords):
    for x in dwords:
        put_integer32(file_object, x)

def write_words(file_object, words):
    for x in words:
        put_integer16(file_object, x)

def write_string(file_object, s):
    file_object.write(s.encode())

def fpeek4u(file_object, off, count = 1):
    if count == 1:
        file_object.seek(off)
        return get_integer32(file_object)
    elif count > 1:
        file_object.seek(off)
        return [get_integer32(file_object) for i in range(count)]

def fpeek2u(file_object, off, count = 1):
    if count == 1:
        file_object.seek(off)
        return get_integer16(file_object)
    elif count > 1:
        file_object.seek(off)
        return [get_integer16(file_object) for i in range(count)]

if __name__ == "__main__":
    import sys
    import random
    class TestFileObject(object):
        def read(self, n):
            return [int(random.random()*256) for i in range(n)]
        
        def seek(self, n):
            pass
    put_integer32(sys.stdout, 0x30313233)
    print()
    put_integer16(sys.stdout, 0x3435)
    print()
    put_integer8(sys.stdout, 0x36)
    print()
    write_string(sys.stdout, "123")
    print()
    fn = TestFileObject()
    print(get_dwords(fn,3))
    print()
    print(get_words(fn,3))
