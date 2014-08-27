
def get_integer32(file_object):
    return int.from_bytes(file_object.read(4), byteorder='little')

def get_integer16(file_object):
    return int.from_bytes(file_object.read(2), byteorder='little')

def fpeek(file_object, off, count = 1):
    if count == 1:
        file_object.seek(off)
        return int(file_object.read(1))
    elif count > 1:
        file_object.seek(off)
        return file_object.read(count)

def get_dwords(file_object, count):
    return [get_integer32(file_object) for i in range(count)]

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
