from io import BytesIO

from dfrus.binio import *


def test_binio():
    file_object = BytesIO()

    put_integer32(file_object, 0xDEADBEEF)
    put_integer16(file_object, 0xBAAD)
    put_integer8(file_object, 0xAB)
    write_string(file_object, "1234")

    assert file_object.getvalue() == b'\xef\xbe\xad\xde\xad\xba\xab1234\x00'

    file_object.seek(0)
    assert get_dwords(file_object, 2) == [0xDEADBEEF, 0x31ABBAAD]

    file_object.seek(0)
    assert get_words(file_object, 3) == [0xBEEF, 0xDEAD, 0xBAAD]
