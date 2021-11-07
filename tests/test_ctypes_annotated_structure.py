from ctypes import c_int, c_byte, sizeof

from dfrus.ctypes_annotated_structure import AnnotatedStructure


def test_annotated_structure():
    class Test(AnnotatedStructure):
        field: c_int
        bytes_field: c_byte * 4

    assert sizeof(Test) == 8

    test = Test()
    test.field = 10
    test.bytes_field = type(test.bytes_field)(*b'1234')
    assert test.field == 10
    assert bytes(test.bytes_field) == b'1234'
    assert bytes(test) == test.field.to_bytes(4, 'little') + bytes(test.bytes_field)
