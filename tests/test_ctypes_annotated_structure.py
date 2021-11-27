from ctypes import c_int, c_byte, sizeof

from dfrus.ctypes_annotated_structure import AnnotatedStructure


def test_annotated_structure():
    class Test(AnnotatedStructure):
        field: c_int
        bytes_field: c_byte * 4

    assert sizeof(Test) == 8

    test = Test()

    integer_value = 10
    bytes_value = b"1234"

    test.field = integer_value
    test.bytes_field = type(test.bytes_field)(*bytes_value)
    assert test.field == integer_value
    assert bytes(test.bytes_field) == bytes_value
    assert bytes(test) == integer_value.to_bytes(4, "little") + bytes_value
