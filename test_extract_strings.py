import pytest

from extract_strings import check_string_array

def test_check_string_array():
    assert (list(check_string_array(b'\0\0\0abcd\0\0\0\0foo\0\0\0\0\0\0\0bar\0\0qwerty\0\0', 0)) ==
        [(3, b'abcd', 7), (11, b'foo', 9), (21, b'bar', 4), (26, b'qwerty', 7)])
