import pytest

from extract_strings import check_string_array

def test_check_string_array():
    assert (list(check_string_array(b'\0\0\0abcd\0\0\0\0foo\0\0\0\0\0\0\0bar\0\0qwerty\0\0', 0)) ==
        [(3, b'abcd', 7), (11, b'foo', 9), (21, b'bar', 4), (26, b'qwerty', 7)])

def test_check_string_array_1():
    assert (list(check_string_array(b'\0\0\1abcd\0\0\0\2foo\0\0\0\0\0\2\3bar\0\4qwerty\0\0', 0)) ==
        [(3, b'abcd', 6), (11, b'foo', 7), (21, b'bar', 3), (26, b'qwerty', 7)])

def test_check_string_array_trivial():
    assert (list(check_string_array(b'InitializeConditionVariable\0', 0)) ==
        [(0, b'InitializeConditionVariable', 27)])
