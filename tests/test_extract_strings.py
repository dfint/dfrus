import pytest

from dfrus.extract_strings import check_string_array, check_string


@pytest.mark.parametrize("test_data,encoding,expected", [
    (b"", "cp437", (0, 0)),
    (b"12345\0", "cp437", (5, 0)),
    (b"12345\xFF\0", "utf-8", (0, 0)),
    (b"1a345a\xFF\0", "utf-8", (0, 2)),
])
def test_check_string(test_data, encoding, expected):
    assert check_string(test_data, encoding) == expected


@pytest.mark.parametrize("test_data,expected", [
    (b"\0\0\0abcd\0\0\0\0foo\0\0\0\0\0\0\0bar\0\0qwerty\0\0",
     [(3, b"abcd", 7), (11, b"foo", 9), (21, b"bar", 4), (26, b"qwerty", 7)]),

    (b"\0\0\1abcd\0\0\0\2foo\0\0\0\0\0\2\3bar\0\4qwerty\0\0",
     [(3, b"abcd", 6), (11, b"foo", 7), (21, b"bar", 3), (26, b"qwerty", 7)]),

    (b"InitializeConditionVariable\0", [(0, b"InitializeConditionVariable", 27)]),
])
def test_check_string_array(test_data, expected):
    assert list(check_string_array(test_data, 0)) == expected
