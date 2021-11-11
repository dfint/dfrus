import pytest

from dfrus.edit_relocs import int_literal_converter, list_int_literal_converter


@pytest.mark.parametrize("values, expected_result", [
    (["10", "0b10", "0o10", "0x10"], [10, 0b10, 0o10, 0x10]),
])
def test_list_int_literal_converter(values, expected_result):
    assert list_int_literal_converter(values) == expected_result


@pytest.mark.parametrize("value", [
    "asdsdf",
    "x1123",
    "23424x",
    "---"
])
def test_int_literal_converter_raises_error(value):
    with pytest.raises(Exception):
        int_literal_converter(value)
