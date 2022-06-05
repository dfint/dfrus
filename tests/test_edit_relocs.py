import pytest

from dfrus.edit_relocs import int_literal_converter, list_int_literal_converter, add_items, remove_items, remove_range


@pytest.mark.parametrize(
    "values, expected_result",
    [
        (["10", "0b10", "0o10", "0x10"], [10, 0b10, 0o10, 0x10]),
    ],
)
def test_list_int_literal_converter(values, expected_result):
    assert list_int_literal_converter(values) == expected_result


@pytest.mark.parametrize("value", ["asdsdf", "x1123", "23424x", "---"])
def test_int_literal_converter_raises_error(value):
    with pytest.raises(Exception):
        int_literal_converter(value)


def test_add_items():
    assert add_items((3, 4, 5), {1, 2, 3}) == {1, 2, 3, 4, 5}


def test_remove_items():
    assert remove_items((3, 4, 5), {1, 2, 3}) == {1, 2}


@pytest.mark.parametrize(
    "items, relocs, expected",
    [
        ((3, 4), {1, 2, 3, 4, 5, 6}, {1, 2, 5, 6}),
        ((3,), {1, 2, 3, 4, 5, 6}, {1, 2, 3, 4, 5, 6}),
        ((3, 4, 5), {1, 2, 3, 4, 5, 6}, {1, 2, 5, 6}),
        ((3, 4), {1, 2, 5, 6}, {1, 2, 5, 6}),
    ],
)
def test_remove_range(items, relocs, expected):
    assert remove_range(items, relocs) == expected
