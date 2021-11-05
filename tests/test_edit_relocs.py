import pytest

from dfrus.edit_relocs import group_args


@pytest.mark.parametrize("args, expected_result", [
    ([], dict()),
    (["+"], {"+": []}),
    (["+", "-", "-*"], {"+": [], "-": [], "-*": []}),
    (["+", "10", "0b10", "0o10", "0x10"],
     {"+": [10, 0b10, 0o10, 0x10]}),
    (["+", "10", "0b10", "0o10", "0x10", "-", "1", "2", "3"],
     {"+": [10, 0b10, 0o10, 0x10], "-": [1, 2, 3]}),
    (["+", "10", "0b10", "0o10", "0x10", "-", "1", "2", "3", "-*", "0", "100"],
     {"+": [10, 0b10, 0o10, 0x10], "-": [1, 2, 3], "-*": [0, 100]}),
])
def test_group_args(args, expected_result):
    assert dict(group_args(args)) == expected_result
