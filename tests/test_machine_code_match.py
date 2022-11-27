import pytest

from dfrus.machine_code_match import get_start, match_mov_reg_imm32
from dfrus.opcodes import Prefix, Reg, mov_acc_mem, mov_rm_reg, nop


@pytest.mark.parametrize(
    "test_data,expected",
    [
        ([nop, mov_acc_mem], 1),
        ([Prefix.operand_size, mov_acc_mem], 2),
        ([nop, mov_rm_reg, 0x05], 2),
        ([Prefix.operand_size, mov_rm_reg, 0x05], 3),
        (bytes.fromhex("0f 10 05"), 3),  # movups xmm0, [...]
    ],
)
def test_get_start(test_data, expected):
    assert get_start(test_data) == expected


def test_match_mov_reg_imm32():
    assert match_mov_reg_imm32(b"\xb9\x0a\x00\x00\x00", Reg.ecx.code, 0x0A)
