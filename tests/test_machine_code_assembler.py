import pytest

from dfrus.disasm import Operand, disasm
from dfrus.machine_code_assembler import asm
from dfrus.opcodes import Reg


@pytest.mark.parametrize("operands, bytes_result, expected_disasm", [
    ((Reg.edi, Operand(disp=0x100)), b"\x8D\x3D\x00\x01\x00\x00", "lea edi, [0x100]"),
    ((Reg.edi, Operand(base_reg=Reg.eax)), b"\x8D\x38", "lea edi, [eax]"),
    ((Reg.edi, Operand(base_reg=Reg.ebp)), b"\x8D\x7D\x00", "lea edi, [ebp]"),
    ((Reg.edi, Operand(base_reg=Reg.esp)), b"\x8D\x3C\x24", "lea edi, [esp]"),
    ((Reg.edi, Operand(base_reg=Reg.eax, disp=-0x10)), b"\x8D\x78\xF0", "lea edi, [eax-0x10]"),
    ((Reg.edi, Operand(base_reg=Reg.eax, disp=0x123)), b"\x8D\xB8\x23\x01\x00\x00", "lea edi, [eax+0x123]"),
    ((Reg.edi, Operand(base_reg=Reg.eax, index_reg=Reg.esi, disp=0x123)), b"\x8D\xBC\x30\x23\x01\x00\x00",
        "lea edi, [eax+esi+0x123]"),
    ((Reg.edi, Operand(base_reg=Reg.eax, index_reg=Reg.esi, scale=2, disp=0x123)), b"\x8D\xBC\xB0\x23\x01\x00\x00",
        "lea edi, [eax+4*esi+0x123]"),
])
def test_lea(operands, bytes_result, expected_disasm):
    bs = asm().lea(*operands).build()
    assert bs == bytes_result
    assert str(next(disasm(bs))) == expected_disasm
