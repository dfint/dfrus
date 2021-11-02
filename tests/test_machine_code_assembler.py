import pytest

from dfrus.disasm import Operand, disasm
from dfrus.machine_code_assembler import asm
from dfrus.opcodes import Reg


@pytest.mark.parametrize("operands,expected_size,expected_disasm", [
    # ((Reg.edi, Operand(disp=0x100)), 6, "lea edi, [0x100]"),  # FIXME
    # ((Reg.edi, Operand(base_reg=Reg.eax)), 2, "lea edi, [eax]"),  # FIXME
    ((Reg.edi, Operand(base_reg=Reg.eax, disp=-0x10)), 3, "lea edi, [eax-0x10]"),
    ((Reg.edi, Operand(base_reg=Reg.eax, disp=0x123)), 6, "lea edi, [eax+0x123]"),
    # ((Reg.edi, Operand(base_reg=Reg.eax, index_reg=Reg.esi, disp=0x123)), 7, "lea edi, [eax+esi+0x123]"),  # FIXME
    # ((Reg.edi, Operand(base_reg=Reg.eax, index_reg=Reg.esi, scale=2, disp=0x123)), 7,
    #   "lea edi, [eax+4*esi+0x123]"),  # FIXME
])
def test_lea(operands, expected_size, expected_disasm):
    bs = asm().lea(*operands).build()
    assert len(bs) == expected_size
    assert str(next(disasm(bs))) == expected_disasm
