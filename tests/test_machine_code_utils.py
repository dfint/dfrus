import pytest

from dfrus.disasm import Operand, disasm
from dfrus.machine_code_assembler import MachineCodeAssembler
from dfrus.machine_code_utils import mach_strlen
from dfrus.opcodes import nop, Reg


def test_mach_strlen():
    code = mach_strlen(bytes([nop]))
    expected = (
        "51 "  # push ecx
        "31 C9 "  # xor ecx, ecx
        "80 3C 08 00 "  # cmp byte [eax+ecx], 0
        "74 0B "  # jz 0x14
        "81 F9 00 01 00 00 "  # cmp ecx, 100h
        "7F 04 "  # jg 0x15 
        "41 "  # inc ecx
        "EB EF "  # jmp 0x3
        "90 "  # nop
        "59"  # pop ecx
    )
    assert code.build() == bytes.fromhex(expected)


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
    m = MachineCodeAssembler()
    m.lea(*operands)
    bs = m.build()
    assert len(bs) == expected_size
    assert str(next(disasm(m.build()))) == expected_disasm
