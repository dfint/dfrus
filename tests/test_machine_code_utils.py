from dfrus.machine_code_utils import mach_strlen
from dfrus.opcodes import nop


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
