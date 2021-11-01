from dfrus.binio import to_dword
from dfrus.disasm import join_byte
from dfrus.machine_code import MachineCode, Reference
from dfrus.opcodes import mov_rm_imm, Reg, call_near, mov_reg_imm, jmp_near


def test_machinecode_1():
    """
    # Sample code:
    use32

    func = 222222h
    return_addr = 777777h

    org 123456h

    mov dword [esi+14h], 0fh
    call near func
    mov edi, 0fh
    jmp near return_addr
    """

    code = MachineCode(
        (mov_rm_imm | 1), join_byte(1, 0, Reg.esi), 0x14, to_dword(0xf),  # mov dword [esi+14h], 0fh
        call_near, Reference.relative(name='func', size=4),  # call near func
        mov_reg_imm | 8 | Reg.edi.code, to_dword(0xf),  # mov edi, 0fh
        jmp_near, Reference.relative(name='return_addr', size=4)  # jmp near return_addr
    )

    code.origin_address = 0x123456
    code.fields['func'] = 0x222222
    code.fields['return_addr'] = 0x777777

    assert bytes(code) == bytes.fromhex('C7 46 14 0F 00 00 00 E8 C0 ED 0F 00 BF 0F 00 00 00 E9 0B 43 65 00')


def test_machinecode_2():
    # Test getting addresses of absolute references
    code = MachineCode(
        bytes(123),
        Reference.absolute(name='b', size=4),
        bytes(12345),
        Reference.absolute(name='a', size=4),
        bytes(10)
    )

    code.origin_address = 0
    code.fields['a'] = 0xDEAD
    code.fields['b'] = 0xBEEF

    b = bytes(code)
    found_refs = sorted(b.index(to_dword(code.fields[ref_name])) for ref_name in 'ab')
    assert found_refs == list(code.absolute_references)
