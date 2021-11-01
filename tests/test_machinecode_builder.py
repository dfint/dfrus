from dfrus.disasm import join_byte
from dfrus.machine_code_builder import MachineCodeBuilder
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

    m = MachineCodeBuilder()
    m.byte(mov_rm_imm | 1).byte(join_byte(1, 0, Reg.esi)).byte(0x14).dword(0xf)  # mov dword [esi+14h], 0fh
    m.byte(call_near).relative_reference("func", size=4)  # call near func
    m.byte(mov_reg_imm | 8 | Reg.edi.code).dword(0xf)  # mov edi, 0fh
    m.byte(jmp_near).relative_reference("return_addr", size=4)  # jmp near return_addr

    m.origin_address = 0x123456
    m.values(func=0x222222, return_addr=0x777777)

    assert m.build() == bytes.fromhex('C7 46 14 0F 00 00 00 E8 C0 ED 0F 00 BF 0F 00 00 00 E9 0B 43 65 00')


def test_machinecode_2():
    # Test getting addresses of absolute references
    m = MachineCodeBuilder()
    m.bytes(123)
    m.absolute_reference("b", size=4)
    m.bytes(12345)
    m.absolute_reference("a", size=4)
    m.bytes(10)

    m.origin_address = 0
    m.values(a=0xDEAD, b=0xBEEF)

    b = m.build()
    field_values = m.values()
    found_refs = {b.index(field_values[ref_name].to_bytes(4, 'little')) for ref_name in 'ab'}
    assert found_refs == set(m.absolute_references)
