import pytest

from dfrus.disasm import join_byte
from dfrus.machine_code_builder import MachineCodeBuilder
from dfrus.opcodes import mov_rm_imm, Reg, call_near, mov_reg_imm, jmp_near


def test_machine_code_builder_1():
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
    m.set_values(func=0x222222, return_addr=0x777777)

    assert m.build() == bytes.fromhex('C7 46 14 0F 00 00 00 E8 C0 ED 0F 00 BF 0F 00 00 00 E9 0B 43 65 00')


def test_machine_code_builder_absolute_references():
    # Test getting addresses of absolute references
    m = MachineCodeBuilder()
    m.add_bytes(bytes(123))
    m.absolute_reference("b", size=4)
    m.add_bytes(bytes(12345))
    m.absolute_reference("a", size=4)
    m.add_bytes(bytes(10))
    m.relative_reference("c", size=4)
    m.add_bytes(bytes(321))

    m.origin_address = 0
    m.set_values(a=0xDEAD, b=0xBEEF, c=0xF00)

    b = m.build()
    field_values = dict(m.get_values())
    found_refs = {b.index(field_values[ref_name].to_bytes(4, 'little')) for ref_name in 'ab'}
    assert found_refs == set(m.absolute_references)


def test_machine_code_builder_absolute_references_2():
    # Test getting addresses of absolute references
    m = MachineCodeBuilder()
    m.add_bytes(bytes(123))
    m.absolute_reference(value=0xBEEF, size=4)
    m.add_bytes(bytes(12345))
    m.absolute_reference(value=0xDEAD, size=4)
    m.add_bytes(bytes(10))
    m.relative_reference("c", size=4)
    m.add_bytes(bytes(321))

    m.origin_address = 0
    m.set_values(c=0xF00)

    b = m.build()
    found_refs = {b.index(value.to_bytes(4, 'little')) for value in (0xDEAD, 0xBEEF)}
    assert found_refs == set(m.absolute_references)


def test_undefined_value():
    m = MachineCodeBuilder()
    m.relative_reference(name="a", size=4)

    with pytest.raises(ValueError):
        m.build()


def test_add_bytes():
    m = MachineCodeBuilder()
    m.dword(0xDEADBEEF)
    m += b'1234'
    bs = m.build()
    assert bs == 0xDEADBEEF.to_bytes(4, 'little') + b'1234'


def test_radd_bytes():
    m = MachineCodeBuilder()
    m1 = b'1234' + m.absolute_reference(value=0xDEADBEEF).label("some_label").absolute_reference(value=0xF00)
    bs = m1.build()
    assert bs == b'1234' + 0xDEADBEEF.to_bytes(4, 'little') + 0xF00.to_bytes(4, 'little')
    assert set(m1.absolute_references) == {4, 8}
    assert m1.labels["some_label"] == 8
