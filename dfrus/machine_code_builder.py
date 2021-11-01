"""
Machine code builder. Possible replacement for the MachineCode class.
See concept() for example.
"""
import io
from typing import List, Optional, Dict, Mapping

from attr import dataclass

from .binio import to_unsigned


def concept():
    from .disasm import join_byte
    from .opcodes import mov_rm_imm, Reg, mov_reg_imm, call_near, jmp_near

    # Concept:
    m = MachineCodeBuilder()
    m.byte(mov_rm_imm | 1).byte(join_byte(1, 0, Reg.esi)).byte(0x14).dword(0xf)  # mov dword [esi+14h], 0fh
    m.byte(call_near).relative_reference(name='func', size=4)  # call near func
    m.byte(mov_reg_imm | 8 | Reg.edi.code).dword(0xf)  # mov edi, 0fh
    m.byte(jmp_near).relative_reference(name='return_address', size=4)  # jmp near return_addr

    m.origin_address = 0x123456
    m.values(func=0x756733, return_address=0x475675)

    file = io.BytesIO()
    file.seek(m.origin_address)
    file.write(m.build())


@dataclass
class MachineCodeItem:
    size: int
    name: Optional[str] = None
    value: Optional[int] = None
    position: Optional[int] = None
    is_relative: Optional[bool] = None


class MachineCodeBuilder:
    def __init__(self, origin_address=0, byteorder='little'):
        self.origin_address = origin_address
        self.byteorder = byteorder
        self._raw_list: List[MachineCodeItem] = list()
        self._fields: Dict[str, MachineCodeItem] = dict()
        self._labels: Dict[str, int] = dict()
        self._cursor: int = 0

    def _add_item(self, item: MachineCodeItem) -> "MachineCodeBuilder":
        item.position = self._cursor
        self._raw_list.append(item)
        self._cursor += self._raw_list[-1].size
        return self

    def byte(self, value) -> "MachineCodeBuilder":
        return self._add_item(MachineCodeItem(value=value, size=1))

    def dword(self, value) -> "MachineCodeBuilder":
        return self._add_item(MachineCodeItem(value=value, size=4))

    def label(self, name) -> "MachineCodeBuilder":
        self._labels[name] = self._cursor
        return self

    def relative_reference(self, name, size) -> "MachineCodeBuilder":
        reference = MachineCodeItem(name=name, size=size, is_relative=True)
        self._fields[name] = reference
        return self._add_item(reference)

    def absolute_reference(self, name, size) -> "MachineCodeBuilder":
        reference = MachineCodeItem(name=name, size=size, is_relative=False)
        self._fields[name] = reference
        return self._add_item(reference)

    def _set_value(self, field_name: str, value: int) -> None:
        field = self._fields[field_name]

        if field.is_relative:
            value = value - (self.origin_address + field.position + field.size)

        field.value = value

    def values(self, **kwargs: int) -> Optional[Mapping[str, int]]:
        """
        Set values of the corresponding fields or get values of all fields if no parameters are passed
        """
        if not kwargs:
            return {field.name: field.value for field in self._fields.values()}

        for field_name, value in kwargs.items():
            self._set_value(field_name, value)

    def build(self) -> bytes:
        # Fill-in label references (eg. addresses of internal jumps)
        for name, value in self._labels.items():
            self._set_value(name, self.origin_address + value)

        # Build byte buffer
        buffer = io.BytesIO()
        for item in self._raw_list:
            if item.value is None:
                raise ValueError(f"Value of the {item.name!r} field is undefined")

            value = to_unsigned(item.value, item.size)
            if item.size == 1:
                buffer.write(bytes([value]))
            else:
                buffer.write(value.to_bytes(item.size, signed=False, byteorder=self.byteorder))

        return buffer.getvalue()