"""
Machine code builder. Possible replacement for the MachineCode class.

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
"""
import io
import uuid
from collections import defaultdict
from copy import copy, deepcopy
from typing import List, Optional, Dict, Union, Iterable, Tuple

from attr import dataclass

from .binio import to_unsigned


@dataclass
class MachineCodeItem:
    size: int
    name: Optional[str] = None
    value: Optional[Union[int, bytes]] = None
    position: Optional[int] = None


@dataclass
class Reference(MachineCodeItem):
    is_relative: bool = False

    @classmethod
    def relative(cls, name, size=4):
        return cls(name=name, size=size, is_relative=True)

    @classmethod
    def absolute(cls, value=None, name=None, size=4):
        return cls(value=value, name=name, size=size, is_relative=False)


class MachineCodeBuilder:
    def __init__(self, origin_address=0, byteorder='little'):
        self.origin_address = origin_address
        self.byteorder = byteorder
        self._raw_list: List[MachineCodeItem] = list()
        self._fields: Dict[str, List[MachineCodeItem]] = defaultdict(list)
        self.labels: Dict[str, int] = dict()
        self._cursor: int = 0

    def _add_item(self, item: MachineCodeItem):
        item.position = self._cursor
        self._raw_list.append(item)
        self._cursor += self._raw_list[-1].size
        return self

    def byte(self, value: int):
        return self._add_item(MachineCodeItem(value=value, size=1))

    def dword(self, value: int):
        return self._add_item(MachineCodeItem(value=value, size=4))

    def label(self, name: str):
        self.labels[name] = self._cursor
        return self

    def add_bytes(self, value: bytes):
        return self._add_item(MachineCodeItem(value=value, size=len(value)))

    def relative_reference(self, name: str, size: int):
        reference = Reference.relative(name=name, size=size)
        self._fields[name].append(reference)
        return self._add_item(reference)

    def absolute_reference(
            self,
            name: Optional[str] = None,
            value: Optional[int] = None,
            size: int = 4
    ):

        if name is None:
            name = "unnamed_" + uuid.uuid1().hex

        reference = Reference.absolute(name=name, value=value, size=size)
        self._fields[name].append(reference)
        return self._add_item(reference)

    @property
    def absolute_references(self) -> Iterable[int]:
        """
        Get addresses of absolute references (to add them to the relocation table)
        """
        for fields in self._fields.values():
            for item in fields:
                if isinstance(item, Reference) and not item.is_relative:
                    yield self.origin_address + item.position

    def set_value(self, field_name: str, value: int) -> None:
        fields = self._fields[field_name]

        for field in fields:
            if isinstance(field, Reference) and field.is_relative:
                value = value - (self.origin_address + field.position + field.size)

            field.value = value

    def get_values(self) -> Iterable[Tuple[str, Optional[Union[int, bytes]]]]:
        for field_name, fields in self._fields.items():
            if fields:
                yield field_name, fields[0].value

    def set_values(self, **kwargs: int):
        """
        Set values of the corresponding fields or get values of all fields if no parameters are passed
        """
        for field_name, value in kwargs.items():
            self.set_value(field_name, value)

    def build(self) -> bytes:
        # Fill-in label references (eg. addresses of internal jumps)
        for name, value in self.labels.items():
            self.set_value(name, self.origin_address + value)

        # Build byte buffer
        buffer = io.BytesIO()
        for item in self._raw_list:
            if item.value is None:
                raise ValueError(f"Value of the {item.name!r} field is undefined")

            if isinstance(item.value, bytes):
                buffer.write(item.value)
            else:
                value = to_unsigned(item.value, item.size * 8)
                if item.size == 1:
                    buffer.write(bytes([value]))
                else:
                    buffer.write(value.to_bytes(item.size, signed=False, byteorder=self.byteorder))

        return buffer.getvalue()

    def __iadd__(self, other: Union["MachineCodeBuilder", bytes]):
        assert isinstance(other, (MachineCodeBuilder, bytes))

        if isinstance(other, bytes):
            self.add_bytes(other)
        elif isinstance(other, MachineCodeBuilder):
            for name, index in other.labels.items():
                self.labels[name] = index + self._cursor

            for item in other._raw_list:
                item_copy = copy(item)
                self._add_item(item_copy)
                if item_copy.name is not None:
                    self._fields[item_copy.name].append(item_copy)

        return self

    def __add__(self, other: Union["MachineCodeBuilder", bytes]):
        assert isinstance(other, (MachineCodeBuilder, bytes))
        new = deepcopy(self)
        new += other
        return new

    def __radd__(self, other: bytes):
        assert isinstance(other, bytes)
        return MachineCodeBuilder().add_bytes(other) + self

    def __len__(self):
        return self._cursor
