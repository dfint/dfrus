from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional

from .opcodes import Reg, RegType


def asmhex(n):
    assert(n >= 0)
    if n < 0xA:
        return str(n)
    else:
        return '0x{:X}'.format(n)


seg_regs = ("es", "cs", "ss", "ds", "fs", "gs")
op_sizes = {1: "byte", 2: "word", 4: "dword", 8: "qword", 16: "dqword"}


class OperandType(Enum):
    immediate_value = auto()
    general_purpose_register = auto()
    xmm_register = auto()
    segment_register = auto()
    absolute_memory_reference = auto()
    relative_memory_reference = auto()
    unknown = auto()


class Operand(ABC):
    @abstractmethod
    def get_type(self) -> OperandType:
        return OperandType.unknown

    def get_data_size(self) -> Optional[int]:
        raise NotImplementedError()

    def set_data_size(self, value: Optional[int]):
        raise NotImplementedError()

    @property
    def data_size(self) -> Optional[int]:
        return self.get_data_size()

    @data_size.setter
    def data_size(self, value: Optional[int]):
        self.set_data_size(value)


@dataclass
class ImmediateValueOperand(Operand):
    value: int

    def get_type(self) -> OperandType:
        return OperandType.immediate_value

    def __str__(self):
        if self.value >= 0:
            return asmhex(self.value)
        else:
            return '-' + asmhex(-self.value)


@dataclass
class RegisterOperand(Operand):
    reg: Reg

    def get_type(self) -> OperandType:
        if self.reg.type == RegType.general:
            return OperandType.general_purpose_register
        elif self.reg.type == RegType.xmm:
            return OperandType.xmm_register
        elif self.reg.type == RegType.segment:
            return OperandType.segment_register
        else:
            raise ValueError("Unknown register type")

    def get_data_size(self) -> Optional[int]:
        return self.reg.size

    def set_data_size(self, new_size):
        assert new_size is None or 1 <= new_size

        if self.reg is not None:
            assert self.reg.type == RegType.general, 'Do not change non-general register size explicitly'
            self.reg = Reg((RegType.general, self.reg.code, new_size))

    def __str__(self):
        return self.reg.name


@dataclass
class MemoryReference(Operand, ABC):
    disp: int = 0
    seg_prefix: Optional[Reg] = None


@dataclass
class RelativeMemoryReference(MemoryReference):
    base_reg: Optional[Reg] = None
    index_reg: Optional[Reg] = None
    scale: Optional[int] = None
    _data_size: Optional[int] = None

    def get_type(self) -> OperandType:
        return OperandType.relative_memory_reference

    def get_data_size(self) -> Optional[int]:
        return self._data_size

    def set_data_size(self, value: Optional[int]):
        self._data_size = value

    def __str__(self):
        if self.base_reg is None and self.index_reg is None:
            result = asmhex(self.disp)
        else:
            result = ""
            if self.base_reg is not None:
                result = self.base_reg.name
                if self.index_reg is not None:
                    result += "+"

            if self.index_reg is not None:
                if self.scale:
                    result += "%d*" % (1 << self.scale)

                result += self.index_reg.name

            if self.disp or not result:
                if self.disp >= 0:
                    if not result:
                        result += asmhex(self.disp)
                    else:
                        result += '+' + asmhex(self.disp)
                else:
                    result += '-' + asmhex(-self.disp)

        if self.seg_prefix is None:
            result = "[%s]" % result
        else:
            result = "%s:[%s]" % (seg_regs[int(self.seg_prefix)], result)

        data_size = self.get_data_size()
        if data_size is not None:
            result = op_sizes[data_size] + ' ' + result

        return result


@dataclass
class AbsoluteMemoryReference(MemoryReference):
    _data_size: Optional[int] = None

    def get_type(self) -> OperandType:
        return OperandType.absolute_memory_reference

    def get_data_size(self) -> Optional[int]:
        return self._data_size

    def set_data_size(self, value: Optional[int]):
        self._data_size = value

    def __str__(self):
        result = asmhex(self.disp)

        if self.seg_prefix is None:
            result = "[%s]" % result
        else:
            result = "%s:[%s]" % (seg_regs[int(self.seg_prefix)], result)

        data_size = self.get_data_size()
        if data_size is not None:
            result = op_sizes[data_size] + ' ' + result

        return result