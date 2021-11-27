from dataclasses import dataclass, field, fields
from typing import Optional, Set, Mapping, Iterable

from .machine_code_builder import MachineCodeBuilder
from .trace_machine_code import FunctionInformation


@dataclass
class Metadata:
    fixed: Optional[str] = None  #: Was the string length value fixed?
    cause: Optional[str] = None  #: A cause of failure (if fixed == "no")
    length: Optional[str] = None  #: A way of string length specification (a register, push, etc.)
    string: Set[str] = field(default_factory=set)  #: A way of string value passing (a register, push, etc.)
    func: Optional[FunctionInformation] = None  #: A function to which the string is passed
    prev_bytes: Optional[str] = None


@dataclass
class Fix:
    new_code: Optional[MachineCodeBuilder] = None
    pokes: Optional[Mapping[int, bytes]] = None
    src_off: Optional[int] = None
    dest_off: Optional[int] = None
    added_relocs: Iterable[int] = field(default_factory=list)
    deleted_relocs: Iterable[int] = field(default_factory=list)
    meta: Optional[Metadata] = None
    fix: Optional["Fix"] = None

    def update(self, other: "Fix"):
        for f in fields(self):  # FIXME: is this correct? Do we need to replace values of all the fields?
            self.__setattr__(f.name, other.__getattribute__(f.name))

    def add_fix(self, fix: "Fix"):
        new_code = fix.new_code
        assert new_code is not None
        old_code = self.new_code
        assert old_code is not None and new_code is not None
        if new_code.build() not in old_code.build():  # FIXME: probably this check needs to be optimized
            fix.new_code = new_code + old_code
            self.update(fix)
