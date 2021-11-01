from dfrus.disasm import join_byte
from dfrus.machine_code_builder import MachineCodeBuilder
from dfrus.opcodes import *


class MachineCodeAssembler(MachineCodeBuilder):
    def push_reg(self, register: Reg):
        self.byte(push_reg | register.code)

    def pop_reg(self, register: Reg):
        self.byte(pop_reg | register.code)

    def jump_conditional_short(self, condition: Cond, label: str):
        self.byte(jcc_short | condition).relative_reference(label, size=1)

    def jump_short(self, label: str):
        self.byte(jmp_short).relative_reference(label, size=1)

    def modrm(self, mode: int, register: int, register_memory: int) -> "MachineCodeAssembler":
        return self.byte(join_byte(mode, register, register_memory))

    def sib(self, scale: int, index_register: int, base_register: int) -> "MachineCodeAssembler":
        return self.byte(join_byte(scale, index_register, base_register))
