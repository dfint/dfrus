from .disasm import join_byte
from .machine_code_builder import MachineCodeBuilder
from .opcodes import *
from .operand import Operand, RelativeMemoryReference


class MachineCodeAssembler(MachineCodeBuilder):
    def push_reg(self, register: Reg):
        return self.byte(push_reg | register.code)

    def pop_reg(self, register: Reg):
        return self.byte(pop_reg | register.code)

    def jump_conditional_short(self, condition: Cond, label: str):
        return self.byte(jcc_short | condition).relative_reference(label, size=1)

    def jump_short(self, label: str):
        return self.byte(jmp_short).relative_reference(label, size=1)

    def modrm(self, mode: int, register: int, register_memory: int):
        return self.byte(join_byte(mode, register, register_memory))

    def sib(self, scale: int, index_register: int, base_register: int):
        return self.byte(join_byte(scale, index_register, base_register))

    def mov_reg_imm(self, register: Reg, immediate: int, is_absolute_reference=False):
        assert register.type is RegType.general
        assert register.size != 2
        size_bit = 8 * (register.size == 4)
        self.byte(mov_reg_imm | size_bit | register.code)

        if is_absolute_reference:
            self.absolute_reference(value=immediate, size=register.size)
        else:
            self.add_bytes(immediate.to_bytes(register.size, byteorder='little'))

        return self

    def mov_reg_reg32(self, dest: Reg, src: Reg):
        return self.byte(mov_rm_reg | 1).modrm(3, src.code, dest.code)

    def modrm_sib_compiler(self, register: Reg, src: RelativeMemoryReference):
        if src.disp == 0 and src.base_reg != Reg.ebp:
            mode = 0
        elif -0x80 <= src.disp < 0x80:
            mode = 1
        else:
            mode = 2

        if src.base_reg is None:
            assert src.index_reg is None
            self.modrm(0, register.code, 5)
        elif src.index_reg is None and src.base_reg != Reg.esp:
            self.modrm(mode, register.code, src.base_reg.code)
        else:
            if src.index_reg is None:
                self.modrm(mode, register.code, 4).sib(0, 4, src.base_reg.code)
            else:
                scale = src.scale
                assert src.index_reg != Reg.esp  # ESP cannot be an index register
                self.modrm(mode, register.code, 4)
                self.sib(scale, src.index_reg.code, src.base_reg.code)

        if mode == 1:
            self.byte(src.disp)
        elif mode == 2:
            self.dword(src.disp)

        return self

    def lea(self, register: Reg, src: Operand):
        return self.byte(lea).modrm_sib_compiler(register, src)

    def push_imm8(self, new_len):
        return self.byte(push_imm8).byte(new_len)

    def call_near(self, label: str):
        return self.byte(call_near).relative_reference(label)


def asm() -> MachineCodeAssembler:
    return MachineCodeAssembler()
