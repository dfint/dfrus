from typing import BinaryIO

from .binio import from_dword, read_bytes, to_signed, fpoke, fpoke4
from .disasm import disasm, DisasmLine, join_byte
from .machine_code_assembler import asm
from .machine_code_match import match_mov_reg_imm32, get_start
from .machine_code_utils import mach_strlen
from .metadata_objects import Metadata, Fix
from .moves_series import get_fix_for_moves, analyze_moves_series
from .opcodes import *
from .operand import (RegisterOperand, RelativeMemoryReference, ImmediateValueOperand)
from .trace_machine_code import FunctionInformation, which_func


def find_instruction(s, instruction):
    for line in disasm(s):
        assert (line.mnemonic != "db")
        if line.data[0] == instruction:
            return line.address
    return None


count_before = 0x20
count_after = 0x100
count_after_for_get_length = 0x2000


def analyze_reference_code(fn: BinaryIO,
                           offset: int,
                           old_len: int,
                           new_len: int,
                           string_address: int,
                           original_string_address: int) -> Fix:
    """
    Analyze a machine code around a reference to a string and provide a fix for the code if needed
    """
    next_off = offset + 4

    pre = read_bytes(fn, offset - count_before, count_before)
    aft = read_bytes(fn, next_off, count_after)
    jmp = None
    old_next = next_off
    if aft[0] in {jmp_short, jmp_near} or aft[0] & 0xf0 == jcc_short:
        if aft[0] == jmp_short or aft[0] & 0xf0 == jcc_short:
            displacement = to_signed(aft[1], width=8)
            next_off += 2 + displacement
        elif aft[0] == jmp_near:
            displacement = from_dword(aft[1:5], signed=True)
            next_off += 5 + displacement
        jmp = aft[0]
        aft = read_bytes(fn, next_off, count_after)
    elif aft[0] == call_near or (aft[0] == 0x0f and aft[1] == x0f_jcc_near):
        aft = bytes()

    meta = Metadata()
    if pre[-1] == push_imm32:
        # push offset str
        meta.string.add("push")

        if pre[-3] == push_imm8 and pre[-2] == old_len:
            fpoke(fn, offset - 2, new_len)
            meta.length = "push before"
            meta.fixed = "yes"

        meta.func = which_func(fn, old_next)
    elif pre[-1] & 0xF8 == (mov_reg_imm | 8):
        # mov reg32, offset str
        reg = pre[-1] & 7

        def stop_func(disasm_line: DisasmLine):
            if disasm_line.operands:
                operand1 = disasm_line.operand1
                if isinstance(operand1, RegisterOperand) and operand1.reg == reg:
                    return True
                elif disasm_line.operand2:
                    operand2 = disasm_line.operand2
                    if isinstance(operand2, RelativeMemoryReference) and operand2.base_reg == reg:
                        return True

            return False

        func = which_func(fn, old_next, stop_cond=stop_func)

        meta.func = func

        if reg == Reg.eax.code:
            # mov eax, offset str
            meta.string.add("eax")
            if from_dword(pre[-5:-1]) == old_len:
                fpoke4(fn, offset - 5, new_len)
                meta.fixed = "yes"
                if pre[-6] == mov_reg_imm | 8 | Reg.edi.code:
                    meta.length = "edi"
                    # mov edi, len before
                    if (old_len == 15 or old_len == 16) and aft and not jmp:
                        # Trying to fix the case when the edi value is used as a stl-string cap size
                        # Sample code for this case:
                        # mov edi, 0fh
                        # mov eax, strz_You_last_spoke__db24d8
                        # lea esi, [esp+40h]
                        # mov [esp+54h], edi  ; Equivalent to mov [esi+14h], edi
                        # mov dword ptr [esp+50h], 0
                        # mov byte ptr [esp+40h], 0
                        # call sub_40f650

                        mov_esp_edi = False

                        for line in disasm(aft, next_off):
                            assert (line.mnemonic != "db")
                            str_line = str(line)
                            if str_line.startswith("mov [esp") and str_line.endswith("], edi"):
                                # Check if the value of edi is used in "mov [esp+N], edi"
                                mov_esp_edi = True
                            elif line.data[0] == call_near:
                                # jmp near m1 ; replace call of sub_40f650 with jmp
                                # return_addr:
                                # ; ...
                                # ; ----------------------------------------------
                                # m1:
                                # mov dword [esi+14h], oldlen
                                # call sub_40f650 ; or whatever the function was
                                # mov edi, oldlen
                                # jmp near return_addr

                                m = asm()

                                if mov_esp_edi:
                                    # Restore the cap length value of stl-string if needed
                                    # mov dword [esi+14h], oldlen
                                    m.byte(mov_rm_imm | 1).modrm(1, 0, Reg.esi).byte(0x14).dword(old_len)

                                m.byte(call_near).relative_reference(name="func", size=4)  # call near func
                                # Restore original edi value for the case if it is used further in the code:
                                m.mov_reg_imm(Reg.edi, old_len)  # mov edi, old_len
                                m.byte(jmp_near).relative_reference(name="return_addr", size=4)  # jmp near return_addr

                                operand = line.operand1
                                assert isinstance(operand, ImmediateValueOperand), operand

                                m.set_values(func=operand.value, return_addr=line.address + 5)

                                ret_value = Fix(
                                    src_off=line.address + 1,
                                    new_code=m,
                                    pokes={line.address: bytes([jmp_near])}  # Replace call with jump
                                )
                                ret_value.meta = meta
                                return ret_value
                return Fix(meta=meta)  # Length fixed successfully
            elif pre[-3] == push_imm8 and pre[-2] == old_len:
                # push len ; before
                fpoke(fn, offset - 2, new_len)
                meta.length = "push"
                meta.fixed = "yes"
                return Fix(meta=meta)
            elif aft and aft[0] == push_imm8 and aft[1] == old_len:
                # push len ; after
                meta.length = "push"
                if not jmp:
                    fpoke(fn, next_off + 1, new_len)
                    meta.fixed = "yes"
                    return Fix(meta=meta)
                elif jmp == jmp_near:
                    ret_value = Fix(
                        src_off=old_next + 1,
                        new_code=asm().push_imm8(new_len),
                        dest_off=next_off + 2
                    )
                    ret_value.meta = meta
                    return ret_value
                else:  # jmp == jmp_short
                    i = find_instruction(aft, call_near)
                    if i is not None:
                        displacement = from_dword(aft[i + 1:i + 5], signed=True)
                        ret_value = Fix(
                            src_off=next_off + i + 1,
                            new_code=mach_strlen(
                                # mov [ESP+8], ECX
                                asm().byte(mov_rm_reg | 1).modrm(1, Reg.ecx, 4).sib(0, 4, Reg.esp).byte(8)
                            ),
                            dest_off=next_off + i + 5 + displacement
                        )
                        ret_value.meta = meta
                        return ret_value
            elif pre[-2] == mov_reg_rm | 1 and pre[-1] & 0xf8 == join_byte(3, Reg.edi, 0):
                # mov edi, reg
                meta.length = "edi"
                # There"s no code in DF that passes this condition. Left just in case.
                # TODO: Drop it
                i = find_instruction(aft, call_near)
                if i is not None:
                    displacement = from_dword(aft[i + 1:i + 5], signed=True)
                    ret_value = Fix(
                        src_off=next_off + i + 1,
                        new_code=mach_strlen(
                            asm().byte(mov_reg_rm | 1).modrm(3, Reg.edi, Reg.ecx)  # mov edi, ecx
                        ),
                        dest_off=next_off + i + 5 + displacement,
                    )
                    ret_value.meta = meta
                    return ret_value
            elif aft and match_mov_reg_imm32(aft[:5], Reg.edi, old_len):
                # mov edi, len ; after
                meta.length = "edi"
                if not jmp:
                    fpoke4(fn, next_off + 1, new_len)
                    meta.fixed = "yes"
                    return Fix(meta=meta)
                elif jmp == jmp_near:
                    m = asm().mov_reg_imm(Reg.edi, new_len)  # mov edi, new_len
                    ret_value = Fix(
                        src_off=old_next + 1,
                        new_code=m,
                        dest_off=next_off + 5
                    )
                    ret_value.meta = meta
                    return ret_value
                else:  # jmp == jmp_short
                    i = find_instruction(aft, call_near)
                    if i is not None:
                        displacement = from_dword(aft[i + 1:i + 5], signed=True)
                        ret_value = Fix(
                            src_off=next_off + i + 1,
                            new_code=mach_strlen(
                                asm().byte(mov_reg_rm | 1).modrm(3, Reg.edi, Reg.ecx)  # mov edi, ecx
                            ),
                            dest_off=next_off + i + 5 + displacement,
                        )
                        ret_value.meta = meta
                        return ret_value
            elif pre[-4] == lea and pre[-3] & 0xf8 == join_byte(1, Reg.edi, 0) and pre[-2] != 0:
                # Possible to be `lea edi, [reg+N]`
                displacement = to_signed(pre[-2], 8)
                if displacement == old_len:
                    # lea edi, [reg+old_len]
                    meta.length = "edi"
                    fpoke(fn, offset - 2, new_len)
                    meta.fixed = "yes"
                    return Fix(meta=meta)
            elif (aft and aft[0] == mov_reg_rm | 1 and aft[1] & 0xf8 == join_byte(3, Reg.ecx, 0) and
                  aft[2] == push_imm8 and aft[3] == old_len):
                # mov ecx, reg; push imm8
                meta.length = "push"
                if not jmp:
                    fpoke(fn, next_off + 3, new_len)
                    meta.fixed = "yes"
                    return Fix(meta=meta)
                elif jmp == jmp_near:
                    # TODO: Handle this case
                    meta.fixed = "not implemented"
                    return Fix(meta=meta)
                else:
                    meta.fixed = "no"
                    return Fix(meta=meta)
        elif reg == Reg.esi.code and isinstance(func, tuple) and func[0].startswith("rep"):
            # Sample code:
            # ; old_len = 22
            # ; r = (old_len+1) % 4 = 3 (3 bytes moved with 1 movsw and 1 movsb)
            # mov ecx, 5 ; 5 = (old_len + 1) // 4
            # mov esi, strz_Store_Item_in_Hospital_dc4f40
            # lea edi, [dest]
            # repz movsd
            # movsw
            # movsb
            meta.string.add("esi")
            r = (old_len + 1) % 4
            dword_count = (old_len + 1) // 4
            new_dword_count = (new_len - r) // 4 + 1
            mod_1_ecx_0 = join_byte(1, Reg.ecx, 0)
            if match_mov_reg_imm32(pre[-6:-1], Reg.ecx, dword_count):
                # mov ecx, dword_count
                fpoke4(fn, offset - 5, new_dword_count)
                meta.length = "ecx*4"
                meta.fixed = "yes"
                return Fix(meta=meta)
            elif pre[-4] == lea and pre[-3] & 0xf8 == mod_1_ecx_0 and pre[-2] == dword_count:
                # lea ecx, [reg+dword_count]  ; assuming that reg value == 0
                fpoke(fn, offset - 2, new_dword_count)
                meta.length = "ecx*4"
                meta.fixed = "yes"
                return Fix(meta=meta)
            elif new_len > old_len:
                # ecx modification code was not found. TODO: handle this case properly.
                if jmp:
                    meta.fixed = "no"
                    return Fix(meta=meta)
                elif aft:
                    for line in disasm(aft, start_address=next_off):
                        if line.mnemonic != "db":
                            break
                        offset = line.address
                        line_data = line.data
                        if line_data[0] == Prefix.rep:
                            meta.length = "ecx*4"
                            meta.fixed = "no"
                            return Fix(meta=meta)
                        elif line_data[0] == jmp_near:
                            operand = line.operand1
                            assert isinstance(operand, ImmediateValueOperand), operand
                            next_off_2 = operand.value
                            aft = read_bytes(fn, offset, count_after)

                            skip = None
                            if match_mov_reg_imm32(aft[:5], Reg.ecx, dword_count):
                                skip = 5
                            elif aft[0] == lea and aft[1] & 0xf8 == mod_1_ecx_0 and aft[2] == dword_count:
                                skip = 3

                            if skip is not None:
                                meta.length = "ecx*4"
                                ret_value = Fix(
                                    src_off=line.address + 1,
                                    new_code=asm().mov_reg_imm(Reg.ecx, dword_count),
                                    dest_off=next_off_2 + skip
                                )
                                ret_value.meta = meta
                                return ret_value

                            meta.fixed = "no"
                            return Fix(meta=meta)
                        elif len(line_data) == 5 and match_mov_reg_imm32(line_data, Reg.ecx, dword_count):
                            fpoke4(fn, line.address + 1, new_dword_count)
                            meta.length = "ecx*4"
                            meta.fixed = "yes"
                            return Fix(meta=meta)
                        elif line_data[0] == lea and line_data[1] & 0xf8 == mod_1_ecx_0 and line_data[2] == dword_count:
                            fpoke(fn, line.address + 2, new_dword_count)
                            meta.length = "ecx*4"
                            meta.fixed = "yes"
                            return Fix(meta=meta)
                    return Fix(meta=meta)
        else:
            meta.string.add(["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"][reg])
        return Fix(meta=meta)
    elif (pre[-1] & 0xFE == mov_acc_mem or (pre[-2] & 0xFE == mov_reg_rm and
                                            pre[-1] & 0xC7 == join_byte(0, 0, 5)) or  # mov
          pre[-3] == 0x0F and pre[-2] in {x0f_movups, x0f_movaps} and
          pre[-1] & 0xC7 == join_byte(0, 0, 5)):  # movups or movaps
        # mov eax, [addr] or mov reg, [addr]
        meta.string.add("mov")

        next_off = offset - get_start(pre)
        aft = read_bytes(fn, next_off, count_after_for_get_length)
        try:
            get_length_info = analyze_moves_series(aft, old_len, original_string_address)
        except (ValueError, IndexError) as err:
            meta.fixed = "no"
            meta.cause = repr(err)
            return Fix(meta=meta)

        if get_length_info.pokes:
            for off, b in get_length_info.pokes.items():
                fpoke(fn, next_off + off, b)

        if new_len <= old_len and not get_length_info.pokes:
            meta.fixed = "not needed"
            return Fix(meta=meta)
        else:
            fix = get_fix_for_moves(get_length_info, new_len, string_address, meta)

            if meta.fixed == "yes":
                # Make deleted relocs offsets relative to the given offset
                fix.deleted_relocs = [next_off + ref - offset for ref in fix.deleted_relocs]

                if fix.fix:
                    fix.fix.src_off = next_off + 1
                else:
                    # Make new relocations relative to the given offset (only if they not belong to a procedure)
                    fix.added_relocs = [next_off + ref - offset for ref in fix.added_relocs]

                if fix.pokes:
                    fix.pokes = {next_off + off: b for off, b in fix.pokes.items()}

            return fix
    elif pre[-2] == mov_reg_rm and pre[-1] & 0xC0 == 0x80:
        # mov reg8, string[reg]
        meta.func = FunctionInformation("strcpy")
        meta.string.add("mov byte")
        meta.fixed = "not needed"
        return Fix(meta=meta)  # No need fixing
    elif pre[-1] == add_acc_imm | 1:
        # add reg, offset string
        meta.func = FunctionInformation("array")
        meta.string.add("add offset")
        meta.fixed = "not needed"
        return Fix(meta=meta)
    elif pre[-2] == op_rm_imm | 1 and pre[-1] & 0xF8 == 0xF8:
        # cmp reg, offset string
        meta.string.add("cmp reg")
    elif pre[-4] == mov_rm_imm | 1 and pre[-3] == join_byte(1, 0, 4) and pre[-2] == join_byte(0, 4, Reg.esp):
        # mov [esp+N], offset string
        meta.string.add("mov var")
        meta.fixed = "not needed"
    meta.prev_bytes = " ".join("{:02X}".format(x) for x in pre[-4:])
    return Fix(meta=meta)
