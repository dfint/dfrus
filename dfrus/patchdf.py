import codecs
import csv
import io
import sys
import textwrap
from binascii import hexlify
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, fields, field
from operator import itemgetter
from typing import Tuple, Optional, Any, Union, Set, Iterable, Mapping, MutableMapping, List
from warnings import warn

from .binio import read_bytes, fpoke4, fpoke, from_dword, to_dword, to_signed
from .cross_references import get_cross_references
from .disasm import disasm, DisasmLine, join_byte, Operand, align, OperandType
from .extract_strings import extract_strings
from .machine_code import MachineCode, Reference
from .machine_code_utils import mach_strlen, match_mov_reg_imm32, get_start, mach_memcpy
from .opcodes import *
from .patch_charmap import search_charmap, patch_unicode_table, get_codepages, get_encoder
from .peclasses import Section, RelocationTable
from .trace_machine_code import which_func, FunctionInformation


def load_trans_file(fn):
    def unescape(x):
        return x.replace('\\r', '\r').replace('\\t', '\t')

    dialect = 'unix'

    fn.seek(0)
    reader = csv.reader(fn, dialect)
    for parts in reader:
        if not parts[0]:
            parts = parts[1:]
        assert len(parts) >= 2, parts
        yield unescape(parts[0]), unescape(parts[1])


code_section, rdata_section, data_section = range(3)


def find_instruction(s, instruction):
    for line in disasm(s):
        assert (line.mnemonic != 'db')
        if line.data[0] == instruction:
            return line.address
    return None


@dataclass
class Metadata:
    fixed: Optional[str] = None  #: Was the string length value fixed?
    cause: Optional[str] = None  #: A cause of failure (if fixed == 'no')
    length: Optional[str] = None  #: A way of string length specification (a register, push, etc.)
    string: Set[str] = field(default_factory=set)  #: A way of string value passing (a register, push, etc.)
    func: Optional[FunctionInformation] = None  #: A function to which the string is passed
    prev_bytes: Optional[str] = None


@dataclass
class Fix:
    new_code: Optional[Union[bytes, MachineCode]] = None
    pokes: Optional[dict] = None
    poke: Any = None
    src_off: Optional[int] = None
    dest_off: Optional[int] = None
    added_relocs: Iterable[int] = field(default_factory=list)
    deleted_relocs: Iterable[int] = field(default_factory=list)
    meta: Optional[Metadata] = None
    op: Optional[Any] = None
    fix: Optional[Any] = None

    def update(self, other: "Fix"):
        for field in fields(self):
            self.__setattr__(field.name, other.__getattribute__(field.name))

    def add_fix(self, fix: "Fix"):
        new_code = fix.new_code
        assert new_code is not None
        old_fix = self
        if not self:
            self.update(fix)
        else:
            old_code = old_fix.new_code
            assert old_code is not None
            if bytes(new_code) in bytes(old_code):
                pass  # Fix is already added, do nothing
            else:
                if isinstance(old_code, MachineCode):
                    assert not isinstance(new_code, MachineCode)
                    new_code = new_code + old_code
                    if old_fix.poke and not fix.poke:
                        fix.poke = old_fix.poke
                else:
                    new_code = old_code + new_code
                fix.new_code = new_code
                self.update(fix)


def get_fix_for_moves(get_length_info: "GetLengthResult", newlen, string_address, meta: Metadata) -> Fix:
    added_relocs = get_length_info.added_relocs

    mach, new_refs = mach_memcpy(string_address, get_length_info.dest, newlen + 1)
    if get_length_info.saved_mach:
        mach = get_length_info.saved_mach + mach  # If there is "lea edi, [dest]", put it before the new code
        new_refs = {item + len(get_length_info.saved_mach) for item in new_refs}

    added_relocs.update(new_refs)

    proc = None
    if len(mach) > get_length_info.length:
        # if memcpy code is to long, try to write it into the new section and make call to it
        if isinstance(mach, bytes):
            mach = bytearray(mach)

        mach.append(ret_near)
        proc = mach

        mach = bytes((call_near,)) + bytes(4)  # leave zeros instead of displacement for now
        if len(mach) > get_length_info.length:
            # Too tight here, even for a procedure call
            meta.fixed = 'no'
            meta.cause = 'to tight to call'
            return Fix(meta=meta)

    # Write replacement code
    mach = mach.ljust(get_length_info.length, nop.to_bytes(1, 'little'))
    pokes = {0: mach}

    # Nop-out old instructions
    if get_length_info.nops:
        for off, count in get_length_info.nops.items():
            pokes[off] = bytes(nop for _ in range(count))

    if proc:
        fix = Fix(
            # src_off=next_off + 1,
            fix=Fix(new_code=proc, pokes=pokes),
            deleted_relocs=get_length_info.deleted_relocs,
            added_relocs=added_relocs,  # These relocs belong to proc, not to the current code block
        )
    else:
        fix = Fix(
            deleted_relocs=get_length_info.deleted_relocs,
            added_relocs=added_relocs,
            pokes=pokes,
        )

    meta.fixed = 'yes'
    fix.meta = meta
    return fix


count_before = 0x20
count_after = 0x100
count_after_for_get_length = 0x2000


def fix_len(fn, offset, old_len, new_len, string_address, original_string_address) -> Fix:
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
        aft = None

    meta = Metadata()
    if pre[-1] == push_imm32:
        # push offset str
        meta.string.add('push')

        if pre[-3] == push_imm8 and pre[-2] == old_len:
            fpoke(fn, offset - 2, new_len)
            meta.length = 'push before'
            meta.fixed = 'yes'

        meta.func = which_func(fn, old_next)
    elif pre[-1] & 0xF8 == (mov_reg_imm | 8):
        # mov reg32, offset str
        reg = pre[-1] & 7

        def stop_func(disasm_line: DisasmLine):
            if disasm_line.operands:
                operands = disasm_line.operands
                if (operands[0].get_type() is OperandType.general_purpose_register
                        and operands[0].reg == reg):
                    return True
                elif (len(operands) > 1
                      and operands[1].get_type() == OperandType.relative_memory_reference
                      and operands[1].base_reg == reg):
                    return True

            return False

        func = which_func(fn, old_next, stop_cond=stop_func)

        if isinstance(func, tuple):
            meta.func = func

        if reg == Reg.eax.code:
            # mov eax, offset str
            meta.func = FunctionInformation('eax')
            if from_dword(pre[-5:-1]) == old_len:
                fpoke4(fn, offset - 5, new_len)
                meta.fixed = 'yes'
                if pre[-6] == mov_reg_imm | 8 | Reg.edi.code:
                    meta.length = 'edi'
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
                            assert (line.mnemonic != 'db')
                            str_line = str(line)
                            if str_line.startswith('mov [esp') and str_line.endswith('], edi'):
                                # Check if the value of edi is used in 'mov [esp+N], edi'
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

                                # Restore the cap length value of stl-string if needed
                                # mov dword [esi+14h], oldlen
                                if mov_esp_edi:
                                    fix_cap = MachineCode(mov_rm_imm | 1, join_byte(1, 0, Reg.esi), 0x14,
                                                          to_dword(old_len))
                                else:
                                    fix_cap = MachineCode()

                                assert line.operands is not None

                                new_code = MachineCode(
                                    fix_cap,
                                    call_near, Reference.relative(name='func'),  # call near func
                                    # Restore original edi value for the case if it is used further in the code:
                                    mov_reg_imm | 8 | Reg.edi.code, to_dword(old_len),  # mov edi, old_len
                                    jmp_near, Reference.relative(name='return_addr'),  # jmp near return_addr
                                    func=line.operands[0].value,
                                    return_addr=line.address + 5
                                )
                                ret_value = Fix(
                                    src_off=line.address + 1,
                                    new_code=new_code,
                                    pokes={line.address: jmp_near}  # Replace call with jump
                                )
                                ret_value.meta = meta
                                return ret_value
                return Fix(meta=meta)  # Length fixed successfully
            elif pre[-3] == push_imm8 and pre[-2] == old_len:
                # push len ; before
                fpoke(fn, offset - 2, new_len)
                meta.length = 'push'
                meta.fixed = 'yes'
                return Fix(meta=meta)
            elif aft and aft[0] == push_imm8 and aft[1] == old_len:
                # push len ; after
                meta.length = 'push'
                if not jmp:
                    fpoke(fn, next_off + 1, new_len)
                    meta.fixed = 'yes'
                    return Fix(meta=meta)
                elif jmp == jmp_near:
                    ret_value = Fix(
                        src_off=old_next + 1,
                        new_code=bytes((push_imm8, new_len)),
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
                                (mov_rm_reg | 1, join_byte(1, Reg.ecx, 4), join_byte(0, 4, Reg.esp), 8)
                            ),  # mov [ESP+8], ECX
                            dest_off=next_off + i + 5 + displacement
                        )
                        ret_value.meta = meta
                        return ret_value
            elif pre[-2] == mov_reg_rm | 1 and pre[-1] & 0xf8 == join_byte(3, Reg.edi, 0):
                # mov edi, reg
                meta.length = 'edi'
                # There's no code in DF that passes this condition. Leaved just in case.
                # TODO: Drop it
                i = find_instruction(aft, call_near)
                if i is not None:
                    displacement = from_dword(aft[i + 1:i + 5], signed=True)
                    ret_value = Fix(
                        src_off=next_off + i + 1,
                        new_code=mach_strlen((mov_reg_rm | 1, join_byte(3, Reg.edi, Reg.ecx))),  # mov edi, ecx
                        dest_off=next_off + i + 5 + displacement,
                        op=call_near
                    )
                    ret_value.meta = meta
                    return ret_value
            elif aft and match_mov_reg_imm32(aft[:5], Reg.edi, old_len):
                # mov edi, len ; after
                meta.length = 'edi'
                if not jmp:
                    fpoke4(fn, next_off + 1, new_len)
                    meta.fixed = 'yes'
                    return Fix(meta=meta)
                elif jmp == jmp_near:
                    ret_value = Fix(
                        src_off=old_next + 1,
                        new_code=bytes((mov_reg_imm | 8 | Reg.edi.code,)) + to_dword(new_len),
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
                            new_code=mach_strlen((mov_reg_rm | 1, join_byte(3, Reg.edi, Reg.ecx))),  # mov edi, ecx
                            dest_off=next_off + i + 5 + displacement,
                            op=call_near
                        )
                        ret_value.meta = meta
                        return ret_value
            elif pre[-4] == lea and pre[-3] & 0xf8 == join_byte(1, Reg.edi, 0) and pre[-2] != 0:
                # Possible to be `lea edi, [reg+N]`
                displacement = to_signed(pre[-2], 8)
                if displacement == old_len:
                    # lea edi, [reg+old_len]
                    meta.length = 'edi'
                    fpoke(fn, offset - 2, new_len)
                    meta.fixed = 'yes'
                    return Fix(meta=meta)
            elif (aft and aft[0] == mov_reg_rm | 1 and aft[1] & 0xf8 == join_byte(3, Reg.ecx, 0) and
                  aft[2] == push_imm8 and aft[3] == old_len):
                # mov ecx, reg; push imm8
                meta.length = 'push'
                if not jmp:
                    fpoke(fn, next_off + 3, new_len)
                    meta.fixed = 'yes'
                    return Fix(meta=meta)
                elif jmp == jmp_near:
                    # TODO: Handle this case
                    meta.fixed = 'not implemented'
                    return Fix(meta=meta)
                else:
                    meta.fixed = 'no'
                    return Fix(meta=meta)
        elif reg == Reg.esi.code and isinstance(func, tuple) and func[0].startswith('rep'):
            # Sample code:
            # ; old_len = 22
            # ; r = (old_len+1) % 4 = 3 (3 bytes moved with 1 movsw and 1 movsb)
            # mov ecx, 5 ; 5 = (old_len + 1) // 4
            # mov esi, strz_Store_Item_in_Hospital_dc4f40
            # lea edi, [dest]
            # repz movsd
            # movsw
            # movsb
            meta.string.add('esi')
            r = (old_len + 1) % 4
            dword_count = (old_len + 1) // 4
            new_dword_count = (new_len - r) // 4 + 1
            mod_1_ecx_0 = join_byte(1, Reg.ecx, 0)
            if match_mov_reg_imm32(pre[-6:-1], Reg.ecx, dword_count):
                # mov ecx, dword_count
                fpoke4(fn, offset - 5, new_dword_count)
                meta.length = 'ecx*4'
                meta.fixed = 'yes'
                return Fix(meta=meta)
            elif pre[-4] == lea and pre[-3] & 0xf8 == mod_1_ecx_0 and pre[-2] == dword_count:
                # lea ecx, [reg+dword_count]  ; assuming that reg value == 0
                fpoke(fn, offset - 2, new_dword_count)
                meta.length = 'ecx*4'
                meta.fixed = 'yes'
                return Fix(meta=meta)
            elif new_len > old_len:
                # ecx modification code was not found. TODO: handle this case properly.
                if jmp:
                    meta.fixed = 'no'
                    return Fix(meta=meta)
                elif aft:
                    for line in disasm(aft, start_address=next_off):
                        if line.mnemonic != 'db':
                            break
                        offset = line.address
                        line_data = line.data
                        if line_data[0] == Prefix.rep:
                            meta.length = 'ecx*4'
                            meta.fixed = 'no'
                            return Fix(meta=meta)
                        elif line_data[0] == jmp_near:
                            assert line.operands is not None
                            next_off_2 = line.operands[0].value
                            aft = read_bytes(fn, offset, count_after)

                            skip = None
                            if match_mov_reg_imm32(aft[:5], Reg.ecx, dword_count):
                                skip = 5
                            elif aft[0] == lea and aft[1] & 0xf8 == mod_1_ecx_0 and aft[2] == dword_count:
                                skip = 3

                            if skip is not None:
                                meta.length = 'ecx*4'
                                ret_value = Fix(
                                    src_off=line.address + 1,
                                    new_code=bytes((mov_reg_imm | 8 | Reg.ecx.code,)) + to_dword(dword_count),
                                    dest_off=next_off_2 + skip
                                )
                                ret_value.meta = meta
                                return ret_value

                            meta.fixed = 'no'
                            return Fix(meta=meta)
                        elif len(line_data) == 5 and match_mov_reg_imm32(line_data, Reg.ecx, dword_count):
                            fpoke4(fn, line.address + 1, new_dword_count)
                            meta.length = 'ecx*4'
                            meta.fixed = 'yes'
                            return Fix(meta=meta)
                        elif line_data[0] == lea and line_data[1] & 0xf8 == mod_1_ecx_0 and line_data[2] == dword_count:
                            fpoke(fn, line.address + 2, new_dword_count)
                            meta.length = 'ecx*4'
                            meta.fixed = 'yes'
                            return Fix(meta=meta)
                    return Fix(meta=meta)
        else:
            meta.string = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'][reg]
        return Fix(meta=meta)
    elif (pre[-1] & 0xFE == mov_acc_mem or (pre[-2] & 0xFE == mov_reg_rm and
                                            pre[-1] & 0xC7 == join_byte(0, 0, 5)) or  # mov
          pre[-3] == 0x0F and pre[-2] in {x0f_movups, x0f_movaps} and
          pre[-1] & 0xC7 == join_byte(0, 0, 5)):  # movups or movaps
        # mov eax, [addr] or mov reg, [addr]
        meta.string.add('mov')

        next_off = offset - get_start(pre)
        aft = read_bytes(fn, next_off, count_after_for_get_length)
        try:
            get_length_info = get_length(aft, old_len, original_string_address)
        except (ValueError, IndexError) as err:
            meta.fixed = 'no'
            meta.cause = repr(err)
            return Fix(meta=meta)

        if get_length_info.pokes:
            for off, b in get_length_info.pokes.items():
                fpoke(fn, next_off + off, b)

        if new_len <= old_len and not get_length_info.pokes:
            meta.fixed = 'not needed'
            return Fix(meta=meta)
        else:
            fix = get_fix_for_moves(get_length_info, new_len, string_address, meta)

            if meta.fixed == 'yes':
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
        meta.func = FunctionInformation('strcpy')
        meta.string.add('mov byte')
        meta.fixed = 'not needed'
        return Fix(meta=meta)  # No need fixing
    elif pre[-1] == add_acc_imm | 1:
        # add reg, offset string
        meta.func = FunctionInformation('array')
        meta.string.add('add offset')
        meta.fixed = 'not needed'
        return Fix(meta=meta)
    elif pre[-2] == op_rm_imm | 1 and pre[-1] & 0xF8 == 0xF8:
        # cmp reg, offset string
        meta.string.add('cmp reg')
    elif pre[-4] == mov_rm_imm | 1 and pre[-3] == join_byte(1, 0, 4) and pre[-2] == join_byte(0, 4, Reg.esp):
        # mov [esp+N], offset string
        meta.string.add('mov var')
        meta.fixed = 'not needed'
    meta.prev_bytes = ' '.join('%02X' % x for x in pre[-4:])
    return Fix(meta=meta)


@dataclass
class GetLengthResult:
    deleted_relocs: Set[int]
    added_relocs: Set[int]
    dest: Operand
    length: int
    saved_mach: bytes
    nops: Mapping[int, int] = field(default_factory=dict)
    pokes: Mapping[int, Union[int, bytes]] = field(default_factory=dict)


def is_empty(reg_state: Mapping[Reg, int], reg: Reg):
    return reg_state[reg.parent] is None or reg_state[reg.parent] == 0


def get_length(data: bytes,
               oldlen: int,
               original_string_address: int = None,
               reg_state: dict = None,
               dest: Optional[Operand] = None) -> GetLengthResult:

    def belongs_to_the_string(ref_value):
        osa = original_string_address
        return osa is None or 0 <= ref_value - osa < oldlen

    def valid_reference(ref_value):
        return 0x400000 <= ref_value < 0x80000000

    copied_len = 0
    oldlen += 1

    # A dict to store states of registers
    # Possible states:
    # * None - unknown or empty: state unknown or freed by an instruction not related to the string copying
    # * -1   - not empty: a value which is not related to the string copying is stored here
    # * 0    - empty: freed by string copying instruction
    # * > 0  - not empty: a value of the specific size is stored in the register
    reg_state = reg_state or {reg.parent: None for reg in Reg if reg.type is not RegType.segment}

    deleted_relocs = set()
    added_relocs = set()  # Added relocs offsets are relative to the start of saved_mach
    saved_mach = bytes()
    not_moveable_after = None

    def is_moveable():
        return not_moveable_after is None

    pokes = dict()  # eg. fixes of jumps
    nops = dict()

    length = None
    for line in disasm(data):
        offset = line.address
        assert copied_len <= oldlen

        if copied_len == oldlen:
            length = offset
            break

        if line.mnemonic == 'db':
            raise ValueError('Unknown instruction encountered: '
                             + hexlify(data[line.address:line.address + 8]).decode())

        if line.mnemonic.startswith('mov') and not line.mnemonic.startswith('movs'):
            assert line.operands is not None
            left_operand, right_operand = line.operands
            if left_operand.get_type() in {OperandType.general_purpose_register, OperandType.xmm_register}:
                # mov reg, [...]
                assert left_operand.reg is not None

                if (not is_empty(reg_state, left_operand.reg) and
                        left_operand.reg not in {right_operand.base_reg, right_operand.index_reg}):
                    warn(f'{left_operand} register is already marked as occupied. '
                         f'String address: 0x{original_string_address:x}', stacklevel=2)

                if right_operand.get_type() is OperandType.absolute_memory_reference:
                    # mov reg, [mem]
                    local_offset = line.data.index(to_dword(right_operand.disp))
                    if belongs_to_the_string(right_operand.disp):
                        reg_state[left_operand.reg.parent] = left_operand.data_size
                        deleted_relocs.add(offset + local_offset)
                        if not is_moveable():
                            nops[offset] = len(line.data)
                    else:
                        reg_state[left_operand.reg.parent] = -1
                        # This may be a reference to another string, thus it is not moveable
                        not_moveable_after = not_moveable_after or offset
                elif right_operand.get_type() is OperandType.immediate_value and valid_reference(right_operand.value):
                    # This may be a reference to another string
                    not_moveable_after = not_moveable_after or offset
                else:
                    # `mov reg1, [reg2+disp]` or `mov reg, imm`
                    reg_state[left_operand.reg.parent] = -1
                    if is_moveable():
                        if valid_reference(right_operand.disp):
                            value = right_operand.disp
                            local_offset = line.data.rindex(to_dword(value))
                            deleted_relocs.add(offset + local_offset)
                            added_relocs.add(len(saved_mach) + local_offset)
                        saved_mach += line.data
            elif left_operand.get_type() in {OperandType.relative_memory_reference,
                                             OperandType.absolute_memory_reference}:
                # `mov [reg1+disp], reg2` or `mov [off], reg`
                if right_operand.get_type() in {OperandType.general_purpose_register,
                                                OperandType.xmm_register}:

                    assert right_operand.reg is not None
                    if reg_state[right_operand.reg.parent] is None or reg_state[right_operand.reg.parent] < 0:
                        # It can be a part of a copying code of another string. Leave it as is.
                        not_moveable_after = not_moveable_after or offset
                        reg_state[right_operand.reg.parent] = None  # Mark the register as free
                    else:
                        assert left_operand.index_reg is None

                        if reg_state[right_operand.reg.parent] == 0:
                            raise ValueError('Copying of a string to several diferent locations not supported.')

                        if (dest is None or (dest.get_type() == left_operand.get_type() and
                                             dest.base_reg == left_operand.base_reg and
                                             dest.disp > left_operand.disp)):
                            dest = left_operand

                        if left_operand.get_type() is OperandType.absolute_memory_reference:
                            deleted_relocs.add(offset + line.data.index(to_dword(left_operand.disp)))

                        copied_len += left_operand.data_size or right_operand.data_size

                        if not is_moveable():
                            nops[offset] = len(line.data)

                        reg_state[right_operand.reg.parent] = 0  # Mark the register as freed
                elif is_moveable():
                    if (right_operand.get_type() is OperandType.absolute_memory_reference
                            or (right_operand.get_type() is OperandType.immediate_value
                                and valid_reference(right_operand.value))):
                        # TODO: check if this actually a reference. Until then just skip
                        not_moveable_after = not_moveable_after or offset
                        continue
                        # value = right_operand.disp
                        # if right_operand.get_type() is OperandType.absolute_memory_reference
                        # else right_operand.value
                        # local_offset = line.data.rindex(to_dword(value))  # use rindex() to find the second operand
                        # deleted_relocs.add(offset + local_offset)
                        # added_relocs.add(len(saved_mach) + local_offset)

                    if left_operand.get_type() == OperandType.absolute_memory_reference:
                        value = left_operand.disp
                        local_offset = line.data.index(to_dword(value))
                        deleted_relocs.add(offset + local_offset)
                        added_relocs.add(len(saved_mach) + local_offset)

                    saved_mach += line.data
            else:
                # Segment register etc.
                raise ValueError('Unallowed left operand type: %s, type is %r, instruction is `%s`' %
                                 (left_operand, left_operand.get_type(), str(line)))
        elif line.mnemonic == 'lea':
            assert line.operands is not None
            left_operand, right_operand = line.operands

            # Left operand of lea is always a register
            assert left_operand.reg is not None
            reg_state[left_operand.reg.parent] = -1
            if (dest is not None
                    and dest.base_reg == right_operand.base_reg
                    and dest.disp == right_operand.disp):

                dest = Operand(base_reg=left_operand.reg, disp=0)

            saved_mach += line.data
        elif line.mnemonic.startswith('j'):
            if line.mnemonic.startswith('jmp'):
                not_moveable_after = not_moveable_after or offset

                assert line.operands is not None
                data_after_jump = data[line.operands[0].value:]
                if not data_after_jump:
                    raise ValueError('Cannot jump: jump destination not included in the passed machinecode.')

                result = get_length(data_after_jump, oldlen - copied_len - 1,
                                    original_string_address, reg_state, dest)
                dest = result.dest
                if 'short' in line.mnemonic:
                    disp = line.data[1] + result.length
                    pokes = {offset + 1: disp}
                else:
                    disp = from_dword(line.data[1:]) + result.length
                    pokes = {offset + 1: to_dword(disp)}
                break
            else:
                raise ValueError('Conditional jump encountered at offset 0x%02x' % line.address)
        else:
            if line.prefix and line.prefix.name.startswith('rep'):
                reg_state[Reg.ecx] = None  # Mark ecx as unoccupied
            if line.mnemonic.startswith('movs'):
                reg_state[Reg.esi] = None
                reg_state[Reg.edi] = None
            elif line.mnemonic.startswith('set'):
                # setz, setnz etc.
                assert line.operands is not None
                assert line.operands[0].reg is not None
                reg_state[line.operands[0].reg.parent] = -1
            elif line.mnemonic == 'push':
                assert line.operands is not None
                if line.operands[0].get_type() is OperandType.general_purpose_register:
                    assert line.operands[0].reg is not None
                    reg_state[line.operands[0].reg.parent] = None  # Mark the pushed register as unoccupied
                not_moveable_after = not_moveable_after or offset
            elif line.mnemonic == 'pop':
                assert line.operands is not None
                if line.operands[0].get_type() is OperandType.general_purpose_register:
                    assert line.operands[0].reg is not None
                    reg_state[line.operands[0].reg.parent] = -1
                not_moveable_after = not_moveable_after or offset
            elif line.mnemonic in {'add', 'sub', 'and', 'xor', 'or'}:
                assert line.operands is not None
                if line.operands[0].get_type() is OperandType.general_purpose_register:
                    assert line.operands[0].reg is not None
                    if line.operands[0].reg == Reg.esp:
                        not_moveable_after = not_moveable_after or offset
                    reg_state[line.operands[0].reg.parent] = -1
            elif line.mnemonic.startswith('call'):
                not_moveable_after = not_moveable_after or offset
            elif line.mnemonic.startswith('ret'):
                break

            if is_moveable():
                if line.operands:
                    abs_refs = [operand for operand in line.operands
                                if operand.get_type() in {OperandType.absolute_memory_reference,
                                                          OperandType.immediate_value}]

                    for ref in abs_refs:
                        value = ref.disp if ref.get_type() is OperandType.absolute_memory_reference else ref.value

                        if ref.get_type() is OperandType.immediate_value and not valid_reference(value):
                            continue

                        local_offset = line.data.index(to_dword(value))
                        deleted_relocs.add(offset + local_offset)
                        added_relocs.add(len(saved_mach) + local_offset)

                saved_mach += line.data

    if not length and copied_len == oldlen:
        length = len(data)
    if not is_moveable():
        length = not_moveable_after  # return length of code which can be moved harmlessly
    if length is None:
        raise ValueError('Length of the copying code not recognized.')
    if dest is None:
        raise ValueError('Destination not recognized.')

    result = GetLengthResult(
        length=length,
        dest=dest,
        deleted_relocs=deleted_relocs,
        saved_mach=saved_mach,
        added_relocs=added_relocs
    )

    if nops:
        result.nops = nops

    if pokes:
        result.pokes = pokes

    return result


def add_to_new_section(fn, new_section_offset, s: bytes, alignment=4, padding_byte=b'\0'):
    aligned = align(len(s), alignment)
    s = s.ljust(aligned, padding_byte)
    fpoke(fn, new_section_offset, s)
    return new_section_offset + aligned


def fix_df_exe(fn, pe, codepage, original_codepage, trans_table: Mapping[str, str], debug=False):
    print("Finding cross-references...")

    image_base = pe.optional_header.image_base
    sections = pe.section_table

    # Getting addresses of all relocatable entries
    relocs = set(pe.relocation_table)
    relocs_to_add: Set[int] = set()
    relocs_to_remove: Set[int] = set()

    # Getting cross-references:
    xref_table = get_cross_references(fn, relocs, sections, image_base)

    # --------------------------------------------------------
    if codepage:
        print("Searching for charmap table...")
        needle = search_charmap(fn, sections, xref_table)

        if needle is None:
            print("Warning: charmap table not found. Skipping.")
        else:
            print("Charmap table found at offset 0x%X" % needle)

            try:
                print("Patching charmap table to %s..." % codepage)
                patch_unicode_table(fn, needle, codepage)
            except KeyError:
                print("Warning: codepage %s not implemented. Skipping." % codepage)
            else:
                print("Done.")

    # --------------------------------------------------------
    if debug:
        print("Preparing additional data section...")

    last_section = sections[-1]

    if last_section.name == b'.new':
        print("There is '.new' section in the file already.")
        return

    file_alignment = pe.optional_header.file_alignment
    section_alignment = pe.optional_header.section_alignment

    # New section prototype
    new_section = Section(
        name=b'.new',
        virtual_size=0,  # for now
        rva=align(last_section.rva + last_section.virtual_size,
                  section_alignment),
        physical_size=0xFFFFFFFF,  # for now
        physical_offset=align(last_section.physical_offset +
                              last_section.physical_size, file_alignment),
        flags=Section.IMAGE_SCN_CNT_INITIALIZED_DATA | Section.IMAGE_SCN_MEM_READ | Section.IMAGE_SCN_MEM_EXECUTE
    )

    new_section_offset = new_section.physical_offset

    # --------------------------------------------------------
    print("Translating...")

    strings = list(extract_strings(fn, xref_table, encoding=original_codepage, arrays=True))

    if debug:
        print("%d strings extracted." % len(strings))

        print("Leaving only strings, which have translations.")
        strings = [x for x in strings if x[1] in trans_table]
        print("%d strings remaining." % len(strings))
        if 0 < len(strings) <= 16:
            print('All remaining strings:')
            for meta in strings:
                print("0x{:x} : {!r}".format(*meta[:2]))

    fixes: MutableMapping[int, Fix] = defaultdict(Fix)
    metadata: MutableMapping[Tuple[str, int], Fix] = OrderedDict()
    delayed_pokes = dict()

    encoding = codepage if codepage else 'cp437'

    try:
        encoder_function = codecs.getencoder(encoding)
    except LookupError as ex:
        if encoding in get_codepages():
            encoder_function = get_encoder(encoding)
        else:
            raise ex

    for off, string, cap_len in strings:
        if string in trans_table:
            translation = trans_table[string]

            if string == translation:
                continue

            if off in xref_table:
                # Find the earliest reference to the string (even if it is a reference to the middle of the string)
                refs = find_earliest_midrefs(off, xref_table, len(string))
            else:
                refs = []

            is_long = cap_len < len(translation) + 1
            original_string_address = sections.offset_to_rva(off) + image_base

            try:
                encoded_translation = encoder_function(translation)[0] + b'\0'
            except UnicodeEncodeError:
                encoded_translation = encoder_function(translation, errors='replace')[0] + b'\0'
                print("Warning: some of characters in a translation strings can't be represented in {}, "
                      "they will be replaced with ? marks.".format(encoding))
                print("{!r}: {!r}".format(string, encoded_translation))

            if not is_long or off not in xref_table:
                # Overwrite the string with the translation in-place
                fpoke(fn, off, encoded_translation.ljust(cap_len, b'\0'))
                string_address = original_string_address
            else:
                # Add the translation to the separate section
                str_off = new_section_offset
                string_address = new_section.offset_to_rva(str_off) + image_base
                new_section_offset = add_to_new_section(fn, new_section_offset, encoded_translation)

            # Fix string length for each reference
            for ref in refs:
                ref_rva = sections.offset_to_rva(ref)
                if 0 <= (ref - sections[code_section].physical_offset) < sections[code_section].physical_size:
                    try:
                        fix = fix_len(fn, offset=ref, old_len=len(string), new_len=len(translation),
                                      string_address=string_address,
                                      original_string_address=original_string_address)
                    except Exception:
                        print('Catched %s exception on string %r at reference 0x%x' %
                              (sys.exc_info()[0], string, ref_rva + image_base))
                        raise
                else:
                    fix = Fix(meta=Metadata(fixed='not needed'))

                meta = fix.meta
                if 'cmp reg' in meta.string:
                    # This is probably a bound of an array, not a string reference
                    continue
                elif fix.new_code:
                    new_code = fix.new_code
                    assert isinstance(new_code, (bytes, bytearray, MachineCode))
                    src_off = fix.src_off
                    assert src_off is not None
                    fixes[src_off].add_fix(fix)
                else:
                    if fix.added_relocs:
                        # Add relocations of new references of moved items
                        relocs_to_add.update(item + ref_rva for item in fix.added_relocs)

                    if fix.pokes:
                        delayed_pokes.update({off + ref: val for off, val in fix.pokes.items()})

                # Remove relocations of the overwritten references
                if fix.deleted_relocs:
                    relocs_to_remove.update(item + ref_rva for item in fix.deleted_relocs)
                elif is_long and string_address:
                    fpoke4(fn, ref, string_address)

                metadata[(string, ref_rva + image_base)] = fix

    for offset, b in delayed_pokes.items():
        # print(hex(offset), b)
        fpoke(fn, offset, b)

    functions = extract_function_information(image_base, metadata, sections)

    if debug:
        print('\nGuessed function parameters:')
        for address, meta in sorted(functions.items(), key=itemgetter(0)):
            print('sub_%x: %r' % (sections[code_section].offset_to_rva(address) + image_base, meta))
        print()

    add_strlens(debug, fixes, functions, metadata)

    new_section_offset = apply_delayed_fixes(fixes, fn, new_section, new_section_offset, relocs_to_add, sections)

    # Write relocation table to the executable
    if relocs_to_add or relocs_to_remove:
        new_section_offset, relocs = update_relocation_table(debug, fn, image_base, new_section, new_section_offset, pe,
                                                             relocs, relocs_to_add, relocs_to_remove, sections)

    # Add new section to the executable
    if new_section_offset > new_section.physical_offset:
        add_new_section(file_alignment, fn, new_section, new_section_offset, pe, section_alignment, sections)

    # Check if the patched file is not broken
    print("Final check...")
    pe.reread()
    assert set(pe.relocation_table) == relocs, "Error: relocation table is broken"

    print('Done.')


def add_strlens(debug, fixes, functions, metadata):
    """
    Add strlen before call of functions for strings which length was not fixed
    """

    status_unknown = dict()
    not_fixed = dict()

    for string, fix in metadata.items():
        meta: Metadata = fix.meta
        if (meta.fixed is None or meta.fixed == 'no') and fix.new_code is None:
            func: FunctionInformation = meta.func
            if func is not None and func.info == 'call near':
                if functions[func.address].length is not None:
                    src_off = func.address
                    dest_off = func.operand
                    assert src_off is not None
                    src_off += 1
                    code_chunk: Optional[Iterable[int]] = None
                    if functions[dest_off].length == 'push':
                        # mov [esp+8], ecx
                        code_chunk = (mov_rm_reg | 1, join_byte(1, Reg.ecx, 4), join_byte(0, 4, Reg.esp), 8)
                    elif functions[dest_off].length == 'edi':
                        code_chunk = (mov_reg_rm | 1, join_byte(3, Reg.edi, Reg.ecx))  # mov edi, ecx

                    if code_chunk:
                        new_code = mach_strlen(code_chunk)
                        fix = Fix(src_off=src_off, new_code=new_code, dest_off=dest_off)
                        fixes[src_off].add_fix(fix)
                        meta.fixed = 'yes'
                    else:
                        meta.fixed = 'no'
                else:
                    meta.fixed = 'not needed'

            if debug:
                if meta.fixed is None:
                    status_unknown[string[1]] = (string[0], meta)
                elif meta.fixed == 'no':
                    not_fixed[string[1]] = (string[0], meta)
    if debug:
        for ref, (string, meta) in sorted(not_fixed.items(), key=lambda x: x[0]):
            print('Length not fixed: %s (reference from 0x%x)' % (myrepr(string), ref), meta)

        print()

        for ref, (string, meta) in sorted(status_unknown.items(), key=lambda x: x[0]):
            print('Status unknown: %s (reference from 0x%x)' % (myrepr(string), ref), meta)


def update_relocation_table(debug, fn, image_base, new_section, new_section_offset, pe, relocs, relocs_to_add,
                            relocs_to_remove, sections):
    if relocs_to_remove - relocs:
        warn("Trying to remove some relocations which weren't in the original list: " +
             int_list_to_hex_str(item + image_base for item in (relocs_to_remove - relocs)))
    relocs -= relocs_to_remove
    relocs |= relocs_to_add
    if debug:
        print("\nRemoved relocations:")
        print("[%s]" % '\n'.join(textwrap.wrap(int_list_to_hex_str(relocs_to_remove), 80)))
        print("\nAdded relocations:")
        print("[%s]" % '\n'.join(textwrap.wrap(int_list_to_hex_str(relocs_to_add), 80)))
    reloc_table = RelocationTable.build(relocs)
    new_size = reloc_table.size
    data_directory = pe.data_directory
    relocation_table_offset = sections.rva_to_offset(data_directory.basereloc.virtual_address)
    relocation_table_size = data_directory.basereloc.size
    relocation_section = sections[sections.which_section(offset=relocation_table_offset)]
    if new_size <= relocation_section.physical_size:
        fn.seek(relocation_table_offset)
        reloc_table.to_file(fn)

        if new_size < relocation_table_size:
            # Clear empty bytes after the relocation table
            fn.seek(relocation_table_offset + new_size)
            fn.write(bytes(relocation_table_size - new_size))

        # Update data directory table
        data_directory.basereloc.size = new_size
        data_directory.rewrite()
    else:
        # Write relocation table to the new section
        with io.BytesIO() as buffer:
            reloc_table.to_file(buffer)

            data_directory.basereloc.size = new_size
            data_directory.basereloc.virtual_address = new_section.offset_to_rva(new_section_offset)
            data_directory.rewrite()
            new_section_offset = add_to_new_section(fn, new_section_offset, buffer.getvalue())
    return new_section_offset, relocs


def add_new_section(file_alignment, fn, new_section, new_section_offset, pe, section_alignment, sections):
    file_size = align(new_section_offset, file_alignment)
    new_section.physical_size = file_size - new_section.physical_offset
    print("Adding new data section...")
    # Align file size
    if file_size > new_section_offset:
        fn.seek(file_size - 1)
        fn.write(b'\0')
    # Set the new section virtual size
    new_section.virtual_size = new_section_offset - new_section.physical_offset
    # Write the new section info
    fn.seek(pe.nt_headers.offset + pe.nt_headers.sizeof() + len(sections) * Section.sizeof())
    new_section.write(fn)
    # Fix number of sections
    pe.file_header.number_of_sections = len(sections) + 1
    # Fix ImageSize field of the PE header
    pe.optional_header.size_of_image = align(new_section.rva + new_section.virtual_size, section_alignment)
    pe.file_header.rewrite()
    pe.optional_header.rewrite()


def apply_delayed_fixes(fixes, fn, new_section, new_section_offset, relocs_to_add, sections):
    # Delayed fix
    for fix in fixes.values():
        src_off = fix.src_off
        assert src_off is not None
        mach = fix.new_code
        assert mach is not None

        hook_rva = new_section.offset_to_rva(new_section_offset)

        dest_off = mach.fields.get('dest', None) if isinstance(mach, MachineCode) else fix.dest_off

        if isinstance(mach, MachineCode):
            for field, value in mach.fields.items():
                if value is not None:
                    mach.fields[field] = sections[code_section].offset_to_rva(value)
            mach.origin_address = hook_rva

        if dest_off is not None:
            dest_rva = sections[code_section].offset_to_rva(dest_off)
            if isinstance(mach, MachineCode):
                mach.fields['dest'] = dest_rva
            else:
                disp = dest_rva - (hook_rva + len(mach) + 5)  # 5 is a size of jmp near + displacement
                # Add jump from the hook
                mach += bytes((jmp_near,)) + to_dword(disp, signed=True)

        assert mach is not None
        # Write the hook to the new section
        new_section_offset = add_to_new_section(fn, new_section_offset, bytes(mach), padding_byte=int3)

        # If there are absolute references in the code, add them to relocation table
        if fix.added_relocs or isinstance(mach, MachineCode) and list(mach.absolute_references):
            new_refs = set(mach.absolute_references) if isinstance(mach, MachineCode) else set()

            if fix.added_relocs:
                new_refs.update(fix.added_relocs)

            relocs_to_add.update(hook_rva + item for item in new_refs)

        if fix.pokes:
            for off, b in fix.pokes.items():
                fpoke(fn, off, b)

        src_rva = sections[code_section].offset_to_rva(src_off)
        disp = hook_rva - (src_rva + 4)  # 4 is a size of a displacement itself
        fpoke(fn, src_off, to_dword(disp, signed=True))
    return new_section_offset


def extract_function_information(image_base: int,
                                 metadata: Mapping[Tuple[str, int], Fix],
                                 sections: List[Section]) -> MutableMapping[int, Metadata]:
    """
    Extract information of functions parameters
    """

    functions: MutableMapping[int, Metadata] = defaultdict(Metadata)
    for fix in metadata.values():
        meta = fix.meta
        assert meta is not None
        if meta.func and meta.func.info == 'call near':
            offset = meta.func.address
            assert offset is not None
            address = sections[code_section].offset_to_rva(offset) + image_base
            if meta.string:
                str_param = meta.string
                if not functions[offset].string:
                    functions[offset].string.update(str_param)
                elif str_param not in functions[offset].string:
                    print('Warning: possible function parameter recognition collision for sub_%x: %r not in %r' %
                          (address, str_param, functions[offset].string))
                    functions[offset].string.update(str_param)

            if meta.length is not None:
                len_param = meta.length
                if functions[offset].length is None:
                    functions[offset].length = len_param
                elif functions[offset].length != len_param:
                    raise ValueError('Function parameter recognition collision for sub_%x: %r != %r' %
                                     (address, functions[offset].length, len_param))

    return functions


def int_list_to_hex_str(s):
    return ', '.join(hex(x) for x in sorted(s))


def find_earliest_midrefs(offset, xref_table, length):
    increment = 4
    k = increment
    references = xref_table[offset]
    while k < length + 1:
        if offset + k in xref_table:
            for j, ref in enumerate(references):
                mid_refs = xref_table[offset + k]
                for mid_ref in reversed(sorted(mid_refs)):
                    if mid_ref < ref and ref - mid_ref < 70:  # Empirically picked number
                        references[j] = mid_ref
                        break

        while k + increment >= length + 1 and increment > 1:
            increment //= 2

        k += increment
    return references


def myrepr(s):
    text = repr(s)
    if sys.stdout:
        b = text.encode(sys.stdout.encoding, 'backslashreplace')
        text = b.decode(sys.stdout.encoding, 'strict')
    return text
