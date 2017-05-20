
import csv
from collections import defaultdict
from warnings import warn
from contextlib import suppress
from binascii import hexlify

from .binio import fpeek, fpoke4, fpoke, pad_tail, from_dword, to_dword
from .disasm import *
from .machinecode import MachineCode, Reference
from .opcodes import *


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


code, rdata, data = range(3)


def get_cross_references(fn, relocs, sections, image_base):
    xrefs = defaultdict(list)
    code_upper_bound = sections[code].rva + sections[code].virtual_size
    # Read all the file sections:
    base_offset = sections[code].physical_offset
    size = sections[-1].physical_offset + sections[-1].physical_size - base_offset
    buffer = fpeek(fn, base_offset, size)
    for reloc in relocs:
        reloc_off = sections.rva_to_offset(reloc)
        local_off = reloc_off - base_offset
        obj_rva = from_dword(buffer[local_off:local_off+4]) - image_base
        reloc += sections[code].physical_offset
        if code_upper_bound <= obj_rva:
            obj_off = sections.rva_to_offset(obj_rva)
            if obj_off is not None:
                xrefs[obj_off].append(reloc_off)

    return xrefs


MAX_LEN = 0x80


def mach_strlen(code_chunk):
    return (bytes((
                push_reg | Reg.ecx.code,  # push ecx
                xor_rm_reg | 1, join_byte(3, Reg.ecx, Reg.ecx),  # xor ecx, ecx
                # @@:
                cmp_rm_imm, join_byte(0, 7, 4), join_byte(0, Reg.ecx, Reg.eax), 0x00,  # cmp byte [eax+ecx], 0
                jcc_short | Cond.z, 0x0b,  # jz success
                cmp_rm_imm | 1, join_byte(3, 7, Reg.ecx), MAX_LEN, 0x00, 0x00, 0x00,  # cmp ecx, MAX_LEN
                jcc_short | Cond.g, 3+len(code_chunk),  # jg skip
                inc_reg | Reg.ecx.code,  # inc ecx
                jmp_short, 0xef  # jmp @b
            )) +
            # success:
            bytes(code_chunk) +
            # skip:
            bytes((pop_reg | Reg.ecx.code,)))


def find_instruction(s, instruction):
    for line in disasm(s):
        assert(line.mnemonic != 'db')
        if line.data[0] == instruction:
            return line.address
    return None


class Trace:
    not_follow = 0
    follow = 1
    stop = 2
    forward_only = 3


def trace_code(fn, offset, stop_cond, trace_jmp=Trace.follow, trace_jcc=Trace.forward_only, trace_call=Trace.stop):
    s = fpeek(fn, offset, count_after)
    with suppress(IndexError):
        for line in disasm(s, offset):
            # print('%-8x\t%-16s\t%s' % (line.address, ' '.join('%02x' % x for x in line.data), line))
            if line.mnemonic == 'db':
                return None
            elif stop_cond(line):  # Stop when the stop_cond returns True
                return line
            elif line.mnemonic.startswith('jmp'):
                if trace_jmp == Trace.not_follow:
                    pass
                elif trace_jmp == Trace.follow:
                    return trace_code(fn, int(line.operands[0]), stop_cond, trace_jmp, trace_jcc, trace_call)
                elif trace_jmp == Trace.stop:
                    return line
                elif trace_jmp == Trace.forward_only:
                    if int(line.operands[0]) > line.address:
                        return trace_code(fn, int(line.operands[0]), stop_cond, trace_jmp, trace_jcc, trace_call)
            elif line.mnemonic.startswith('j'):
                if trace_jcc == Trace.not_follow:
                    pass
                elif trace_jcc == Trace.follow:
                    return trace_code(fn, int(line.operands[0]), stop_cond, trace_jmp, trace_jcc, trace_call)
                elif trace_jcc == Trace.stop:
                    return line
                elif trace_jcc == Trace.forward_only:
                    if int(line.operands[0]) > line.address:
                        return trace_code(fn, int(line.operands[0]), stop_cond, trace_jmp, trace_jcc, trace_call)
            elif line.mnemonic.startswith('call'):
                if trace_call == Trace.not_follow:
                    pass
                elif trace_call == Trace.follow:
                    returned = trace_code(fn, int(line.operands[0]), stop_cond, trace_jmp, trace_jcc, trace_call)
                    if returned is None or not returned.mnemonic.startswith('ret'):
                        return returned
                elif trace_call == Trace.stop:
                    return line
                elif trace_call == Trace.forward_only:
                    if int(line.operands[0]) > line.address:
                        return trace_code(fn, int(line.operands[0]), stop_cond, trace_jmp, trace_jcc, trace_call)
            elif line.mnemonic.startswith('ret'):
                return line
    return None


def match_mov_reg_imm32(b, reg, imm):
    assert len(b) == 5, b
    return b[0] == mov_reg_imm | 8 | int(reg) and from_dword(b[1:]) == imm


def get_fix_for_moves(get_length_info, newlen, string_address, meta):
    x = get_length_info

    added_relocs = x['added_relocs']

    mach, new_refs = mach_memcpy(string_address, x['dest'], newlen + 1)
    if x['saved_mach']:
        mach = x['saved_mach'] + mach  # If there is "lea edi, [dest]", put it before the new code
        new_refs = {item + len(x['saved_mach']) for item in new_refs}

    added_relocs.update(new_refs)

    proc = None
    if len(mach) > x['length']:
        # if memcpy code is to long, try to write it into the new section and make call to it
        if isinstance(mach, bytes):
            mach = bytearray(mach)

        mach.append(ret_near)
        proc = mach

        mach = bytes((call_near,)) + bytes(4)  # leave zeros instead of displacement for now
        if len(mach) > x['length']:
            # Too tight here, even for a procedure call
            meta['fixed'] = 'no'
            meta['cause'] = 'to tight to call'
            return meta

    # Write replacement code
    mach = pad_tail(mach, x['length'], nop)
    pokes = {0: mach}

    # Nop-out old instructions
    if 'nops' in x:
        for off, count in x['nops'].items():
            pokes[off] = bytes(nop for _ in range(count))

    if proc:
        retvalue = dict(
            # src_off=next_off + 1,
            new_code=proc,
            deleted_relocs=x['deleted_relocs'],
            added_relocs=added_relocs,  # These relocs belong to proc, not to the current code block
            pokes=pokes,
        )
    else:
        retvalue = dict(
            deleted_relocs=x['deleted_relocs'],
            added_relocs=added_relocs,
            pokes=pokes,
        )

    meta['fixed'] = 'yes'
    retvalue.update(meta)
    return retvalue


def get_start(s):
    i = None
    if s[-1] & 0xfe == mov_acc_mem:
        i = 1
    elif s[-2] & 0xf8 == mov_rm_reg and s[-1] & 0xc7 == 0x05:
        i = 2
    elif s[-3] == 0x0f and s[-2] & 0xfe == x0f_movups and s[-1] & 0xc7 == 0x05:
        i = 3
        return i  # prefix is not allowed here

    if s[-1-i] == Prefix.operand_size:
        i += 1

    return i


count_before = 0x20
count_after = 0x100
count_after_for_get_length = 0x2000


def fix_len(fn, offset, oldlen, newlen, string_address, original_string_address):
    def which_func(offset, stop_cond=lambda _: False):
        disasm_line = trace_code(fn, offset, stop_cond=lambda cur_line: str(cur_line).startswith('rep') or
                                                                        stop_cond(cur_line))
        if disasm_line is None:
            result = ('not reached',)
        elif str(disasm_line).startswith('rep'):
            result = (str(disasm_line),)
        elif disasm_line.mnemonic.startswith('call'):
            try:
                result = (disasm_line.mnemonic, disasm_line.address, int(disasm_line.operands[0]))
            except ValueError:
                result = (disasm_line.mnemonic + ' indirect', disasm_line.address, str(disasm_line.operands[0]))
        else:
            result = ('not reached',)
        return result

    next_off = offset+4

    pre = fpeek(fn, offset-count_before, count_before)
    aft = fpeek(fn, next_off, count_after)
    jmp = None
    oldnext = next_off
    if aft[0] in {jmp_short, jmp_near} or aft[0] & 0xf0 == jcc_short:
        if aft[0] == jmp_short or aft[0] & 0xf0 == jcc_short:
            disp = to_signed(aft[1], width=8)
            next_off += 2 + disp
        elif aft[0] == jmp_near:
            disp = from_dword(aft[1:5], signed=True)
            next_off += 5 + disp
        jmp = aft[0]
        aft = fpeek(fn, next_off, count_after)
    elif aft[0] == call_near or (aft[0] == 0x0f and aft[1] == x0f_jcc_near):
        aft = None

    meta = dict()
    if pre[-1] == push_imm32:
        # push offset str
        meta['str'] = 'push'
        
        if pre[-3] == push_imm8 and pre[-2] == oldlen:
            fpoke(fn, offset-2, newlen)
            meta['len'] = 'push before'
            meta['fixed'] = 'yes'
        
        meta['func'] = which_func(oldnext)
    elif pre[-1] & 0xF8 == (mov_reg_imm | 8):
        # mov reg32, offset str
        reg = pre[-1] & 7

        def stop_func(disasm_line: DisasmLine):
            return disasm_line.operands and (
                (disasm_line.operands[0].type == 'reg gen' and disasm_line.operands[0].reg == reg) or
                (len(disasm_line.operands) > 1 and disasm_line.operands[1].type == 'ref rel' and
                 disasm_line.operands[1].base_reg == reg)
            )

        func = which_func(oldnext, stop_cond=stop_func)

        if isinstance(func, tuple):
            meta['func'] = func

        if reg == Reg.eax.code:
            # mov eax, offset str
            meta['str'] = 'eax'
            if from_dword(pre[-5:-1]) == oldlen:
                fpoke4(fn, offset-5, newlen)
                meta['fixed'] = 'yes'
                if pre[-6] == mov_reg_imm | 8 | Reg.edi.code:
                    meta['len'] = 'edi'
                    # mov edi, len before
                    if (oldlen == 15 or oldlen == 16) and aft and not jmp:
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
                            assert(line.mnemonic != 'db')
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
                                fix_cap = (MachineCode(mov_rm_imm | 1, join_byte(1, 0, Reg.esi), 0x14, to_dword(oldlen))
                                           if mov_esp_edi else None)

                                new_code = MachineCode(
                                    fix_cap,
                                    call_near, Reference.relative(name='func'),  # call near func
                                    # Restore original edi value for the case if it is used further in the code:
                                    mov_reg_imm | 8 | Reg.edi.code, to_dword(oldlen),  # mov edi, oldlen
                                    jmp_near, Reference.relative(name='return_addr'),  # jmp near return_addr
                                    func=line.operands[0].value,
                                    return_addr=line.address + 5
                                )
                                retvalue = dict(
                                    src_off=line.address + 1,
                                    new_code=new_code,
                                    pokes={line.address: jmp_near}  # Replace call with jump
                                )
                                retvalue.update(meta)
                                return retvalue
                return meta  # Length fixed successfully
            elif pre[-3] == push_imm8 and pre[-2] == oldlen:
                # push len ; before
                fpoke(fn, offset-2, newlen)
                meta.update(dict(len='push', fixed='yes'))
                return meta
            elif aft and aft[0] == push_imm8 and aft[1] == oldlen:
                # push len ; after
                meta['len'] = 'push'
                if not jmp:
                    fpoke(fn, next_off+1, newlen)
                    meta['fixed'] = 'yes'
                    return meta
                elif jmp == jmp_near:
                    retvalue = dict(
                        src_off=oldnext+1,
                        new_code=bytes((push_imm8, newlen)),
                        dest_off=next_off+2
                    )
                    retvalue.update(meta)
                    return retvalue
                else:  # jmp == jmp_short
                    i = find_instruction(aft, call_near)
                    if i is not None:
                        disp = from_dword(aft[i+1:i+5], signed=True)
                        retvalue = dict(
                            src_off=next_off+i+1,
                            new_code=mach_strlen(
                                (mov_rm_reg | 1, join_byte(1, Reg.ecx, 4), join_byte(0, 4, Reg.esp), 8)
                            ),  # mov [ESP+8], ECX
                            dest_off=next_off+i+5+disp
                        )
                        retvalue.update(meta)
                        return retvalue
            elif pre[-2] == mov_reg_rm | 1 and pre[-1] & 0xf8 == join_byte(3, Reg.edi, 0):
                # mov edi, reg
                meta['len'] = 'edi'
                # There's no code in DF that passes this condition. Leaved just in case.
                # TODO: Drop it
                i = find_instruction(aft, call_near)
                if i is not None:
                    disp = from_dword(aft[i+1:i+5], signed=True)
                    retvalue = dict(
                        src_off=next_off+i+1,
                        new_code=mach_strlen((mov_reg_rm | 1, join_byte(3, Reg.edi, Reg.ecx))),  # mov edi, ecx
                        dest_off=next_off+i+5+disp,
                        op=call_near
                    )
                    retvalue.update(meta)
                    return retvalue
            elif aft and match_mov_reg_imm32(aft[:5], Reg.edi, oldlen):
                # mov edi, len ; after
                meta['len'] = 'edi'
                if not jmp:
                    fpoke4(fn, next_off+1, newlen)
                    meta['fixed'] = 'yes'
                    return meta
                elif jmp == jmp_near:
                    retvalue = dict(
                        src_off=oldnext+1,
                        new_code=bytes((mov_reg_imm | 8 | Reg.edi.code,)) + to_dword(newlen),
                        dest_off=next_off+5
                    )
                    retvalue.update(meta)
                    return retvalue
                else:  # jmp == jmp_short
                    i = find_instruction(aft, call_near)
                    if i is not None:
                        disp = from_dword(aft[i+1:i+5], signed=True)
                        retvalue = dict(
                            src_off=next_off+i+1,
                            new_code=mach_strlen((mov_reg_rm | 1, join_byte(3, Reg.edi, Reg.ecx))),  # mov edi, ecx
                            dest_off=next_off+i+5+disp,
                            op=call_near
                        )
                        retvalue.update(meta)
                        return retvalue
            elif pre[-4] == lea and pre[-3] & 0xf8 == join_byte(1, Reg.edi, 0) and pre[-2] != 0:
                # Possible to be `lea edi, [reg+N]`
                disp = to_signed(pre[-2], 8)
                if disp == oldlen:
                    # lea edi, [reg+oldlen]
                    meta['len'] = 'edi'
                    fpoke(fn, offset-2, newlen)
                    meta['fixed'] = 'yes'
                    return meta
            elif (aft and aft[0] == mov_reg_rm | 1 and aft[1] & 0xf8 == join_byte(3, Reg.ecx, 0) and
                  aft[2] == push_imm8 and aft[3] == oldlen):
                # mov ecx, reg; push imm8
                meta['len'] = 'push'
                if not jmp:
                    fpoke(fn, next_off+3, newlen)
                    meta['fixed'] = 'yes'
                    return meta
                elif jmp == jmp_near:
                    # TODO: Handle this case
                    meta['fixed'] = 'not implemented'
                    return meta
                else:
                    meta['fixed'] = 'no'
                    return meta
        elif reg == Reg.esi.code and isinstance(func, tuple) and func[0].startswith('rep'):
            # Sample code:
            # ; oldlen = 22
            # ; r = (oldlen+1) % 4 = 3 (3 bytes moved with 1 movsw and 1 movsb)
            # mov ecx, 5 ; 5 = (oldlen + 1) // 4
            # mov esi, strz_Store_Item_in_Hospital_dc4f40
            # lea edi, [dest]
            # repz movsd
            # movsw
            # movsb
            meta['str'] = 'esi'
            r = (oldlen+1) % 4
            dword_count = (oldlen+1)//4
            new_dword_count = (newlen-r)//4 + 1
            mod_1_ecx_0 = join_byte(1, Reg.ecx, 0)
            if match_mov_reg_imm32(pre[-6:-1], Reg.ecx, dword_count):
                # mov ecx, dword_count
                fpoke4(fn, offset-5, new_dword_count)
                meta['len'] = 'ecx*4'
                meta['fixed'] = 'yes'
                return meta
            elif pre[-4] == lea and pre[-3] & 0xf8 == mod_1_ecx_0 and pre[-2] == dword_count:
                # lea ecx, [reg+dword_count]  ; assuming that reg value == 0
                fpoke(fn, offset-2, new_dword_count)
                meta['len'] = 'ecx*4'
                meta['fixed'] = 'yes'
                return meta
            elif newlen > oldlen:
                # ecx modification code was not found. TODO: handle this case properly.
                if jmp:
                    meta['fixed'] = 'no'
                    return meta
                elif aft:
                    for line in disasm(aft, start_address=next_off):
                        if line.mnemonic != 'db':
                            break
                        offset = line.address
                        line_data = line.data
                        if line_data[0] == Prefix.rep:
                            meta['len'] = 'ecx*4'
                            meta['fixed'] = 'no'
                            return meta
                        elif line_data[0] == jmp_near:
                            next_off_2 = line.operands[0].value
                            aft = fpeek(fn, offset, count_after)

                            skip = None
                            if match_mov_reg_imm32(aft[:5], Reg.ecx, dword_count):
                                skip = 5
                            elif aft[0] == lea and aft[1] & 0xf8 == mod_1_ecx_0 and aft[2] == dword_count:
                                skip = 3

                            if skip is not None:
                                meta['len'] = 'ecx*4'
                                retvalue = dict(
                                    src_off=line.address+1,
                                    new_code=bytes((mov_reg_imm | 8 | Reg.ecx.code,)) + to_dword(dword_count),
                                    dest_off=next_off_2 + skip
                                )
                                retvalue.update(meta)
                                return retvalue

                            meta['fixed'] = 'no'
                            return meta
                        elif len(line_data) == 5 and match_mov_reg_imm32(line_data, Reg.ecx, dword_count):
                            fpoke4(fn, line.address + 1, new_dword_count)
                            meta['len'] = 'ecx*4'
                            meta['fixed'] = 'yes'
                            return meta
                        elif line_data[0] == lea and line_data[1] & 0xf8 == mod_1_ecx_0 and line_data[2] == dword_count:
                            fpoke(fn, line.address + 2, new_dword_count)
                            meta['len'] = 'ecx*4'
                            meta['fixed'] = 'yes'
                            return meta
                    return meta
        else:
            meta['str'] = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'][reg]
        return meta
    elif (pre[-1] & 0xFE == mov_acc_mem or (pre[-2] & 0xFE == mov_reg_rm and pre[-1] & 0xC7 == join_byte(0, 0, 5)) or  # mov
          pre[-3] == 0x0F and pre[-2] in {x0f_movups, x0f_movaps} and pre[-1] & 0xC7 == join_byte(0, 0, 5)):  # movups or movaps
        # mov eax, [addr] or mov reg, [addr]
        meta['str'] = 'mov'

        next_off = offset - get_start(pre)
        aft = fpeek(fn, next_off, count_after_for_get_length)
        try:
            x = get_length(aft, oldlen, original_string_address)
        except (ValueError, IndexError) as err:
            meta['fixed'] = 'no'
            meta['get_length_error'] = repr(err)
            return meta

        if 'pokes' in x:
            for off, b in x['pokes'].items():
                fpoke(fn, next_off + off, b)

        if newlen <= oldlen and 'pokes' not in x:
            meta['fixed'] = 'not needed'
            return meta
        else:
            fix = get_fix_for_moves(x, newlen, string_address, meta)

            if fix['fixed'] == 'yes':
                # Make deleted relocs offsets relative to the given offset
                fix['deleted_relocs'] = [next_off + ref - offset for ref in fix['deleted_relocs']]

                if 'new_code' in fix:
                    fix['src_off'] = next_off + 1
                else:
                    # Make new relocations relative to the given offset (only if they not belong to a procedure)
                    fix['added_relocs'] = [next_off + ref - offset for ref in fix['added_relocs']]

                if 'pokes' in fix:
                    fix['pokes'] = {next_off + off: b for off, b in fix['pokes'].items()}

            return fix
    elif pre[-2] == mov_reg_rm and pre[-1] & 0xC0 == 0x80:
        # mov reg8, string[reg]
        meta['func'] = 'strcpy'
        meta['str'] = 'mov byte'
        meta['fixed'] = 'not needed'
        return meta  # No need fixing
    elif pre[-1] == add_acc_imm | 1:
        # add reg, offset string
        meta['func'] = 'array'
        meta['str'] = 'add offset'
        meta['fixed'] = 'not needed'
        return meta
    elif pre[-2] == op_rm_imm | 1 and pre[-1] & 0xF8 == 0xF8:
        # cmp reg, offset string
        meta['str'] = 'cmp reg'
    elif pre[-4] == mov_rm_imm | 1 and pre[-3] == join_byte(1, 0, 4) and pre[-2] == join_byte(0, 4, Reg.esp):
        # mov [esp+N], offset string
        meta['str'] = 'mov var'
        meta['fixed'] = 'not needed'
    meta['prev_bytes'] = ' '.join('%02X' % x for x in pre[-4:])
    return meta


def get_length(s: bytes, oldlen, original_string_address=None, reg_state=None, dest=None):
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

    def is_empty(reg: Reg):
        return reg_state[reg.parent] is None or reg_state[reg.parent] == 0

    deleted_relocs = set()
    added_relocs = set()  # Added relocs offsets are relative to the start of saved_mach
    saved_mach = bytes()
    not_moveable_after = None

    def is_moveable():
        return not_moveable_after is None

    pokes = dict()  # eg. fixes of jumps

    nops = dict()
    length = None
    for line in disasm(s):
        offset = line.address
        assert copied_len <= oldlen
        if copied_len == oldlen:
            length = offset
            break
        if line.mnemonic == 'db':
            raise ValueError('Unknown instruction encountered: ' + hexlify(s[line.address:line.address+8]).decode())
        if line.mnemonic.startswith('mov') and not line.mnemonic.startswith('movs'):
            left_operand, right_operand = line.operands
            if left_operand.type in {'reg gen', 'reg xmm'}:
                # mov reg, [...]
                if (not is_empty(left_operand.reg) and
                        left_operand.reg not in {right_operand.base_reg, right_operand.index_reg}):
                    warn('%s register is already marked as occupied. String address: 0x%x' %
                         (left_operand, original_string_address), stacklevel=2)

                if right_operand.type == 'ref abs':
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
                elif right_operand.type == 'imm' and valid_reference(right_operand.value):
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
            elif left_operand.type in {'ref rel', 'ref abs'}:
                # `mov [reg1+disp], reg2` or `mov [off], reg`
                if right_operand.type in {'reg gen', 'reg xmm'}:
                    if reg_state[right_operand.reg.parent] is None or reg_state[right_operand.reg.parent] < 0:
                        # It can be a part of a copying code of another string. Leave it as is.
                        not_moveable_after = not_moveable_after or offset
                        reg_state[right_operand.reg.parent] = None  # Mark the register as free
                    else:
                        assert left_operand.index_reg is None

                        if reg_state[right_operand.reg.parent] == 0:
                            raise ValueError('Copying of a string to several diferent locations not supported.')

                        if (dest is None or (dest.type == left_operand.type and
                                             dest.base_reg == left_operand.base_reg and
                                             dest.disp > left_operand.disp)):
                            dest = left_operand

                        if left_operand.type == 'ref abs':
                            deleted_relocs.add(offset + line.data.index(to_dword(left_operand.disp)))

                        copied_len += left_operand.data_size or right_operand.data_size

                        if not is_moveable():
                            nops[offset] = len(line.data)

                        reg_state[right_operand.reg.parent] = 0  # Mark the register as freed
                elif is_moveable():
                    if (right_operand.type == 'ref abs' or right_operand.type == 'imm' and
                            valid_reference(right_operand.value)):
                        # TODO: check if this actually a reference. Until then just skip
                        not_moveable_after = not_moveable_after or offset
                        continue
                        # value = right_operand.disp if right_operand.type == 'ref abs' else right_operand.value
                        # local_offset = line.data.rindex(to_dword(value))  # use rindex() to find the second operand
                        # deleted_relocs.add(offset + local_offset)
                        # added_relocs.add(len(saved_mach) + local_offset)

                    if left_operand.type == 'ref abs':
                        value = left_operand.disp
                        local_offset = line.data.index(to_dword(value))
                        deleted_relocs.add(offset + local_offset)
                        added_relocs.add(len(saved_mach) + local_offset)

                    saved_mach += line.data
            else:
                # Segment register etc.
                raise ValueError('Unallowed left operand type: %s, type is %r, instruction is `%s`' %
                                 (left_operand, left_operand.type, str(line)))
        elif line.mnemonic == 'lea':
            left_operand, right_operand = line.operands
            reg_state[left_operand.reg.parent] = -1
            if dest is not None and dest.base_reg == right_operand.base_reg and dest.disp >= right_operand.disp:
                dest = Operand(base_reg=left_operand.reg, disp=0)
            saved_mach += line.data
        elif line.mnemonic.startswith('j'):
            if line.mnemonic.startswith('jmp'):
                not_moveable_after = not_moveable_after or offset

                data_after_jump = s[line.operands[0].value:]
                if not data_after_jump:
                    raise ValueError('Cannot jump: jump destination not included in the passed machinecode.')

                x = get_length(data_after_jump, oldlen - copied_len - 1,
                               original_string_address, reg_state, dest)
                dest = x['dest']
                if 'short' in line.mnemonic:
                    disp = line.data[1] + x['length']
                    pokes = {offset+1: disp}
                else:
                    disp = from_dword(line.data[1:]) + x['length']
                    pokes = {offset+1: to_dword(disp)}
                break
            else:
                raise ValueError('Conditional jump encountered at offset 0x%02x' % line.address)
        else:
            if str(line).startswith('rep'):
                reg_state[Reg.ecx] = None  # Mark ecx as unoccupied
            if line.mnemonic.startswith('movs'):
                reg_state[Reg.esi] = None
                reg_state[Reg.edi] = None
            elif line.mnemonic.startswith('set'):
                # setz, setnz etc.
                reg_state[line.operands[0].reg.parent] = -1
            elif line.mnemonic == 'push':
                if line.operands[0].type == 'reg gen':
                    reg_state[line.operands[0].reg.parent] = None  # Mark the pushed register as unoccupied
                not_moveable_after = not_moveable_after or offset
            elif line.mnemonic == 'pop':
                if line.operands[0].type == 'reg gen':
                    reg_state[line.operands[0].reg.parent] = -1
                not_moveable_after = not_moveable_after or offset
            elif line.mnemonic in {'add', 'sub', 'and', 'xor', 'or'} and line.operands[0].type == 'reg gen':
                if line.operands[0].reg == Reg.esp:
                    not_moveable_after = not_moveable_after or offset
                reg_state[line.operands[0].reg.parent] = -1
            elif line.mnemonic.startswith('call'):
                not_moveable_after = not_moveable_after or offset
            elif line.mnemonic.startswith('ret'):
                break

            if is_moveable():
                if line.operands:
                    abs_refs = [operand for operand in line.operands if operand.type in {'ref abs', 'imm'}]

                    for ref in abs_refs:
                        value = ref.disp if ref.type == 'ref abs' else ref.value

                        if ref.type == 'imm' and not valid_reference(value):
                            continue

                        local_offset = line.data.index(to_dword(value))
                        deleted_relocs.add(offset + local_offset)
                        added_relocs.add(len(saved_mach) + local_offset)

                saved_mach += line.data

    if not length and copied_len == oldlen:
        length = len(s)
    if not is_moveable():
        length = not_moveable_after  # return length of code which can be moved harmlessly
    if length is None:
        raise ValueError('Length of the copying code not recognized.')
    if dest is None:
        raise ValueError('Destination not recognized.')

    result = dict(
        length=length,
        dest=dest,
        deleted_relocs=deleted_relocs,
        saved_mach=saved_mach,
        added_relocs=added_relocs
    )
    if nops:
        result['nops'] = nops
    if pokes:
        result['pokes'] = pokes
    return result


def mach_memcpy(src, dest: Operand, count):
    mach = bytearray()
    mach.append(pushad)  # pushad
    new_references = set()
    assert dest.index_reg is None
    # If the destination address is not in edi yet, put it there
    if dest.base_reg != Reg.edi or dest.disp != 0:
        if dest.disp == 0:
            # mov edi, reg
            mach += bytes((mov_rm_reg | 1, join_byte(3, dest.base_reg, Reg.edi)))
        elif dest.base_reg is None:
            # mov edi, imm32
            mach.append(mov_reg_imm | 8 | Reg.edi.code)  # mov edi, ...
            new_references.add(len(mach))
            mach += to_dword(dest.disp)  # imm32
        else:
            # lea edi, [reg+imm]
            mach += mach_lea(Reg.edi, dest)

    mach.append(mov_reg_imm | 8 | Reg.esi.code)  # mov esi, ...
    new_references.add(len(mach))
    mach += to_dword(src)  # imm32

    mach += bytes((xor_rm_reg | 1, join_byte(3, Reg.ecx, Reg.ecx)))  # xor ecx, ecx
    mach += bytes((mov_reg_imm | Reg.cl.code, (count+3)//4))  # mov cl, (count+3)//4

    mach += bytes((Prefix.rep, movsd))  # rep movsd

    mach.append(popad)  # popad

    return mach, new_references


def add_to_new_section(fn, dest, s, alignment=4, padding_byte=b'\0'):
    aligned = align(len(s), alignment)
    s = pad_tail(s, aligned, padding_byte)
    fpoke(fn, dest, s)
    return dest + aligned
