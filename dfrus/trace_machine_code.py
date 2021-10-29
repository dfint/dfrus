from contextlib import suppress
from typing import Tuple, Any

from dfrus.binio import read_bytes
from dfrus.disasm import disasm

count_after = 0x100


class Trace:
    not_follow = 0
    follow = 1
    stop = 2
    forward_only = 3


def trace_code(fn, offset, stop_cond, trace_jmp=Trace.follow, trace_jcc=Trace.forward_only, trace_call=Trace.stop):
    s = read_bytes(fn, offset, count_after)
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


def which_func(fn, offset, stop_cond=lambda _: False) -> Tuple[Any, ...]:
    def default_stop_condition(cur_line):
        return str(cur_line).startswith('rep') or stop_cond(cur_line)

    disasm_line = trace_code(fn, offset, stop_cond=default_stop_condition)
    result: Tuple[Any, ...]
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
