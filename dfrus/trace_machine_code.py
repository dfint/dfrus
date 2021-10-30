from contextlib import suppress
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, Union, BinaryIO, Callable

from .binio import read_bytes
from .disasm import disasm, DisasmLine

count_after = 0x100


class Trace(Enum):
    not_follow = auto()
    follow = auto()
    stop = auto()
    forward_only = auto()


@dataclass(frozen=True)
class TraceConfig:
    trace_jmp: Trace
    trace_jcc: Trace
    trace_call: Trace


def trace_code(fn: BinaryIO,
               offset: int,
               stop_cond: Callable[[DisasmLine], bool],
               trace_config: Optional[TraceConfig] = None) -> Optional[DisasmLine]:

    if trace_config is None:
        trace_config = TraceConfig(trace_jmp=Trace.follow,
                                   trace_jcc=Trace.forward_only,
                                   trace_call=Trace.stop)

    s = read_bytes(fn, offset, count_after)
    with suppress(IndexError):
        for line in disasm(s, offset):
            # print('%-8x\t%-16s\t%s' % (line.address, ' '.join('%02x' % x for x in line.data), line))
            if line.mnemonic == 'db':
                return None
            elif stop_cond(line):  # Stop when the stop_cond returns True
                return line
            elif line.mnemonic.startswith('jmp'):
                assert line.operands is not None
                if trace_config.trace_jmp is Trace.not_follow:
                    pass
                elif trace_config.trace_jmp is Trace.follow:
                    return trace_code(fn, int(line.operands[0]), stop_cond, trace_config)
                elif trace_config.trace_jmp is Trace.stop:
                    return line
                elif trace_config.trace_jmp is Trace.forward_only:
                    if int(line.operands[0]) > line.address:
                        return trace_code(fn, int(line.operands[0]), stop_cond, trace_config)
            elif line.mnemonic.startswith('j'):
                assert line.operands is not None
                if trace_config.trace_jcc is Trace.not_follow:
                    pass
                elif trace_config.trace_jcc is Trace.follow:
                    return trace_code(fn, int(line.operands[0]), stop_cond, trace_config)
                elif trace_config.trace_jcc is Trace.stop:
                    return line
                elif trace_config.trace_jcc is Trace.forward_only:
                    if int(line.operands[0]) > line.address:
                        return trace_code(fn, int(line.operands[0]), stop_cond, trace_config)
            elif line.mnemonic.startswith('call'):
                assert line.operands is not None
                if trace_config.trace_call is Trace.not_follow:
                    pass
                elif trace_config.trace_call is Trace.follow:
                    returned = trace_code(fn, int(line.operands[0]), stop_cond, trace_config)
                    if returned is None or not returned.mnemonic.startswith('ret'):
                        return returned
                elif trace_config.trace_call is Trace.stop:
                    return line
                elif trace_config.trace_call is Trace.forward_only:
                    if int(line.operands[0]) > line.address:
                        return trace_code(fn, int(line.operands[0]), stop_cond, trace_config)
            elif line.mnemonic.startswith('ret'):
                return line

    return None


@dataclass(frozen=True)
class FunctionInformation:
    info: str
    address: Optional[int] = None
    operand: Optional[Union[int, str]] = None


def which_func(fn, offset, stop_cond=lambda _: False) -> FunctionInformation:
    disasm_line = trace_code(fn, offset, stop_cond=lambda current_line:
                             str(current_line).startswith('rep') or stop_cond(current_line))

    if disasm_line is None:
        return FunctionInformation('not reached')
    elif str(disasm_line).startswith('rep'):
        return FunctionInformation(str(disasm_line))
    elif disasm_line.mnemonic.startswith('call'):
        assert disasm_line.operands is not None and len(disasm_line.operands) == 1
        try:
            return FunctionInformation(disasm_line.mnemonic,
                                       disasm_line.address,
                                       int(disasm_line.operands[0]))
        except ValueError:
            return FunctionInformation(disasm_line.mnemonic + ' indirect',
                                       disasm_line.address,
                                       str(disasm_line.operands[0]))
    else:
        return FunctionInformation('not reached')
