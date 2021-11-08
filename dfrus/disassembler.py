from typing import Union, Optional, Tuple, Callable, Iterator

from dataclasses import dataclass

from .abstract_executor import Executor, NoSuitableCommandException, Command
from .disasm import DisasmLine, seg_prefixes
from .opcodes import *
from .operand import Operand, ImmediateValueOperand


@dataclass
class DisassemblerCommandContext:
    prefix_bytes: Union[bytes, memoryview]
    data: Union[bytes, memoryview]
    address: int
    size_prefix: bool = False
    seg_prefix: Optional[Prefix] = None
    rep_prefix: Optional[Prefix] = None


@dataclass
class DisasmCommandResult:
    size: int
    mnemonic: str
    operands: Optional[Tuple[Operand, ...]] = None


class IllegalCode(Exception):
    pass


class Disassembler(Executor[DisassemblerCommandContext, DisasmCommandResult]):
    def __init__(self):
        super().__init__()
        self._default_command: Optional[Callable[[DisassemblerCommandContext], DisasmCommandResult]] = None

    def disassemble(self, data: bytes, start_address: int = 0) -> Iterator[DisasmLine]:
        data = memoryview(data)
        i = 0
        while True:
            prefix_start = i
            size_prefix = False
            seg_prefix = None
            rep_prefix = None
            if data[i] in seg_prefixes:
                seg_prefix = seg_prefixes[Prefix(data[i])]
                i += 1

            if data[i] == Prefix.operand_size:
                size_prefix = True
                i += 1

            if data[i] in {Prefix.rep.value, Prefix.repne.value, Prefix.lock.value}:
                rep_prefix = Prefix(data[i])
                i += 1

            context = DisassemblerCommandContext(data[prefix_start:i], data[i:], start_address + i,
                                                 size_prefix, seg_prefix, rep_prefix)
            try:
                result = self.execute(context)
            except (NoSuitableCommandException, IllegalCode):
                if self._default_command:
                    result = self._default_command(context)
                else:
                    raise

            yield DisasmLine(
                prefix=rep_prefix,
                address=start_address+prefix_start,
                data=bytes(data[prefix_start:i+result.size]),
                mnemonic=result.mnemonic,
                operands=result.operands
            )
            i += result.size

    def default(self, function: Callable[[DisassemblerCommandContext], DisasmLine]):
        self._default_command = function
        return function


disassembler = Disassembler()


@disassembler.default
def bytes_line(context: DisassemblerCommandContext):
    return DisasmCommandResult(
        size=len(context.prefix_bytes) + 1,
        mnemonic="db",
        operands=tuple(map(ImmediateValueOperand, bytes(context.prefix_bytes) + bytes(context.data[:1])))
    )


@disassembler.command
class OneByteNoOperands(Command[DisassemblerCommandContext, DisasmCommandResult]):
    opcode_to_mnemonic = {
        nop: "nop", ret_near: "retn",
        pushfd: "pushfd", pushad: "pushad",
        popfd: "popfd", popad: "popad",
        leave: "leave", int3: "int3",
        cdq: "cdq", movsb: "movsb", movsd: "movsd",
    }

    def is_applicable(self, context: DisassemblerCommandContext) -> bool:
        return context.data[0] in OneByteNoOperands.opcode_to_mnemonic

    def apply(self, context: DisassemblerCommandContext) -> DisasmCommandResult:
        mnemonic = OneByteNoOperands.opcode_to_mnemonic[context.data[0]]
        if context.prefix_bytes:  # Are there any prefixes?
            if context.size_prefix and context.data[0] == movsd:
                mnemonic = 'movsw'
            elif context.rep_prefix is None:  # Prefixes other then rep* are not allowed
                raise IllegalCode

        return DisasmCommandResult(size=1, mnemonic=mnemonic)
