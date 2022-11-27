from binascii import hexlify
from dataclasses import dataclass, field
from typing import Dict, Mapping, Optional, Set, Union
from warnings import warn

from .binio import from_dword, to_dword
from .disasm import disasm
from .machine_code_assembler import asm
from .machine_code_utils import mach_memcpy
from .metadata_objects import Fix, Metadata
from .opcodes import Reg, RegType, nop, ret_near
from .operand import (
    AbsoluteMemoryReference,
    ImmediateValueOperand,
    MemoryReference,
    RegisterOperand,
    RelativeMemoryReference,
)


@dataclass
class MovesSeriesAnalysisResult:
    dest: MemoryReference
    length: int
    saved_mach: bytes = field(default_factory=bytes)
    added_relocs: Set[int] = field(default_factory=set)
    deleted_relocs: Set[int] = field(default_factory=set)
    nops: Mapping[int, int] = field(default_factory=dict)
    pokes: Mapping[int, Union[int, bytes]] = field(default_factory=dict)


def get_fix_for_moves(get_length_info: MovesSeriesAnalysisResult, newlen, string_address, meta: Metadata) -> Fix:
    added_relocs = get_length_info.added_relocs

    mach = mach_memcpy(string_address, get_length_info.dest, newlen + 1)
    if get_length_info.saved_mach:
        mach = get_length_info.saved_mach + mach  # If there is "lea edi, [dest]", put it before the new code

    added_relocs.update(mach.absolute_references)

    proc = None
    if len(mach) > get_length_info.length:
        # if memcpy code is to long, try to write it into the new section and make call to it
        mach.byte(ret_near)
        proc = mach

        mach = asm().call_near("call_address")
        if len(mach) > get_length_info.length:
            # Too tight here, even for a procedure call
            meta.fixed = "no"
            meta.cause = "to tight to call"
            return Fix(meta=meta)

    mach.duplicate_byte(nop, get_length_info.length - len(mach))

    # Write replacement code
    pokes = {0: mach}

    # Nop-out old instructions
    if get_length_info.nops:
        for off, count in get_length_info.nops.items():
            pokes[off] = asm().duplicate_byte(nop, count).build()

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

    meta.fixed = "yes"
    fix.meta = meta
    return fix


def is_empty(reg_state: Mapping[Reg, int], reg: Reg):
    return reg_state[reg.parent] is None or reg_state[reg.parent] == 0


def analyze_moves_series(
    data: bytes,
    oldlen: int,
    original_string_address: int = None,
    reg_state: dict = None,
    dest: Optional[MemoryReference] = None,
) -> MovesSeriesAnalysisResult:
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

    pokes: Dict[int, Union[int, bytes]] = dict()  # eg. fixes of jumps
    nops = dict()

    length = None
    for line in disasm(data):
        offset = line.address
        assert copied_len <= oldlen

        if copied_len == oldlen:
            length = offset
            break

        if line.mnemonic == "db":
            raise ValueError(
                "Unknown instruction encountered: " + hexlify(data[line.address : line.address + 8]).decode()
            )

        if line.mnemonic.startswith("mov") and not line.mnemonic.startswith("movs"):
            assert line.operands is not None
            left_operand, right_operand = line.operands
            if isinstance(left_operand, RegisterOperand):
                # mov reg, [...]
                # assert isinstance(right_operand, (RelativeMemoryReference))
                if (
                    not is_empty(reg_state, left_operand.reg)
                    and isinstance(right_operand, RelativeMemoryReference)
                    and left_operand.reg not in {right_operand.base_reg, right_operand.index_reg}
                ):
                    warn(
                        f"{left_operand} register is already marked as occupied. "
                        f"String address: 0x{original_string_address:x}",
                        stacklevel=2,
                    )

                if isinstance(right_operand, AbsoluteMemoryReference):
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
                elif isinstance(right_operand, ImmediateValueOperand) and valid_reference(right_operand.value):
                    # This may be a reference to another string
                    not_moveable_after = not_moveable_after or offset
                else:
                    # `mov reg1, [reg2+disp]` or `mov reg, imm`
                    reg_state[left_operand.reg.parent] = -1
                    if is_moveable():
                        if isinstance(right_operand, RelativeMemoryReference) and valid_reference(right_operand.disp):
                            value = right_operand.disp
                            local_offset = line.data.rindex(to_dword(value))
                            deleted_relocs.add(offset + local_offset)
                            added_relocs.add(len(saved_mach) + local_offset)
                        saved_mach += line.data
            elif isinstance(left_operand, MemoryReference):
                # `mov [reg1+disp], reg2` or `mov [off], reg`
                if isinstance(right_operand, RegisterOperand) and right_operand.reg.type in {
                    RegType.general,
                    RegType.xmm,
                }:
                    if reg_state[right_operand.reg.parent] is None or reg_state[right_operand.reg.parent] < 0:
                        # It can be a part of a copying code of another string. Leave it as is.
                        not_moveable_after = not_moveable_after or offset
                        reg_state[right_operand.reg.parent] = None  # Mark the register as free
                    else:
                        assert not (
                            isinstance(left_operand, RelativeMemoryReference) and left_operand.index_reg is not None
                        )

                        if reg_state[right_operand.reg.parent] == 0:
                            raise ValueError("Copying of a string to several different locations not supported.")

                        if dest is None:
                            dest = left_operand
                        elif (
                            isinstance(dest, RelativeMemoryReference)
                            and isinstance(left_operand, RelativeMemoryReference)
                            and dest.base_reg == left_operand.base_reg
                            and dest.disp > left_operand.disp
                        ):
                            dest = left_operand
                        # elif (isinstance(dest, AbsoluteMemoryReference)
                        #       and isinstance(left_operand, AbsoluteMemoryReference)):
                        #     dest = left_operand

                        if isinstance(left_operand, AbsoluteMemoryReference):
                            deleted_relocs.add(offset + line.data.index(to_dword(left_operand.disp)))

                        assert left_operand.data_size is not None or right_operand.data_size is not None
                        if left_operand.data_size:
                            copied_len += left_operand.data_size
                        elif right_operand.data_size:
                            copied_len += right_operand.data_size

                        if not is_moveable():
                            nops[offset] = len(line.data)

                        reg_state[right_operand.reg.parent] = 0  # Mark the register as freed
                elif is_moveable():
                    if isinstance(right_operand, AbsoluteMemoryReference) or (
                        isinstance(right_operand, ImmediateValueOperand) and valid_reference(right_operand.value)
                    ):
                        # TODO: check if this actually a reference. Until then just skip
                        not_moveable_after = not_moveable_after or offset
                        continue
                        # value = right_operand.disp
                        # if isinstance(right_operand, AbsoluteMemoryReference)
                        # else right_operand.value
                        # local_offset = line.data.rindex(to_dword(value))  # use rindex() to find the second operand
                        # deleted_relocs.add(offset + local_offset)
                        # added_relocs.add(len(saved_mach) + local_offset)

                    if isinstance(left_operand, AbsoluteMemoryReference):
                        value = left_operand.disp
                        local_offset = line.data.index(to_dword(value))
                        deleted_relocs.add(offset + local_offset)
                        added_relocs.add(len(saved_mach) + local_offset)

                    saved_mach += line.data
            else:
                # Segment register etc.
                raise ValueError(
                    "Unallowed left operand type: {}, type is {!r}, instruction is `{}`".format(
                        left_operand, type(left_operand), str(line)
                    )
                )
        elif line.mnemonic == "lea":
            assert line.operands is not None
            left_operand, right_operand = line.operands

            # Left operand of lea is always a register
            assert isinstance(left_operand, RegisterOperand)
            assert isinstance(right_operand, RelativeMemoryReference)
            reg_state[left_operand.reg.parent] = -1
            if (
                dest is not None
                and isinstance(dest, RelativeMemoryReference)
                and dest.base_reg == right_operand.base_reg
                and dest.disp == right_operand.disp
            ):
                dest = RelativeMemoryReference(base_reg=left_operand.reg, disp=0)

            saved_mach += line.data
        elif line.mnemonic.startswith("j"):
            if line.mnemonic.startswith("jmp"):
                not_moveable_after = not_moveable_after or offset
                jump_destination = line.operand1
                assert isinstance(jump_destination, ImmediateValueOperand)
                data_after_jump = data[jump_destination.value :]
                if not data_after_jump:
                    raise ValueError("Cannot jump: jump destination not included in the passed machinecode.")

                result = analyze_moves_series(
                    data_after_jump, oldlen - copied_len - 1, original_string_address, reg_state, dest
                )
                dest = result.dest
                if "short" in line.mnemonic:
                    disp = line.data[1] + result.length
                    pokes = {offset + 1: disp}
                else:
                    disp = from_dword(line.data[1:]) + result.length
                    pokes = {offset + 1: to_dword(disp)}
                break
            else:
                raise ValueError("Conditional jump encountered at offset 0x{:02x}".format(line.address))
        else:
            if line.prefix and line.prefix.name.startswith("rep"):
                reg_state[Reg.ecx] = None  # Mark ecx as unoccupied
            if line.mnemonic.startswith("movs"):
                reg_state[Reg.esi] = None
                reg_state[Reg.edi] = None
            elif line.mnemonic.startswith("set"):
                # setz, setnz etc.
                operand = line.operand1
                assert isinstance(operand, RegisterOperand)
                reg_state[operand.reg.parent] = -1
            elif line.mnemonic == "push":
                operand = line.operand1
                if isinstance(operand, RegisterOperand) and operand.reg.type == RegType.general:
                    reg_state[operand.reg.parent] = None  # Mark the pushed register as unoccupied
                not_moveable_after = not_moveable_after or offset
            elif line.mnemonic == "pop":
                operand = line.operand1
                if isinstance(operand, RegisterOperand) and operand.reg.type == RegType.general:
                    reg_state[operand.reg.parent] = -1
                not_moveable_after = not_moveable_after or offset
            elif line.mnemonic in {"add", "sub", "and", "xor", "or"}:
                operand = line.operand1
                if isinstance(operand, RegisterOperand) and operand.reg.type == RegType.general:
                    assert operand.reg is not None
                    if operand.reg == Reg.esp:
                        not_moveable_after = not_moveable_after or offset
                    reg_state[operand.reg.parent] = -1
            elif line.mnemonic.startswith("call"):
                not_moveable_after = not_moveable_after or offset
            elif line.mnemonic.startswith("ret"):
                break

            if is_moveable():
                if line.operands:
                    abs_refs = [
                        operand
                        for operand in line.operands
                        if isinstance(operand, (AbsoluteMemoryReference, ImmediateValueOperand))
                    ]

                    for ref in abs_refs:
                        if isinstance(ref, AbsoluteMemoryReference):
                            value = ref.disp
                        else:
                            value = ref.value

                        if isinstance(ref, ImmediateValueOperand) and not valid_reference(value):
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
        raise ValueError("Length of the copying code not recognized.")
    if dest is None:
        raise ValueError("Destination not recognized.")

    result = MovesSeriesAnalysisResult(
        length=length, dest=dest, deleted_relocs=deleted_relocs, saved_mach=saved_mach, added_relocs=added_relocs
    )

    if nops:
        result.nops = nops

    if pokes:
        result.pokes = pokes

    return result
