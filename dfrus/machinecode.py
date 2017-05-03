from collections import Iterable, Sequence
from .opcodes import *
from .disasm import join_byte, Operand, mach_lea
from .binio import to_dword

'''
# Concept:
new_code = MachineCode(
    (mov_rm_imm | 1), join_byte(1, 0, Reg.esi), 0x14, to_dword(0xf),  # mov dword [esi+14h], 0fh
    call_near, Reference.relative(name='func', size=4),  # call near func
    mov_reg_imm | 8 | Reg.edi, to_dword(0xf),  # mov edi, 0fh
    jmp_near, Reference.relative(name='return_addr', size=4)  # jmp near return_addr
)

# Then:
new_code.origin_address = 0x123456  # Must be set before setting addresses of relative references
new_code.fields['func'] = 0x756733
new_code.fields['return_addr'] = 0x475675
fn.seek(new_code.origin_address)
fn.write(bytes(new_code))
'''


class Reference:
    def __init__(self, name: str, size=4, is_relative: bool=None):
        self.name = name
        self.size = size
        self.is_relative = is_relative
    
    @classmethod
    def relative(cls, name, size=4):
        return cls(name, size, is_relative=True)
    
    @classmethod
    def absolute(cls, name, size=4):
        return cls(name, size, is_relative=False)


class MachineCode:
    def __init__(self, *args, origin_address=0, **kwargs):
        self.origin_address = origin_address
        self._raw_list = list(args)
        self.fields = dict()
        self._labels = dict()
        self._absolute_ref_indexes = []
        i = 0
        for item in args:
            if item is None:
                pass
            elif isinstance(item, int):
                assert 0 <= item < 256
                i += 1
            elif isinstance(item, str):  # label name encountered
                item = item.rstrip(':')
                if item in self._labels:
                    raise ValueError('Duplicate label name: %r' % item)
                self._labels[item] = i
                i += 0  # Labels don't have size
            elif isinstance(item, Iterable):
                if not isinstance(item, Sequence):
                    item = list(item)  # Convert into list to measure item's length
                i += len(item)
            elif isinstance(item, Reference):
                self.fields[item.name] = None
                if not item.is_relative:
                    self._absolute_ref_indexes.append(i)
                i += item.size
        self.code_length = i

        for item, value in kwargs.items():
            if item not in self.fields:
                raise IndexError('Name %r is not used in the code.' % item)
            else:
                self.fields[item] = value

    def __iter__(self):
        for ref_name, value in self.fields.items():
            if ref_name in self._labels:
                self.fields[ref_name] = self._labels[ref_name] + self.origin_address
                value = self.fields[ref_name]
            
            if value is None:
                raise ValueError('A value of the %r field is not set.' % ref_name)
        
        i = 0
        for item in self._raw_list:
            if isinstance(item, int):
                yield item
                i += 1
            elif isinstance(item, str):
                pass  # label name encountered, do nothing
            elif isinstance(item, Iterable):
                j = 0
                for j, b in enumerate(item, 1):
                    yield b
                i += j
            elif isinstance(item, Reference):
                i += item.size
                if item.is_relative:
                    disp = self.fields[item.name] - self.origin_address - i
                    for b in disp.to_bytes(item.size, byteorder='little', signed=True):
                        yield b
                else:
                    for b in self.fields[item.name].to_bytes(item.size, 'little'):
                        yield b

    @property
    def absolute_references(self):
        if self.origin_address is None:
            return iter(self._absolute_ref_indexes)
        else:
            return (self.origin_address + i for i in self._absolute_ref_indexes)

    def __iadd__(self, other):
        if isinstance(other, type(self)):
            self._raw_list.extend(other._raw_list)
            new_labels = dict(other._labels)  # Avoid changing other's labels directly, copy them
            for item in new_labels:
                if item in self._labels:
                    raise ValueError('Duplicate label name: %r' % item)
                new_labels[item] += self.code_length
            self._labels.update(new_labels)

            self.fields.update(dict(other.fields))

            self._absolute_ref_indexes.extend(item + self.code_length for item in other._absolute_ref_indexes)

            self.code_length += other.code_length
        elif isinstance(other, Iterable):
            other = list(other)
            self._raw_list.extend(other)
            self.code_length += len(other)
        else:
            self._raw_list.append(int(other))

    def __add__(self, other):
        internals = list(self._raw_list)
        new_fields = dict(self.fields)

        if isinstance(other, type(self)):
            internals.extend(other._raw_list)
            new_fields.update(other.fields)
        elif isinstance(other, Iterable):
            internals.extend(other)
        else:
            internals.append(int(other))

        return MachineCode(*internals, origin_address=self.origin_address, **new_fields)

    def __radd__(self, other):
        other = list(other) if isinstance(other, Iterable) else [other]
        internals = other + list(self._raw_list)
        return MachineCode(*internals, origin_address=self.origin_address, **self.fields)


MAX_LEN = 0x100


def mach_strlen(code_chunk):
    """
        push ecx
        xor ecx, ecx
    @@:
        cmp byte [eax+ecx], 0  ; assume that eax contains a string address
        jz success
        cmp ecx, 100h
        jg skip
        inc ecx
        jmp @b
    success:
        <code_chunk>
    skip:
        pop ecx
    """
    return MachineCode(
        push_reg | Reg.ecx.code,  # push ecx
        xor_rm_reg | 1, join_byte(3, Reg.ecx, Reg.ecx),  # xor ecx, ecx
        '@@:',
        cmp_rm_imm, join_byte(0, 7, 4), join_byte(0, Reg.ecx, Reg.eax), 0x00,  # cmp byte [eax+ecx], 0
        jcc_short | Cond.z, Reference.relative('success', size=1),  # jz success
        cmp_rm_imm | 1, join_byte(3, 7, Reg.ecx), to_dword(MAX_LEN),  # cmp ecx, MAX_LEN
        jcc_short | Cond.g, Reference.relative('skip', size=1),  # jg skip
        inc_reg | Reg.ecx.code,  # inc ecx
        jmp_short, Reference.relative('@@', size=1),  # jmp @b
        'success:',
        code_chunk,
        'skip:',
        pop_reg | Reg.ecx.code,  # pop ecx
    )


def mach_memcpy(src, dest: Operand, length: int):
    """
    pushad
    <nothing> or <mov edi, dest> or <lea edi, [dest]>
    mov esi, src
    xor ecx, ecx
    mov cl, (length+3)//4
    rep movsd
    popad
    """
    assert dest.index_reg is None
    return MachineCode(
        pushad,
        (
            # If the destination address is not in edi yet, put it there
            None if dest.base_reg == Reg.edi and dest.disp == 0 else
            [mov_rm_reg | 1, join_byte(3, dest.base_reg, Reg.edi)] if dest.disp == 0 else
            mach_lea(Reg.edi, dest)
        ),
        mov_reg_imm | 8 | Reg.esi.code, Reference.absolute('src'),  # mov esi, src
        xor_rm_reg | 1, join_byte(3, Reg.ecx, Reg.ecx),  # xor ecx, ecx
        mov_reg_imm | Reg.cl.code, (length+3)//4,  # mov cl, (length+3)//4
        Prefix.rep, movsd,  # rep movsd
        popad,
        src=src
    )


def test_machinecode():
    """
    # Sample code:
    use32

    func = 222222h
    return_addr = 777777h

    org 123456h

    mov dword [esi+14h], 0fh
    call near func
    mov edi, 0fh
    jmp near return_addr
    """

    code = MachineCode(
        (mov_rm_imm | 1), join_byte(1, 0, Reg.esi), 0x14, to_dword(0xf),  # mov dword [esi+14h], 0fh
        call_near, Reference.relative(name='func', size=4),  # call near func
        mov_reg_imm | 8 | Reg.edi.code, to_dword(0xf),  # mov edi, 0fh
        jmp_near, Reference.relative(name='return_addr', size=4)  # jmp near return_addr
    )

    code.origin_address = 0x123456
    code.fields['func'] = 0x222222
    code.fields['return_addr'] = 0x777777

    assert bytes(code) == bytes(
        int(item, base=16) for item in 'C7 46 14 0F 00 00 00 E8 C0 ED 0F 00 BF 0F 00 00 00 E9 0B 43 65 00'.split()
    )
    
    # Test getting addresses of absolute references
    code = MachineCode(
        bytes(123),
        Reference.absolute(name='b', size=4),
        bytes(12345),
        Reference.absolute(name='a', size=4),
        bytes(10)
    )
    
    code.origin_address = 0
    code.fields['a'] = 0xDEAD
    code.fields['b'] = 0xBEEF
    
    b = bytes(code)
    found_refs = sorted(b.index(to_dword(code.fields[ref_name])) for ref_name in 'ab')
    assert found_refs == list(code.absolute_references)
    
    # Test the new mach_strlen:
    code = mach_strlen(nop)
    sample = '51 31 C9 80 3C 08 00 74 0B 81 F9 00 01 00 00 7F 04 41 EB EF 90 59'
    assert bytes(code) == bytes(int(item, base=16) for item in sample.split())


if __name__ == '__main__':
    test_machinecode()
