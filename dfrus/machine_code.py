from typing import Iterable, Sequence

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
    def __init__(self, name: str, size=4, is_relative: bool = None):
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
