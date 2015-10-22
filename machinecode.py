from collections import Sequence

'''
# Concept:
new_code = MachineCode(
    (mov_rm_imm | 1), join_byte(1, 0, Reg.esi), 0x14, to_dword(0xf),  # mov [esi+14h], 0fh
    call_near, Reference.relative(name='func', size=4),  # call near func
    mov_reg_imm | 8 | Reg.edi, to_dword(0xf),  # mov edi, 0fh
    jmp_near, Reference.relative(name='return_addr', size=4)  # jmp near return_addr
)
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


class Label:
    # Not using in MachineCode for now
    def __init__(self, name: str, offset=None):
        self.name = name
        self.offset = offset


class MachineCode:
    def __init__(self, *args, origin_address=None, **kwargs):
        self.origin_address = origin_address
        self._raw_list = args
        self._fields = dict()
        self._absolute_ref_indexes = []
        i = 0
        for item in args:
            if isinstance(item, int):
                i += 1
            elif isinstance(item, Sequence):
                i += len(item)
            elif isinstance(item, Reference):
                self._fields[item.name] = None
                if not item.is_relative:
                    self._absolute_ref_indexes.append(i)
                i += item.size
        
        for item, value in kwargs.items():
            if item not in self._fields:
                raise IndexError('Name %r is not used in the code.' % item)
            else:
                self._fields[item] = value
    
    def __iter__(self):
        if self.origin_address is None:
            raise ValueError('Origin address is not set.')

        for ref_name, value in self._fields.items():
            if value is None:
                raise ValueError('A value of the %r field is not set.' % ref_name)
        
        i = 0
        for item in self._raw_list:
            if isinstance(item, int):
                yield item
                i += 1
            elif isinstance(item, Sequence):
                for b in item:
                    yield b
                i += len(item)
            elif isinstance(item, Reference):
                i += item.size
                if item.is_relative:
                    d = (self._fields[item.name] - self.origin_address - i).to_bytes(item.size, 'little')
                    for b in d:
                        yield b
                else:
                    for b in self._fields[item.name].to_bytes(item.size, 'little'):
                        yield b
    
    def __setitem__(self, key, value):
        if key not in self._fields:
            raise IndexError('Name %r is not used in the code.' % key)
        else:
            self._fields[key] = value
    
    @property
    def absolute_references(self):
        if self.origin_address is None:
            return iter(self._absolute_ref_indexes)
        else:
            return (self.origin_address + i for i in self._absolute_ref_indexes)
    
    def __contains__(self, item):
        return item in self._fields
