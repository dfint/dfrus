from ctypes import Structure


class AnnotatedStructure(Structure):
    """
    A wrapper for Structure from ctypes which automatically adds _fields_
    and fills it according to type annotations from the class
    """
    def __new__(cls, *args, **kwargs):
        if not hasattr(cls, "_fields_"):
            cls._fields_ = [(name, declared_type) for name, declared_type in cls.__annotations__.items()]
        future_class = super(Structure, cls).__new__(cls, *args, **kwargs)
        return future_class
