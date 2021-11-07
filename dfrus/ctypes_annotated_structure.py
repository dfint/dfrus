from ctypes import Structure


class AnnotatedStructureMetaclass(type(Structure)):
    def __new__(mcs, name, bases, namespace, **kwargs):
        annotations = namespace.get("__annotations__")
        if annotations:
            namespace["_fields_"] = [(name, declared_type) for name, declared_type in annotations.items()]
        return super().__new__(mcs, name, bases, namespace, **kwargs)


class AnnotatedStructure(Structure, metaclass=AnnotatedStructureMetaclass):
    """
    A wrapper for Structure from ctypes which automatically adds _fields_
    and fills it according to type annotations from the class
    """
