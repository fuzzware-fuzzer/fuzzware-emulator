from typing import Tuple, List, Set, Dict, Type
from abc import abstractmethod
from . import POINTER_SIZE

import logging
logger = logging.getLogger("GDMA")

TYPE_NAME_DESCRIPTOR = "descriptor"
TYPE_NAME_POINTER = "pointer"
TYPE_NAME_BUFFER = "buffer"
TYPE_NAME_STATUS = "status"

BUILTIN_TYPES = (
    TYPE_NAME_DESCRIPTOR,
    TYPE_NAME_POINTER,
    TYPE_NAME_BUFFER,
    TYPE_NAME_STATUS,
)

class TypeDescription:
    name: str

    @abstractmethod
    def get_size(self):
        """ Size of the field

        returns size, if constant, else None
        """
        pass

    @abstractmethod
    def parse_config(self, cfg: Dict, typedefs: Dict[str, 'TypeDescription'], peripheral: 'GenericDMA'):
        pass

    def describe(self, printed_typedefs: Set) -> str:
        return self.name

    def __str__(self) -> str:
        return self.describe(set())

    def __repr__(self) -> str:
        return self.__str__()

class PointerType(TypeDescription):
    name: str = TYPE_NAME_POINTER
    referenced_type: TypeDescription
    known_values: Set[int]

    def get_size(self):
        return POINTER_SIZE

    def parse_config(self, cfg: Dict, typedefs: Dict[str, TypeDescription], peripheral: 'GenericDMA'):
        assert "typedef" not in cfg
        self.is_buf_end_ptr = cfg.get("is_buf_end_ptr", False)
        assert type(self.is_buf_end_ptr) == bool
        self.known_values = set(map(lambda v: peripheral.resolve_value(v), cfg.get("known_values", ())))
        assert type(self.known_values) == set
        assert all((type(v) == int for v in self.known_values))
        if "known_sizes" in cfg:
            raise NotImplementedError("Please specify known buffer sizes at the Peripheral level or buffer level.")

        assert "to" in cfg
        referenced = cfg["to"]

        self.referenced_type = reuse_or_create_type(referenced, typedefs, peripheral)
        if self.is_buf_end_ptr:
            assert type(self.referenced_type) == BufferType, f"For pointers with 'is_buf_end_ptr' set, the pointee needs to be of type {TYPE_NAME_BUFFER}."
            assert not self.known_values, "For pointers with 'is_buf_end_ptr' set, 'known_values' cannot be specified"

    def describe(self, printed_typedefs: Set) -> str:
        return f"Pointer -> {self.referenced_type.describe(printed_typedefs)}"

class BufferType(TypeDescription):
    name: str = TYPE_NAME_BUFFER
    known_sizes: dict

    def get_size(self):
        return None

    def parse_config(self, cfg: Dict, typedefs: Dict[str, TypeDescription], peripheral: 'GenericDMA'):
        assert "typedef" not in cfg
        self.known_sizes = peripheral.parse_known_buf_sizes(cfg.get("known_sizes", {}))
        assert type(self.known_sizes) == dict

class DescriptorType(TypeDescription):
    name: str = TYPE_NAME_DESCRIPTOR
    fields: Dict[int, TypeDescription] # Entries of offset -> type

    def __init__(self):
        self.fields = {}

    def get_size(self):
        return None
        # TODO: How to get the size if the type has not finished parsing?
        #if not self.fields:
        #    return 0
        #last_offset, last_type = self.fields[-1]
        #last_size = last_type.get_size()
        #if last_size is None:
        #    return None
        #else:
        #    return last_offset + last_size

    def parse_config(self, cfg: Dict, typedefs: Dict[str, TypeDescription], peripheral: 'GenericDMA'):
        # First take note of any typedef
        typedef_name = cfg.get("typedef", "")
        assert type(typedef_name) == str
        if typedef_name:
            assert typedef_name not in typedefs, f"Type '{typedef_name}' redefined"
            assert typedef_name not in BUILTIN_TYPES, "Cannot use builtin type names for typedefs"
            typedefs[typedef_name] = self
        self.name = typedef_name or TYPE_NAME_DESCRIPTOR

        field_cfgs: List[Dict] = cfg.get("fields", [])
        assert type(field_cfgs) == list

        curr_offset = 0
        for field in field_cfgs:
            offset = field.get("offset", curr_offset)
            # Ensure that the offset is either implied
            assert offset is not None
            assert offset not in self.fields

            self.fields[offset] = field = reuse_or_create_type(field, typedefs, peripheral)

            # Ensure that we do not contain ourselves as a field
            if self.name != TYPE_NAME_DESCRIPTOR:
                assert self.name != field.name
                # TODO: Check for recursive circular references

            # Update (implied) offset
            field_size = field.get_size()
            if field_size is None:
                curr_offset = None
            else:
                curr_offset = offset + field_size

    def describe(self, printed_typedefs: Set) -> str:
        if self.name != TYPE_NAME_DESCRIPTOR:
            # Custom type
            if self.name in printed_typedefs:
                # For custom types, just print the name to avoid cylic reference issues
                return self.name
            else:
                printed_typedefs.add(self.name)

        res = f"{self.name} [\n"
        for offset, field in self.fields.items():
            res += f"{offset:#x}: {field.describe(printed_typedefs)}\n"
        res += "]"

        return res

class StatusType(TypeDescription):
    name: str = TYPE_NAME_STATUS

    size: int = None
    mask: int = None

    def parse_config(self, cfg: Dict, typedefs: Dict[str, TypeDescription], peripheral: 'GenericDMA'):
        assert "typedef" not in cfg

        self.size = cfg.get("size", 4)
        assert type(self.size) == int, f"Status size is an integer, got: {type(self.size)}"
        assert 1 <= self.size <= 4, "Status size is byte-oriented and up to 32 bits"
        self.mask = cfg.get("mask", 2**(self.size * 8) - 1)
        assert type(self.mask) == int
        assert self.mask != 0
        assert 1 <= self.mask < 2 ** 32

    def describe(self, printed_typedefs: Set) -> str:
        return f"Status (size: {self.size:d}, mask: {self.mask:#08x})"

CLASSES_BY_NAME: Dict[str, TypeDescription] = {
    TYPE_NAME_POINTER: PointerType,
    TYPE_NAME_BUFFER: BufferType,
    TYPE_NAME_DESCRIPTOR: DescriptorType,
    TYPE_NAME_STATUS: StatusType
}
def reuse_or_create_type(cfg: Dict, typedefs: Dict[str, TypeDescription], peripheral: 'GenericDMA') -> TypeDescription:
    logger.info(f"[reuse_or_create_type] Parsing {cfg}\nCurrent typedefs: {typedefs}")
    type_name = cfg.get("type", TYPE_NAME_DESCRIPTOR)

    if type_name in typedefs:
        # Existing type, just assign that one and don't parse its config again
        descr = typedefs[type_name]
    else:
        # Primitive type, create object and make it parse the config
        descr: TypeDescription = CLASSES_BY_NAME[type_name]()
        descr.parse_config(cfg, typedefs, peripheral)

    return descr
