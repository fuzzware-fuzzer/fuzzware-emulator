from dataclasses import dataclass

BUF_SIZE_GROW_INDEFINITELY = 0
BUF_SIZE_GROW_DISABLE = None

@dataclass
class SizeRange:
    # By default, start small and grow indefinitely
    minsize: int = 1
    maxsize: int = BUF_SIZE_GROW_INDEFINITELY

    def __str__(self):
        return f"SizeRange(min: {self.minsize:#x}, max: {self.maxsize:#x})"

    def __repr__(self):
        return self.__str__()

    def __eq__(self, other: "SizeRange") -> bool:
        return self.minsize == other.minsize and self.maxsize == other.maxsize

def resolve_max_size(max_size, min_size) -> int:
    if max_size is BUF_SIZE_GROW_DISABLE:
        max_size = min_size
    elif max_size == BUF_SIZE_GROW_INDEFINITELY:
        max_size = 0xffffffff

    return max_size