from . import POINTER_SIZE
from abc import abstractmethod
from copy import deepcopy
from .overlay import DMAOverlay
from .descriptor_type import TypeDescription, TYPE_NAME_BUFFER, TYPE_NAME_POINTER, TYPE_NAME_STATUS, PointerType, BufferType, StatusType, DescriptorType


from typing import TYPE_CHECKING, Any, Callable, Dict, Set, Tuple
if TYPE_CHECKING:
    from ..generic_dma import GenericDMAC
from .sizerange import SizeRange

INVALID_LOCATION_NULL = 0
INVALID_LOCATIONS = (INVALID_LOCATION_NULL, )

import logging
logger = logging.getLogger("GDMA")

class DescriptorField:
    # Stable after initialization
    type: TypeDescription
    parent: "DescriptorField"

    # Requires snapshotting
    current_location: int | None

    # Snapshots
    _snapshot_taken: bool
    _saved_location: int

    def __init__(self, descr_type: TypeDescription, parent: "DescriptorField"):
        self.current_location = None
        self.type = descr_type
        self.parent = parent
        self._snapshot_taken = False
        self._saved_location = None

    @abstractmethod
    def _on_relocate(self, addr):
        pass

    @abstractmethod
    def _deactivate(self):
        """Handle being deactivated
        """
        pass

    @property
    def parent_locations(self) -> list[int]:
        """Get the locations of all parent fields"""
        parent_locations = []
        field = self
        while field:
            parent_locations.append(field.current_location)
            field = field.parent
        return parent_locations

    def set_location(self, addr: int | None):
        """ Set the location of the field.

        If addr is none, deactivate
        """
        logger.info(f"Relocating {self} to addr: {hex(addr) if addr is not None else 'inactive'}")
        if addr == self.current_location:
            logger.info("Same location, nothing to do")
            # We did not move, nothing to do
            return
        # Something changed

        self.current_location = addr

        if addr is None:
            logger.info("No address, deactivating")
            # We are getting removed / invalidated
            self._deactivate()
        else:
            logger.info("New address, relocating")
            # We are getting moved to somewhere different
            self._on_relocate(addr)

    def take_snapshot(self):
        # TODO: handle pointer rings / infinite loops?
        assert not self._snapshot_taken, "Descriptor field snapshot already taken"

        self._snapshot_taken = True
        self._saved_location = self.current_location

    def restore_snapshot(self):
        # We initialize saved location to 'inactive', so always reset
        self.current_location = self._saved_location
        # TODO: handle pointer rings / infinite loops?
        if self._snapshot_taken:
            # TODO: More snapshot restore logic?
            pass
        else:
            # TODO: we have not existed upon snapshot creation
            pass

class Pointer(DescriptorField):
    """ Class representing a pointer to another descriptor field.

    We handle the pointer by registering a memory write hook.

    We have multiple move operations here:
    1. The pointer field itself is moved (because the encapsulating struct moves)
        - Change the listened-to pointer location
        - Notify the pointee, if one exists
    2. The pointer value changes
        - Notify the pointee, if one exists
    """
    # Type re-hints
    type: PointerType

    # State that is static after initialization
    update_listener_hook_func: Callable[[int, int, int, Any], None]
    peripheral: 'GenericDMAC'

    # State with custom snapshotting logic
    to: DescriptorField

    # State requiring snapshotting
    update_listener_hook_id: None | Any

    def __init__(self, descr_type: PointerType, parent: DescriptorField, peripheral: 'GenericDMAC'):
        assert descr_type.name == TYPE_NAME_POINTER
        super().__init__(descr_type, parent)

        self.peripheral = peripheral
        self.update_listener_hook_id = None
        self.to = None

        def on_write(address, size, value, user_data):
            self.on_write(address, size, value, user_data)
        self.update_listener_hook_func = on_write

    def _change_listener_hook(self, addr: None | int):
        logger.debug(f"{self} Changing listener hook to: {hex(addr) if addr is not None else 'inactive'}")
        if addr is None:
            # We are supposed to be removed
            if self.update_listener_hook_id is not None:
                self.peripheral.emu.rem_write_hook(self.update_listener_hook_id)
                self.update_listener_hook_id = None
        else:
            # We are moved to a valid location
            if self.update_listener_hook_id is None:
                # New hook
                self.update_listener_hook_id = self.peripheral.emu.add_write_hook(addr, addr + POINTER_SIZE - 1, self.update_listener_hook_func)
            else:
                # Update hook
                self.peripheral.emu.move_mem_hook(self.update_listener_hook_id, addr, addr + POINTER_SIZE - 1)

    def _deactivate(self):
        """ As a pointer, when deactivated, also deactivate the pointee"""
        super()._deactivate()

        self._change_listener_hook(None)
        if self.to:
            self.to.set_location(None)

    def _resolve_pointee_location(self, raw_addr: int | None) -> int | None:
        if raw_addr is None:
            logger.debug(f"[POINTER] location validation: invalid as address is None")
            return None

        # Handle normalization of buffer end pointers
        if not self.type.is_buf_end_ptr:
            addr = raw_addr
        else:
            addr = None
            assert type(self.type.referenced_type) == BufferType
            known_sizes = self.type.referenced_type.known_sizes
            if not known_sizes:
                known_sizes = self.peripheral._known_sizes

            for known_addr, known_size in known_sizes.items():
                if known_addr <= raw_addr <= known_addr + known_size.minsize:
                    addr = known_addr
                    logger.debug(f"[POINTER] location validation: found valid rande for buffer end pointer. Mapping {raw_addr:#x} -> {addr:#x}")
                    break
            if addr is None:
                logger.debug(f"[POINTER] location validation: unknown buffer end pointer")
                return None

        if self.type.known_values:
            logger.debug(f"[POINTER] location validation: looking up address in known values")
            if addr not in self.type.known_values:
                return None
        else:
            if addr in INVALID_LOCATIONS:
                logger.debug(f"[POINTER] location {addr:#x} validation: invalid as address in invalid locations (is NULL)")
                return None
            elif self.peripheral.emu.is_in_mmio_range(addr):
                logger.debug(f"[POINTER] location {addr:#x} validation: invalid as in MMIO range")
                return None
            elif not self.peripheral.emu.is_in_rw_ram_range(addr):
                logger.debug(f"[POINTER] location {addr:#x} validation: invalid as not in read/write RAM range")
                return None

        return addr

    def _relocate_pointee(self, new_addr_raw: int | None):
        new_addr = self._resolve_pointee_location(new_addr_raw)
        logger.debug(f"[{self}] relocating pointee to {hex(new_addr) if new_addr is not None else 'inactive'} (orig: {hex(new_addr) if new_addr is not None else new_addr})")

        if new_addr in self.parent_locations:
            logger.debug(f"[POINTER] pointee address already covered by parent field, ignoring")
            return

        if new_addr is not None and not self.to:
            # Valid target, create if necessary and set location
            logger.debug(f"[POINTER] Instantiating pointee with type: {self.type.referenced_type}")
            self.to = instantiate_from_type(self.type.referenced_type, self, self.peripheral)

        if self.to:
            self.to.set_location(new_addr)

    def _on_relocate(self, addr: int):
        assert addr is not None, "Relocation should not be called with None value"
        logger.debug(f"{self} on_relocate to {addr:#x}")

        # Move the listener to the target location
        self._change_listener_hook(addr)

        # Also move the pointee
        pointee_addr = self.peripheral.emu.read_memory(addr, POINTER_SIZE)
        if pointee_addr is None:
            logger.warning(f"Could not read pointer from {addr:#x}, deactivating pointee")
        else:
            logger.debug(f"Read pointer value from loc [{addr:#x}] == {pointee_addr:#x}")
        self._relocate_pointee(pointee_addr)

    def on_write(self, address, size, value, user_data=None):
        assert user_data is None

        # TODO: for byte-writes we can read the full value (on full pointer write, so to end of pointer field?)
        if address != self.current_location:
            logger.warning(f"{self} Got write to Pointer field other than own location (write address {address:#x}), ignoring")
            return
        if size != POINTER_SIZE:
            logger.warning(f"Got unaligned write to Pointer field (size: {size}), ignoring")
            return
        self._relocate_pointee(value)

    def take_snapshot(self):
        super().take_snapshot()
        if self.to:
            self.to.take_snapshot()

    def restore_snapshot(self):
        super().restore_snapshot()

        if self._snapshot_taken:
            # We existed before the snapshot
            self._change_listener_hook(self._saved_location)
        else:
            self._change_listener_hook(None)

        # We need to indicate to the pointee to restore the snapshot
        # in all cases. If it was not present before, it will deactivate.
        if self.to is not None:
            self.to.restore_snapshot()

    def __del__(self):
        if self.update_listener_hook_id is not None:
            self.peripheral.emu.rem_write_hook(self.update_listener_hook_id)
            self.update_listener_hook_id = None

    def __str__(self):
        if self.current_location is not None:
            return f"{self.type} &{self.current_location:#x}"
        else:
            return f"{self.type} (inactive)"

    def __repr__(self):
        return self.__str__()

class Buffer(DescriptorField):
    # State that is static after initialization
    peripheral: 'GenericDMAC'

    # Self-snapshotting members
    mem_overlay: DMAOverlay # The fuzzer-controlled memory buffer

    # Re-definition for type hint
    type: BufferType

    def __init__(self, descr_type: BufferType, parent: DescriptorField, peripheral: 'GenericDMAC'):
        assert descr_type.name == TYPE_NAME_BUFFER
        super().__init__(descr_type, parent)

        self.peripheral = peripheral

        access_timeout = self.peripheral._buf_access_timeout_ticks
        access_context_regs = self.peripheral._access_context_regs
        num_allowed_reaccesses = self.peripheral._num_buf_reaccesses_until_refresh

        self.mem_overlay = DMAOverlay(peripheral, None, 0, None, access_timeout=access_timeout, access_context_regs=access_context_regs, num_allowed_reaccesses=num_allowed_reaccesses)

    def _deactivate(self):
        super()._deactivate()

        self.mem_overlay.deactivate()

    def known_sizes(self):
        res = self.type.known_sizes
        if not res:
            res = self.peripheral._known_sizes
        return res

    def _on_relocate(self, addr):
        # TODO: replace SizeRange with simple tuple?
        # TODO: For buffer end pointers, handle potentially smaller size due to pointing
        #       to the middle of a buffer (see _resolve_pointee_location)
        size_range = self.known_sizes().get(addr, SizeRange())

        if addr is not None:
            logger.debug(f"{self} relocating to {addr:#x}, got size: {size_range}")
        self.current_location = addr
        self.mem_overlay.set_location(addr, size_range.minsize, size_range.maxsize)

    def take_snapshot(self):
        super().take_snapshot()
        self.mem_overlay.take_snapshot()

    def restore_snapshot(self):
        super().restore_snapshot()
        self.mem_overlay.restore_snapshot()

    def __str__(self):
        if self.current_location is not None:
            return f"{self.type} at {self.current_location:#x} representing {self.mem_overlay}"
        else:
            return f"{self.type} (inactive)"

    def __repr__(self):
        return self.__str__()

class Status(DescriptorField):
    # State that is static after initialization
    peripheral: 'GenericDMAC'
    type: StatusType

    # State to be snapshot
    access_count_per_context: Dict[Tuple[int], int] # (<reg_val>): access_count

    # Self-snapshotting members
    mem_overlay: DMAOverlay # The fuzzer-controlled memory buffer

    read_hook_id: None = None
    read_hook_func: Callable[[int, int, Any], None] = None

    # Snapshot variables
    _saved_access_count_per_context: Dict[Tuple[int], int]

    @property
    def access_context_regs(self):
        return self.peripheral._status_access_context_regs

    @property
    def num_accesses_before_refresh(self):
        return self.peripheral._num_status_reaccesses_until_refresh

    def __init__(self, descr_type: StatusType, parent: DescriptorField, peripheral: 'GenericDMAC'):
        assert descr_type.name == TYPE_NAME_STATUS
        super().__init__(descr_type, parent)

        self.peripheral = peripheral
        self.access_count_per_context = {}
        self._saved_access_count_per_context = {}

        self.read_hook_id = None
        self.to = None

        def on_read(address, size, user_data):
            self.on_read(address, size, user_data)
        self.read_hook_func = on_read

    def _change_listener_hook(self, addr: None | int):
        logger.debug(f"{self} Changing listener hook to: {hex(addr) if addr is not None else 'inactive'}")
        if addr is None:
            # We are supposed to be removed
            if self.read_hook_id is not None:
                self.peripheral.emu.rem_read_hook(self.read_hook_id)
                self.read_hook_id = None
        else:
            # We are moved to a valid location
            if self.read_hook_id is None:
                # New hook
                self.read_hook_id = self.peripheral.emu.add_read_hook(addr, addr + self.type.size - 1, self.read_hook_func)
            else:
                # Update hook
                self.peripheral.emu.move_mem_hook(self.read_hook_id, addr, addr + self.type.size - 1)

    def _deactivate(self):
        """ As a status field, when deactivated, remove the listener hook"""
        super()._deactivate()

        self._change_listener_hook(None)

    def _on_relocate(self, addr: int):
        assert addr is not None, "Relocation should not be called with None value"
        logger.debug(f"{self} on_relocate to {addr:#x}")

        # Move the listener to the target location
        self._change_listener_hook(addr)

    def on_read(self, address, size, user_data=None):
        assert user_data is None

        # First, figure out whether we need to do a write based on access context
        access_context = tuple(self.peripheral.emu.read_register(reg) for reg in self.access_context_regs)

        if access_context in self.access_count_per_context:
            self.access_count_per_context[access_context] += 1
            access_count = self.access_count_per_context[access_context]
            if access_count <= self.num_accesses_before_refresh:
                logger.debug(f"{self} Got reaccess #{access_count}, no need to refresh value")
                return
            else:
                # If we have too high of an access count, we need to refresh
                logger.debug(f"{self} Got too high reaccess #{access_count}, need to refresh value")
                # We need to clear access counts here
                self.access_count_per_context.clear()
                self.access_count_per_context[access_context] = 0
        elif self.access_count_per_context:
            logger.debug(f"{self} Got new read from access context: {self.access_context_regs} -> {access_context}")
            self.access_count_per_context[access_context] = 0
            return
        else:
            logger.debug(f"{self} Got very first read ({self.access_context_regs} -> {access_context}), need to refresh")
            self.access_count_per_context[access_context] = 0

        # TODO: reaccess check based on registers, num_reaccesses, ... (as in buffer overlay)
        read_align_shift = (self.current_location - address) * 8

        status_field_size = self.type.size
        if not self.peripheral.comm.has_bytes(status_field_size):
            self.peripheral.emu.stop()
            return
        fuzzer_val = self.peripheral.comm.get_bytes(status_field_size)

        fuzzer_val = int.from_bytes(fuzzer_val, byteorder='little')
        # shift by the misalignment of the read and mask
        fuzzer_val   = fuzzer_val     << read_align_shift
        shifted_mask = self.type.mask << read_align_shift
        fuzzer_val  &= shifted_mask

        cur_val = int.from_bytes(self.peripheral.emu.read_bytes(address, size), byteorder='little')

        # Mask out fuzzer-controlled bits from current value and apply fuzzer-supplied ones
        mod_val: int = cur_val & ~shifted_mask
        mod_val     |= fuzzer_val

        if logger.level >= logging.DEBUG:
            pc = self.peripheral.emu.read_register("pc")
            logger.debug(f"{self} [{pc:#x}] modifying status value. Original: {cur_val:#010x}, fuzzer value: {fuzzer_val:#010x}, new value: {mod_val:#010x}, shift: {read_align_shift:d}")
        self.peripheral.emu.write_bytes(address, mod_val.to_bytes(size, byteorder='little'))

    def take_snapshot(self):
        super().take_snapshot()

        self._saved_access_count_per_context = deepcopy(self.access_count_per_context)

    def restore_snapshot(self):
        super().restore_snapshot()

        if self._snapshot_taken:
            # We existed before the snapshot
            self.access_count_per_context = deepcopy(self._saved_access_count_per_context)
            self._change_listener_hook(self._saved_location)
        else:
            self.access_count_per_context.clear()
            self._change_listener_hook(None)

    def __del__(self):
        if self.read_hook_id is not None:
            self.peripheral.emu.rem_read_hook(self.read_hook_id)
            self.read_hook_id = None

    def __str__(self):
        if self.current_location is not None:
            return f"{self.type} at {self.current_location:#x}"
        else:
            return f"{self.type} (inactive)"

    def __repr__(self):
        return self.__str__()


class Descriptor(DescriptorField):
    # type re-hints
    type: DescriptorType

    # State that is static after initialization
    peripheral: 'GenericDMAC'

    # Self-snapshotting members
    fields: Dict[int, DescriptorField] # offset -> Field

    def __init__(self, descr_type: DescriptorType, parent: DescriptorField, peripheral: 'GenericDMAC'):
        super().__init__(descr_type, parent)
        self.peripheral = peripheral
        self.fields = {}

    def _on_relocate(self, addr):
        if addr is not None:
            logger.debug(f"{self} on_relocate to {addr:#x}")

        for offset, field_type in self.type.fields.items():
            # Instantiate fields lazily
            if offset not in self.fields:
                self.fields[offset] = instantiate_from_type(field_type, self, self.peripheral)
                logger.debug(f"Instantiated field {offset:#x}: {self.fields[offset]}")
            field = self.fields[offset]
            field.set_location(addr + offset)

    def _deactivate(self):
        super()._deactivate()

        for field in self.fields.values():
            field.set_location(None)

    def take_snapshot(self):
        logger.debug(f"{self} taking snapshot...")
        super().take_snapshot()

        for field in self.fields.values():
            field.take_snapshot()

    def restore_snapshot(self):
        logger.debug(f"{self} restoring snapshot...")
        super().restore_snapshot()

        for field in self.fields.values():
            field.restore_snapshot()

    def __str__(self):
        if self.current_location is not None:
            res = f"{self.type} at {self.current_location:#x} with fields:"
            for offset, field in self.fields.items():
                res += f"\n{offset:#x}. {field}"
            return res
        else:
            return f"{self.type} (inactive)"

def instantiate_from_type(descr_type: DescriptorType | PointerType | BufferType | StatusType, parent: DescriptorField, peripheral: 'GenericDMAC' = None) -> Buffer | Pointer :
    t = type(descr_type)
    if t == BufferType:
        descr_type: BufferType
        return Buffer(descr_type, parent, peripheral)
    elif t == PointerType:
        descr_type: PointerType
        return Pointer(descr_type, parent, peripheral)
    elif t == DescriptorType:
        descr_type: DescriptorType
        return Descriptor(descr_type, parent, peripheral)
    elif t == StatusType:
        descr_type: StatusType
        return Status(descr_type, parent, peripheral)
    else:
        assert False, f"Cannot instantiate unknown descriptor type: {descr_type}"
