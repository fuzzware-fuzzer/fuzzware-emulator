import copy
import logging

from .comm_interface import CommunicatorInterface
from .emu_interface import EmuInterface

logger = logging.getLogger("DMA")

CONFIG_NAME_PACKET_LIMIT = "packet_limit"

# enum mmio_handle_res_t
MMIO_HANDLE_RES_IS_HANDLED = 0
MMIO_HANDLE_RES_FORWARD_TO_DEFAULT = 1
MMIO_HANDLE_RES_PASSTHROUGH = 2

EPHEMERAL_ATTR_NAMES = [
    # Base configuration
    "name", "address", "size",
    "owned_irqs", "emu", "comm",
    "packet_limit"
]

class Peripheral():
    _snapshot = {}
    _snapshot_mmio_contents: bytes
    _tracing_enabled: bool

    # Auto-snapshot
    packets_placed: int

    def __init__(self, name, addr, size, owned_irqs, emu: EmuInterface, comm: CommunicatorInterface, config, **kwargs):
        self.name = name if name else f"{self.__class__.__name__}_{addr:x}"
        self.address = addr
        self.size = size
        self.owned_irqs = owned_irqs
        self.emu = emu
        self.comm = comm
        self.packets_placed = 0

        # TODO: Change the way the peripheral implementations forward kwargs (or explicitly pass the enable_tracing argument)
        if "kwargs" in kwargs:
            kwargs = kwargs["kwargs"]
        self._tracing_enabled = kwargs.get("enable_tracing", False)

        self.packet_limit = config.get(CONFIG_NAME_PACKET_LIMIT, 0xffffffff)

    def take_snapshot(self):
        for attr_name, value in self.__dict__.items():
            if attr_name.startswith("_") or attr_name in EPHEMERAL_ATTR_NAMES:
                continue

            self._snapshot[attr_name] = getattr(self, copy.deepcopy(attr_name))

        if self.size:
            self._snapshot_mmio_contents = bytes(self.emu.read_bytes(self.address, self.size))

    def restore_snapshot(self):
        for attr_name, val in self._snapshot.items():
            setattr(self, attr_name, copy.deepcopy(self._snapshot[attr_name]))

        if self.size:
            self.emu.write_bytes(self.address, self._snapshot_mmio_contents)

    def discard_snapshot(self):
        # print("Discarding snapshot")
        pass

    def trace_dma_write(self, buf_addr, val: bytes, fuzz_offset=None):
        logger.debug(f"Incoming request for adding a DMA trace entry, self._tracing_enabled={self._tracing_enabled}. buf_addr: {buf_addr:x}, val: {val.hex()}, fuzz_offset: {fuzz_offset}")
        if not self._tracing_enabled:
            return

        assert type(val) == bytes

        self.emu.trace_dma_write(buf_addr, val, fuzz_offset)

    def read_mmio_reg(self, offset, size=4):
        return self.emu.read_memory(self.address + offset, size)

    def write_mmio_reg(self, offset, value, size=4):
        return self.emu.write_memory(self.address + offset, size, value)

    # MMIO
    def hw_read(self, offset, size):
        # print("dummy hw_read", flush=True)

        # Return None to have wrapper forward status MMIO_HANDLE_RES_FORWARD_TO_DEFAULT
        return None

    # MMIO
    def hw_write(self, offset, size, value):
        # print("dummy hw_write", flush=True)
        return None

    # If IRQ is not associated with a device
    # Allows for a trigger workaround
    def interrupt_pending_trigger(self, irq_num):
        # print(f"[can_pend] called for irq_num={irq_num}", flush=True)
        pass

    # Called when fuzzer tries to pend an owned interrupt
    # ALTERNATIVE implementation: actively set/unset interrupt to be allowed
    def can_pend_interrupt(self, irq_num):
        # print(f"[can_pend] called for irq_num={irq_num}", flush=True)
        return True

    # Called when interrupt is actually activated
    def on_interrupt_entry(self, irq_num):
        # print(f"[on_interrupt_entry] called for irq: {irq_num}", flush=True)
        pass

    # Called when interrupt is actually activated
    def on_interrupt_exit(self, irq_num):
        # print(f"[on_interrupt_exit] called for irq: {irq_num}", flush=True)
        pass

    def read_memory(self, addr, size) -> bytes:
        """ Returns raw memory contents for non-MMIO memory addresses, and fuzzing input for addresses belonging to MMIO.

            :param addr:    The address to read from
            :param size:    Number of bytes to read
            :return:        size bytes of either memory contents or fuzzing input
        """
        if self.emu.is_in_mmio_range(addr):
            assert self.emu.is_in_mmio_range(addr + size)
            logger.debug(f"[read_memory] get {size} bytes of fuzzing input")
            return self.comm.get_bytes(size)
        else:
            logger.debug(f"[read_memory] read {size} from RAM at addr {addr:08x}")
            return bytes(self.emu.read_memory(addr, size, raw=True))

    def inc_packet_count(self) -> bool:
        self.packets_placed += 1
        if self.packet_limit != 0 and self.packets_placed > self.packet_limit:
            if logger.level <= logging.DEBUG:
                logger.debug(f"[{self.name}] packet placement limit reached")
            self.emu.stop()
            return False
        return True
