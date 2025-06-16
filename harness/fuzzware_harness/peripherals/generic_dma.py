from . import Peripheral, MMIO_HANDLE_RES_PASSTHROUGH
from .emu_interface import EmuInterface
from .dma import POINTER_SIZE
from .dma.overlay import DMAOverlay

from .dma.descriptor_type import TypeDescription, reuse_or_create_type, TYPE_NAME_POINTER
from .dma.descriptor_fields import instantiate_from_type, Pointer
from .dma.sizerange import SizeRange, BUF_SIZE_GROW_INDEFINITELY

from typing import List, Dict
import os

"""
### Snapshot strategy ###
One important aspect here is that we need to be able to snapshot the peripheral state in all cases.
As we have interactions with the native state (e.g., timers are handled natively), we need to be a
bit careful with how we implement snapshotting.

1. Basic Block hooks
    - Potential issue: If we add/remove basic block hooks during runtime that get JITed, we can alter timing behavior
    - Approach: All necessary Basic Block Hooks are set during configuration time
    -> Snapshots never need to set / remove basic block hooks upon snapshot restore
2. Timers
    - Potential issue: If we create timers during execution, timer handles may get de-synced with the native implementation
    - Approach: All necessary timers are created (but not always started) during configuration time
    - Timer snapshotting is done by native component
    -> We can simply start timers anew during each run when enabling buffers, they will be reset by native timer snapshotting
2. DMA Buffers
    - Potential issue: Buffers can be added / removed dynamically while firmware is running. We need to keep track of that
    - Approach: We take care of the different situations in the snapshotting logic
    - i.e., During snapshot restoration, there may be DMA buffers in the snapshot which are no longer present in the emulator state
        -> need to be able to (re-)add DMA buffers to emulator state upon snapshot restore
        -> TODO: For DMA regions that are added post snapshot, disable them and re-activate during the run instead of fully deleting
    - i.e., During snapshot restoration, there may be DMA buffers in the emulator state which have not been in the snapshot
        -> need to be able to fully remove/disable DMA buffers from emulator state

### Enabling default logic ###

1. Fixed location
    - immediately (this means fuzzing input upon first access)
2. Variable location
    - On MMIO write (initial configuration) -> "on_first_config"
    - For DMA Descriptors
        - Maybe add a bit of delay to allow for setting up DMA descriptors

### Refresh default logic ###
- Reconfiguration (with small grace period)
- Timeout between fresh accesses to buffer
    - On access to buffer, with short-ish access timeout
    - Accesses differentiated by context (access from pc / pc+lr)

1. Fixed location
2. Variable location
    - On MMIO register write (reconfiguration)
2.1. Direct MMIO
2.2. Descriptors
    - Reconfiguration (if available)
        - On write to activation field in descriptor (re-activation)
        - On write to pointer fields (reconfiguration)?
"""

import logging
logger = logging.getLogger("GDMA")

DEFAULT_CFG_NUM_BUF_REACCESSES = DEFAULT_CFG_NUM_STATUS_REACCESSES = 0
DEFAULT_CFG_BUF_ACCESS_TIMEOUT_TICKS = DEFAULT_CFG_STATUS_ACCESS_TIMEOUT_TICKS = 0
DEFAULT_CFG_BUF_ACCESS_CONTEXT_REGS = DEFAULT_CFG_STATUS_ACCESS_CONTEXT_REGS = ("pc", )

SUPPORTED_ACCESS_CONTEXT_REGS = ("pc", "lr")

DEFAULT_BUFFER_REFRESH_CONFIG = [
    {"type": "on_reaccess"}
]

DEFAULT_STATUS_REFRESH_CONFIG = [
    {"type": "on_reaccess"}
]

class GenericDMAC(Peripheral):
    # Auto-saved
    # None

    # Custom snapshotting
    _bufs: List[DMAOverlay]
    _descriptors: Dict[int, Pointer]                        # addr: Pointer object
    _descriptor_types: Dict[int, TypeDescription]           # addr: type
    _descriptor_custom_typedefs: Dict[str, TypeDescription] # name: type

    # Internal variables, constant after initialization
    _known_sizes: Dict[int, SizeRange]
    _num_buf_reaccesses_until_refresh: int
    _buf_access_timeout_ticks: int

    def __init__(self, name, addr, size, owned_irqs, emu, comm, config, **kwargs):
        super().__init__(name, addr, size, owned_irqs, emu, comm, config, **kwargs)

        self._bufs = []
        self._known_sizes = {}
        self._descriptors = {}
        self._descriptor_types = {}
        self._descriptor_custom_typedefs = {}

        self._num_buf_reaccesses_until_refresh, self._num_status_reaccesses_until_refresh = 0, 0
        self._buf_access_timeout_ticks, self._status_access_timeout_ticks = 0, 0
        self._access_context_regs, self._status_access_context_regs = (), ()

        mmio_reg_addr, mmio_reg_size, owned_irqs_from_dma_cfg = self.parse_generic_dma_config(emu, config)

        # The MMIO address of the buffer/descriptor pointer is extracted from the configuration
        # Ensure that there is no mismatch between an optional peripheral region base/size
        orig_region_valid = addr is not None and size
        if mmio_reg_addr is not None:
            if orig_region_valid and mmio_reg_addr != addr:
                logger.error(f"Invalid config: GDMA base address specified explicitly, but differs from config-implied region. Explicitly defined: {addr:#x}, implied in descriptor/buffer config: {mmio_reg_addr:#x}")
                os._exit(-1)
            self.address = mmio_reg_addr
        if mmio_reg_size is not None:
            if orig_region_valid and mmio_reg_size != size:
                logger.error(f"Invalid config: GDMA region size specified explicitly, but differs from size of config-implied region. Explicitly defined: {size:#x}, implied in descriptor/buffer config: {mmio_reg_size:#x}")
                os._exit(-1)
            self.size = mmio_reg_size

        if owned_irqs_from_dma_cfg:
            if owned_irqs and sorted(owned_irqs) != sorted(owned_irqs_from_dma_cfg):
                logger.error(f"Invalid config: Owned IRQs specified explicitly, but differs from config-implied irqs. Explicitly defined: {owned_irqs}, implied in descriptor/buffer config: {owned_irqs_from_dma_cfg}")
                os._exit(-1)
            self.owned_irqs = owned_irqs_from_dma_cfg

    def resolve_value(self, val):
        if type(val) == int:
            return val
        res = None
        if type(val) == str:
            res = self.emu.resolve_symbol(val)
        if res is None:
            raise ValueError(f"Could not resolve {val} to a numeric value")
        return res

    def parse_refresh_options(self, refresh_cfg: list):
        assert type(refresh_cfg) == list

        for refresh_entry in refresh_cfg:
            refresh_type = refresh_entry.get("type")

            if refresh_type == "on_reaccess":
                self._access_context_regs = refresh_entry.get("access_context_regs", DEFAULT_CFG_BUF_ACCESS_CONTEXT_REGS)
                assert type(self._access_context_regs) in (list, tuple)
                assert all(type(reg_name) == str for reg_name in self._access_context_regs)
                self._access_context_regs = tuple(reg_name.lower() for reg_name in self._access_context_regs)
                assert all(reg_name in SUPPORTED_ACCESS_CONTEXT_REGS for reg_name in self._access_context_regs)

                self._num_buf_reaccesses_until_refresh = refresh_entry.get("num_reaccesses", DEFAULT_CFG_NUM_BUF_REACCESSES)
                assert type(self._num_buf_reaccesses_until_refresh) == int

                self._buf_access_timeout_ticks = refresh_entry.get("timeout_ticks", DEFAULT_CFG_BUF_ACCESS_TIMEOUT_TICKS)
                assert type(self._buf_access_timeout_ticks) == int
            else:
                logger.error(f"Unknown refresh config type: {refresh_type} for entry {refresh_entry}")
                os._exit(-1)

    def parse_status_refresh_options(self, refresh_cfg: list):
        assert type(refresh_cfg) == list

        for refresh_entry in refresh_cfg:
            refresh_type = refresh_entry.get("type")

            if refresh_type == "on_reaccess":
                self._status_access_context_regs = refresh_entry.get("access_context_regs", DEFAULT_CFG_STATUS_ACCESS_CONTEXT_REGS)
                assert type(self._status_access_context_regs) in (list, tuple)
                assert all(type(reg_name) == str for reg_name in self._status_access_context_regs)
                self._status_access_context_regs = tuple(reg_name.lower() for reg_name in self._status_access_context_regs)
                assert all(reg_name in SUPPORTED_ACCESS_CONTEXT_REGS for reg_name in self._status_access_context_regs)

                self._num_status_reaccesses_until_refresh = refresh_entry.get("num_reaccesses", DEFAULT_CFG_NUM_STATUS_REACCESSES)
                assert type(self._num_status_reaccesses_until_refresh) == int

                self._status_access_timeout_ticks = refresh_entry.get("timeout_ticks", DEFAULT_CFG_STATUS_ACCESS_TIMEOUT_TICKS)
                assert type(self._status_access_timeout_ticks) == int
                if self._status_access_timeout_ticks != DEFAULT_CFG_STATUS_ACCESS_TIMEOUT_TICKS:
                    raise NotImplementedError("timeout_ticks not implemented for status refresh")

                logger.debug(f"Status refresh config: num reaccesses={self._num_status_reaccesses_until_refresh}, context regs={self._status_access_context_regs}")
            else:
                logger.error(f"Unknown refresh config type: {refresh_type} for entry {refresh_entry}")
                os._exit(-1)

    def parse_known_buf_sizes(self, size_cfg: dict):
        res = {}

        valid_range_fieldnames = ["min", "max"]
        for addr, range_dict in size_cfg.items():
            assert type(range_dict) == dict
            assert all(name in valid_range_fieldnames for name in range_dict)

            addr = self.resolve_value(addr)
            # Default: Do not grow the buffer
            min_size = range_dict.get("min", 1)
            max_size = range_dict.get("max", min_size)
            assert type(min_size) == int and type(max_size) == int
            range = SizeRange(min_size, max_size)
            res[addr] = range

        return res

    def parse_buf_config(self, buf_cfg: dict):
        # Buffer size (either inlined or from known sizes)
        size = None
        max_size = None
        size_cfg: dict = buf_cfg.get('size') or {}

        if type(size_cfg) == int:
            size = max_size = size_cfg
        elif size_cfg:
            size_type = size_cfg.get('type', 'fixed')

            if size_type == 'fixed':
                size = size_cfg.get('min')
                if size is None:
                    # Compatibility alias
                    size = size_cfg.get('val')
                assert type(size) == int
                # Default: Do not grow the buffer
                max_size = size_cfg.get('max', size)
            else:
                print(f"Unknown size type: '{size_type}'")
                os._exit(-1)

        # Buffer base address
        base_cfg: dict = buf_cfg.get('base', {})
        assert type(base_cfg) == dict

        baseaddr_type = base_cfg['type']
        if baseaddr_type == "fixed":
            buf_addr = self.resolve_value(base_cfg['addr'])

            if size is None:
                # No inline size given, check known size
                size_range = self._known_sizes.get(buf_addr)
                if not size_range:
                    logger.warning("No buffer size given, defaulting to initially small, infinitely-growing buffer")
                    size_range = SizeRange(1, BUF_SIZE_GROW_INDEFINITELY)
                size, max_size = size_range.minsize, size_range.maxsize

            logger.info(f"Adding buffer at address {buf_addr:#x} (size: {size}, max_size: {max_size})")
            self._bufs.append(
                DMAOverlay(self, buf_addr, size, max_size,
                    self._buf_access_timeout_ticks, self._num_buf_reaccesses_until_refresh,
                    self._access_context_regs)
            )
        else:
            print(f"Unknown base address type: '{baseaddr_type}'")
            os._exit(-1)

    def parse_descriptor_config(self, descr_config: dict):
        root_descr_type = descr_config.setdefault("type", TYPE_NAME_POINTER)
        assert root_descr_type == TYPE_NAME_POINTER
        pointer_addr = self.resolve_value(descr_config['addr'])
        assert pointer_addr not in self._descriptor_types, "Cannot have multiple descriptors at the same address"

        logger.info(f"Got DMA descriptor at MMIO address: {pointer_addr:#x}")
        descr_type = self._descriptor_types[pointer_addr] = reuse_or_create_type(descr_config, self._descriptor_custom_typedefs, self)

        descr = self._descriptors[pointer_addr] = instantiate_from_type(descr_type, None, self)
        descr.set_location(pointer_addr)

    def parse_generic_dma_config(self, emu: EmuInterface, config: dict):
        peripheral_region_addr, peripheral_region_size, owned_irqs = None, None, []

        self.parse_refresh_options(config.get("refresh", DEFAULT_BUFFER_REFRESH_CONFIG))
        self.parse_status_refresh_options(config.get("status_refresh", DEFAULT_STATUS_REFRESH_CONFIG))

        self._known_sizes = self.parse_known_buf_sizes(config.get("known_sizes", {}))
        assert type(self._known_sizes) == dict

        # Parse Static buffers
        buffer_cfgs = config.get("buffers", [])
        assert type(buffer_cfgs) == list

        # Convenience alias: "buffer"
        buf_cfg = config.get("buffer", None)
        if buf_cfg:
            buffer_cfgs.append(buf_cfg)

        for buf_cfg in buffer_cfgs:
            self.parse_buf_config(buf_cfg)

        # Parse descriptor definitions
        descr_configs = config.get("descriptors", [])
        assert type(descr_configs) == list

        for descr_cfg in descr_configs:
            logger.info(f"Parsing DMA descriptor config: {descr_cfg}")
            self.parse_descriptor_config(descr_cfg)
        for addr, descr_type in self._descriptor_types.items():
            logger.info(f"Descriptor[{addr:#08x}] {descr_type}")

        # If we have descriptors, register the whole span between their base MMIO registers
        if self._descriptor_types:
            peripheral_region_addr = min(self._descriptor_types)
            peripheral_region_size = max(self._descriptor_types) - peripheral_region_addr + POINTER_SIZE

        return peripheral_region_addr, peripheral_region_size, owned_irqs

    # MMIO
    def hw_read(self, offset, size):
        """ As of now, we only register an MMIO region for
        DMA descriptor pointer MMIO registers. We treat these
        as custom passthrough addresses to make sure the pointer
        stays intact when re-read by firmware.

        UNSUPPORTED: This does not account for the situation where the
        hardware increments the pointer after writing DMA
        buffer contents. However, this is a behavior that we
        currently do not support.
        """

        # UNSUPPORTED: This does not support unaligned writes
        if size == POINTER_SIZE and self.address + offset in self._descriptors:
            # Indicate the wrapper to maintain the previously-written value
            return MMIO_HANDLE_RES_PASSTHROUGH, None

        # If this is not an MMIO base register, let MMIO models handle it
        return None

    # MMIO
    def hw_write(self, offset, size, value):
        """ As of now, we only register an MMIO region for
        DMA descriptor pointer MMIO registers.

        When the MMIO registers are written to the write is passed
        through to the respective descriptor.
        """
        # TODO (perf): Could disable the write hook entirely
        return None

    def take_snapshot(self):
        super().take_snapshot()

        for buf in self._bufs:
            buf.take_snapshot()

        for descr in self._descriptors.values():
            descr.take_snapshot()

    def restore_snapshot(self):
        super().restore_snapshot()

        if logger.level <= logging.DEBUG:
            logger.debug("restore_snapshot")

        for buf in self._bufs:
            buf.restore_snapshot()

        for descr in self._descriptors.values():
            descr.restore_snapshot()

    def discard_snapshot(self):
        logger.debug("Discarding snapshot")
        pass
