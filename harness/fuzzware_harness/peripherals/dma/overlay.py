from .. import Peripheral
from ...exceptions import OutOfFuzzingInputException
from typing import Set, Dict, Tuple, Callable
from .sizerange import BUF_SIZE_GROW_INDEFINITELY, BUF_SIZE_GROW_DISABLE, resolve_max_size

import copy

import logging
logger = logging.getLogger("GDMABuf")

# Lookahead area
BUF_EXTENSION_LOOKAHEAD_SIZE = 4
class DMAOverlay:
    """ Fuzzer-controlled memory region

    This class handles low-level buffer filling
    in an on-demand manner.

    Note: Depending on performance requirements, this could
    be lowered into native code.
    """
    peripheral: Peripheral
    _read_callback: Callable[[int, int, int, None], None]
    addr: int | None
    size: int
    extended_max_size: int

    # We keep count of the memory that we have already filled with fuzzing input
    mem_read_hook_handle: None
    written_addrs: Set[int]
    access_counts: Dict[Tuple[Tuple[int], int], int]

    # Access-based refreshing
    access_timer_id: None
    num_accesses_before_refresh: int
    access_context_regs: Tuple[str]

    # Snapshot state
    saved_addr: int
    saved_size: int
    saved_extended_max_size: int
    snapshot_taken: bool
    saved_written_addrs: Set[int]
    saved_access_counts: Dict[Tuple[Tuple[int], int], int]

    def __init__(self, peripheral: Peripheral, addr: int, size: int, extended_maxsize: None | int, access_timeout: int, num_allowed_reaccesses: int, access_context_regs: Tuple):
        self.peripheral = peripheral
        self.addr, self.size = None, None
        self.access_timer_id = None
        self.saved_addr, self.saved_size, self.saved_extended_max_size = None, 0, BUF_SIZE_GROW_DISABLE
        self.snapshot_taken = False
        self.num_accesses_before_refresh = num_allowed_reaccesses
        self.mem_read_hook_handle = None
        self.access_context_regs = access_context_regs
        self.written_addrs, self.saved_written_addrs = set(), set()
        self.access_counts, self.saved_access_counts = dict(), dict()

        if access_timeout:
            def cb_access_timeout(user_data):
                peripheral.refresh()
            self.access_timer_id = peripheral.emu.timer_add(access_timeout, cb_access_timeout, None)

        def _read_callback(addr, size, _):
            self._on_read(addr, size)
        self._read_callback = _read_callback

        self.set_location(addr, size, extended_maxsize)

    def set_location(self, addr, size, extended_maxsize, refresh_on_update=True):
        extended_maxsize = resolve_max_size(extended_maxsize, size)

        if self.addr == addr and self.size == size and self.extended_max_size == extended_maxsize:
            if size != 0:
                logger.debug(f"On-demand buffer location still at: {addr:#x} (size: {size:#x}, max size: {extended_maxsize:#x})")
            return

        if logger.level <= logging.DEBUG:
            logger.debug(f"On-demand buffer changed. Now at: {hex(addr) if addr is not None else 'inactive'} (size: {size}, max size: {extended_maxsize:#x})")

        # We have a change in location
        self.addr = addr
        self.size = size
        self.extended_max_size = extended_maxsize
        self._update_read_hook(addr, size)
        if refresh_on_update:
            self.refresh()

    def refresh(self) -> None:
        if self.access_timer_id is not None:
            # We are stopping the timer as it will be re-started on memory access
            self.peripheral.emu.timer_stop(self.access_timer_id)
        if logger.level <= logging.DEBUG:
            logger.debug(f"On-demand buffer refresh")
        self.written_addrs.clear()
        self.access_counts.clear()

    def _update_read_hook(self, addr, size):
        if size == 0:
            logger.debug("Removing on-demand read hook due to size 0 (_update_read_hook)")
            if self.mem_read_hook_handle is not None:
                self.peripheral.emu.rem_read_hook(self.mem_read_hook_handle)
                self.mem_read_hook_handle = None
            return

        # We may want to look
        if size < self.extended_max_size:
            hooked_size = min(size + BUF_EXTENSION_LOOKAHEAD_SIZE, self.extended_max_size)
            logger.debug(f"Extending hooked size for buffer extension. Size: {size}, hooked size: {hooked_size}")
        else:
            hooked_size = size

        end_addr = addr + hooked_size - 1
        if self.mem_read_hook_handle is not None:
            logger.debug("Moving existing on-demand read hook (_update_read_hook)")
            self.peripheral.emu.move_mem_hook(self.mem_read_hook_handle, addr, end_addr)
        else:
            logger.debug(f"Adding on-demand read hook for range {addr:x}-{end_addr:#x}")
            self.mem_read_hook_handle = self.peripheral.emu.add_read_hook(addr, end_addr, self._read_callback, None)

    def _get_buf_access_context_reg_vals(self) -> Tuple:
        if self.access_context_regs:
            return tuple((self.peripheral.emu.read_register(reg) for reg in self.access_context_regs))
        else:
            return tuple()

    def _on_read(self, addr, access_size):
        """
        Handle read on on-demand region.

        1. First figure out whether we have already filled in contents
        2. Then see whether we need to refresh the full buffer (due to too many reaccesses)
        """
        timer_refresh_required = False

        buf_offset = addr - self.addr
        required_size = buf_offset + access_size

        if logger.level <= logging.DEBUG:
            logger.debug(f"{self}: Handling on-demand read to address: {addr:#x} (size: {access_size:#x}, required_size: {required_size:#x}, max size: {self.extended_max_size:#x})")

        if required_size > self.extended_max_size:
            logger.warning("Access lies outside the maximum range, ignoring the access")
            return

        if required_size > self.size:
            overflow_size = required_size - self.size
            if overflow_size <= 2 * access_size:
                logger.debug(f"Detected linear access outside the buffer, extending it")
                self.set_location(self.addr, required_size, self.extended_max_size, refresh_on_update=False)
            else:
                logger.debug(f"Detected linear access outside the buffer, but read does not seem consecutive (enough)")

        # Check whether we need to refresh before the access
        if (self.num_accesses_before_refresh >= 0) or self.access_timer_id is not None:
            # We track the accesses per access context, calculate that first
            access_context_regs = self._get_buf_access_context_reg_vals()
            if logger.level <= logging.DEBUG:
                logger.debug(f"Got register access context: {list(map(hex, access_context_regs))}")

            for req_addr in range(addr, addr+access_size):
                access_context = (access_context_regs, req_addr)
                if access_context not in self.access_counts:
                    timer_refresh_required = True
                    num_reaccesses = 0
                else:
                    num_reaccesses = self.access_counts[access_context] + 1
                self.access_counts[access_context] = num_reaccesses

                if num_reaccesses > self.num_accesses_before_refresh:
                    logger.debug("Buffer has been reaccessed too many times, refreshing")
                    self.refresh()
                    if not self.peripheral.inc_packet_count():
                        return
                    return self._on_read(addr, access_size)

            logger.debug("Buffer reaccesses okay")

            if self.access_timer_id is not None and timer_refresh_required:
                self.peripheral.emu.timer_reload(self.access_timer_id)
                self.peripheral.emu.timer_start(self.access_timer_id)

        # Fill in the actual contents if necessary
        for req_addr in range(addr, addr+access_size):
            if req_addr not in self.written_addrs:
                self.written_addrs.add(req_addr)
                try:
                    fuzz_byte = self.peripheral.comm.get_bytes(1)
                except OutOfFuzzingInputException:
                    logger.debug(f"Ran out of fuzzing input, run has been stopped")
                    return

                # TODO: Chunk the DMA write?
                self.peripheral.trace_dma_write(req_addr, fuzz_byte)
                if logger.level <= logging.DEBUG:
                    logger.debug(f"Writing byte {fuzz_byte.hex()} to addr {req_addr:#x}")
                write_success = self.peripheral.emu.write_bytes(req_addr, fuzz_byte)
                if not write_success:
                    logger.warning(f"Could not write to the buffer at: {req_addr:#x}")
            else:
                if logger.level <= logging.DEBUG:
                    logger.debug(f"Leaving value at {req_addr:#x} as-is.")

    def deactivate(self):
        if logger.level <= logging.DEBUG:
            logger.debug(f"On-demand buffer cleanup")
        self.set_location(None, 0, BUF_SIZE_GROW_DISABLE, refresh_on_update=True)

    def take_snapshot(self) -> None:
        self.saved_addr = self.addr
        self.saved_size = self.size
        self.saved_extended_max_size = self.extended_max_size

        self.snapshot_taken = True

        self.saved_written_addrs = copy.deepcopy(self.written_addrs)
        self.saved_access_counts = copy.copy(self.access_counts)

    def restore_snapshot(self) -> None:
        # Setting the location also takes care of the memory read hook

        if not self.snapshot_taken:
            logger.debug("No snapshot for buffer, deactivating")
            # We have not existed upon taking the snapshot, deactivate self now
            return self.deactivate()

        # A snapshot has been taken
        logger.debug("Restoring existing snapshot")
        self.set_location(self.saved_addr, self.saved_size, self.saved_extended_max_size)
        self.written_addrs = copy.copy(self.saved_written_addrs)
        self.access_counts = copy.copy(self.saved_access_counts)

        # The timer (if one is required) gets reset by native snapshotting

    def __del__(self):
        if self.access_timer_id is not None:
            self.peripheral.emu.timer_remove(self.access_timer_id)
            self.access_timer_id = None

        if self.mem_read_hook_handle is not None:
            self.peripheral.emu.rem_write_hook(self.mem_read_hook_handle)
            self.mem_read_hook_handle = None

    def __str__(self):
        return f"DMAOverlay({hex(self.addr) if self.addr is not None else 'inactive'}, {self.size:#x})"

    def __repr__(self):
        return self.__str__()