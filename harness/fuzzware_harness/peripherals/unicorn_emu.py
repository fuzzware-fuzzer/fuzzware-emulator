from .emu_interface import EmuInterface
from ..tracing.trace_dma import add_dma_event
from ..native import nvic_set_pending, nvic_clear_pending, do_exit, get_latest_mmio_fuzz_access_index
from ..util import parse_address_value
from ..snapshot import is_snapshot_created

from .. import timer

import struct
import unicorn
import os, sys, traceback
from unicorn.unicorn_const import UC_HOOK_BLOCK, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE

import logging
logger = logging.getLogger("DMA")

CRASH_ADDR = 0xffff1337

class UnicornEmu(EmuInterface):
    uc: unicorn.Uc

    def __init__(self, uc, mmio_ranges, rw_ram_ranges):
        self.uc = uc
        super().__init__(mmio_ranges, rw_ram_ranges)

    # avatar2/targets/target.py
    def read_register(self, register):
        """
        Reading a register from the target
        :param register:     The name of the register
        :return:             The actual value read from the register
        """
        # Resolve via sparkles
        return getattr(self.uc.regs, register)

    # avatar2/targets/target.py
    def write_register(self, register, value):
        """
        Writing a register to the target
        :param register:     The name of the register
        :param value:        The actual value written to the register
        """
        setattr(self.uc.regs, register, value)

    # avatar2/targets/target.py
    def read_memory(self, address, size, num_words=1, raw=False) -> int | list | bytearray | None:
        """
        Reading from memory of the target
        :param address:     The address to read from
        :param size:        The size of a read word
        :param num_words:   The amount of words to read (default: 1)
        :param raw:         Whether the read memory is returned unprocessed
        :return:            The read memory
        """
        assert(num_words == 1)
        try:
            if raw:
                return self.uc.mem_read(address, size * num_words)
            else:
                if size == 1:
                    return self.uc.mem.u8(address, num_words)
                elif size == 2:
                    return self.uc.mem.u16(address, num_words)
                elif size == 4:
                    return self.uc.mem.u32(address, num_words)
                else:
                    assert(False)
        except unicorn.UcError:
            return None

    def read_bytes(self, address, length) -> bytearray | None:
        """
        Reading raw byte string from memory of the target.
        :param address:     The address to read from
        :param length:      The number of bytes to read.
        :return:            The read memory
        """
        try:
            return self.uc.mem_read(address, length)
        except unicorn.UcError:
            return None

    # avatar2/targets/target.py
    def write_memory(self, address, size, value, num_words=1, raw=False) -> bool:
        """
        Writing to memory of the target
        :param address:   The address from where the memory-write should
                          start
        :param size:      The size of the memory write
        :param value:     The actual value written to memory
        :type val:        int if num_words == 1 and raw == False
                          list if num_words > 1 and raw == False
                          str or byte if raw == True
        :param num_words: The amount of words to read
        :param raw:       Specifies whether to write in raw or word mode
        :return:          True on success else False
        """
        if raw:
            raw_mem = value
        else:
            # TODO: endianness support
            num2fmt = {1: 'B', 2: 'H', 4: 'I', 8: 'Q'}
            fmt = '<{}{}'.format(num_words, num2fmt[size])
            if num_words == 1:
                raw_mem = struct.pack(fmt, value)
            else:
                raw_mem = struct.pack(fmt, *value)

        try:
            self.uc.mem_write(address, raw_mem)
            return True
        except unicorn.UcError:
            return False

    def write_bytes(self, address, bytestr: bytes) -> bool:
        """
        Writing a raw byte string to memory of the target
        :param address:   The address from where the memory-write should
                          start
        :param bytestr:   The size of the memory write
        :return:          True on success else False
        """
        try:
            self.uc.mem_write(address, bytestr)
            return True
        except unicorn.UcError:
            return False

    def irq_set_level(self, irqnum, level):
        if level:
            self.irq_pulse(irqnum)
        else:
            nvic_clear_pending(self.uc)

    def irq_pulse(self, irqnum):
        nvic_set_pending(self.uc, irqnum)

    def timer_add(self, reload_val, handler, user_data=None):
        if user_data is not None:
            raise NotImplementedError("Passing user_data is currently not implemented")
        def timer_cb_wrap(uc):
            handler(user_data)
        timer_handle = timer.add_timer(reload_val, timer_cb_wrap)
        return timer_handle

    def timer_start(self, timer_handle):
        timer.start_timer(timer_handle)

    def timer_remove(self, timer_handle):
        timer.remove_timer(timer_handle)

    def timer_stop(self, timer_handle):
        timer.stop_timer(timer_handle)

    def timer_reload(self, timer_handle):
        timer.reset_timer(timer_handle)

    def timer_set_reload_val(self, timer_handle, reload_val):
        timer.set_timer_reload_val(timer_handle, reload_val)

    def crash(self):
        """
        Indicate an unrecoverable crash to have occurred
        """
        self.uc.regs.pc = CRASH_ADDR

    # Deprecated. Renamed to "exit" to avoid confusions with breakpoint functionality
    def stop(self):
        """
        Indicate the end of the current emulation run
        """
        self.exit()

    def exit(self):
        """
        Indicate the end of the current emulation run
        """
        do_exit(self.uc, 0)

    def add_block_hook(self, addr, handler, user_data=None):
        """ Note: Do not use this feature for debugging hooks. These may
        alter the emulator timing behavior due to TB growth.
        """

        assert not is_snapshot_created(), "Adding block hooks after snapshotting may make emulator behavior unpredictable"

        def hook_wrap(uc, addr, size, user_data):
            try:
                handler(user_data)
            except Exception as e:
                print(f"[ERROR] Got exception while trying to run a block hook: {e}", flush=True)
                print(traceback.format_exc())
                sys.stdout.flush()
                os._exit(1)

        return self.uc.hook_add(UC_HOOK_BLOCK, hook_wrap, begin=addr, end=addr+1, user_data=user_data)

    def rem_block_hook(self, hook_id):
        assert not is_snapshot_created(), "Removing block hooks after snapshotting may make emulator behavior unpredictable"

        return self.uc.hook_del(hook_id)

    def add_read_hook(self, start, end, handler, user_data=None):
        def hook_wrap(uc, access, address, size, value, user_data):
            try:
                handler(address, size, user_data)
            except Exception as e:
                print(f"[ERROR] Got exception while trying to run the read hook for access to {address:#x} (size: {size:#x}): {e}")
                print(traceback.format_exc())
                sys.stdout.flush()
                os._exit(1)

        return self.uc.hook_add(UC_HOOK_MEM_READ, hook_wrap, user_data, start, end)

    def rem_read_hook(self, hook_id):
        self.uc.hook_del(hook_id)

    def move_mem_hook(self, hook_id, start, end):
        self.uc.hook_move(hook_id, start, end)

    def add_write_hook(self, start, end, handler, user_data=None):
        def hook_wrap(uc, access, address, size, value, user_data):
            try:
                handler(address, size, value, user_data)
            except Exception as e:
                print(f"[ERROR] Got exception while trying to run the write hook for access [{address:#x}] = {value:#x} (size: {size:#x}): {e}")
                print(traceback.format_exc())
                sys.stdout.flush()
                os._exit(1)

        return self.uc.hook_add(UC_HOOK_MEM_WRITE, hook_wrap, user_data, start, end)

    def rem_write_hook(self, hook_id):
        self.uc.hook_del(hook_id)

    def trace_dma_write(self, buf_addr, val: bytes, fuzz_offset=None):
        if fuzz_offset is None:
            fuzz_offset = get_latest_mmio_fuzz_access_index()
            logger.debug(f"Resolved fuzz_offset to {fuzz_offset}")
        pc, lr = self.read_register("pc"), self.read_register("lr")

        logger.debug(f"got trace register values. pc: {pc:#x}, lr: {lr:#x}")
        add_dma_event(pc, lr, buf_addr, fuzz_offset, val)

    def resolve_symbol(self, name_or_addr):
        return parse_address_value(self.uc.symbols, name_or_addr)