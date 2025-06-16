from abc import ABC, abstractmethod

from typing import Callable, Any

class EmuInterface:
    def __init__(self, mmio_ranges, rw_ram_ranges=None):
        self.mmio_ranges = mmio_ranges
        self.rw_ram_ranges = rw_ram_ranges or []

    # avatar2/targets/target.py
    @abstractmethod
    def read_register(self, register):
        """
        Reading a register from the target
        :param register:     The name of the register
        :return:             The actual value read from the register
        """
        pass

    # avatar2/targets/target.py
    @abstractmethod
    def write_register(self, register, value):
        """
        Writing a register to the target
        :param register:     The name of the register
        :param value:        The actual value written to the register
        """
        pass

    # avatar2/targets/target.py
    @abstractmethod
    def read_memory(self, address, size, num_words=1, raw=False) -> int | list | bytearray | None:
        """
        Reading from memory of the target
        :param address:     The address to read from
        :param size:        The size of a read word
        :param num_words:   The amount of words to read (default: 1)
        :param raw:         Whether the read memory is returned unprocessed
        :return:            The read memory
        """
        pass

    @abstractmethod
    def read_bytes(self, address, length) -> bytearray | None:
        """
        Reading raw byte string from memory of the target.
        :param address:     The address to read from
        :param length:      The number of bytes to read.
        :return:            The read memory
        """
        pass

    # avatar2/targets/target.py
    @abstractmethod
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
        :returns:         True on success else False
        """
        return False

    @abstractmethod
    def write_bytes(self, address, bytestr: bytes) -> bool:
        """
        Writing a raw byte string to memory of the target
        :param address:   The address from where the memory-write should
                          start
        :param bytestr:   The size of the memory write
        :return:          True on success else False
        """
        return False

    @abstractmethod
    def irq_set_level(self, irqnum, level):
        pass

    @abstractmethod
    def irq_pulse(self, irqnum):
        pass

    @abstractmethod
    def timer_add(self, reload_val, handler, user_data):
        pass

    @abstractmethod
    def timer_remove(self, timer_handle):
        pass

    @abstractmethod
    def timer_start(self, timer_handle):
        pass

    @abstractmethod
    def timer_stop(self, timer_handle):
        pass

    @abstractmethod
    def timer_reload(self, timer_handle):
        pass

    @abstractmethod
    def timer_set_reload_val(self, timer_handle):
        pass

    @abstractmethod
    def crash(self):
        """
        Indicate an unrecoverable crash to have occurred
        """
        pass

    # Deprecated. Renamed to "exit" to avoid confusions with breakpoint functionality
    def stop(self):
        """
        Indicate the end of the current emulation run
        """
        self.exit()

    @abstractmethod
    def exit(self):
        pass

    def is_in_mmio_range(self, address) -> bool:
        for start, end in self.mmio_ranges:
            if start <= address and  address < end:
                return True
        return False

    def is_in_rw_ram_range(self, address) -> bool:
        for start, end in self.rw_ram_ranges:
            if start <= address and  address < end:
                return True
        return False

    @abstractmethod
    def add_block_hook(self, addr, handler, user_data=None):
        pass

    @abstractmethod
    def rem_block_hook(self, hook_id):
        pass

    @abstractmethod
    def add_read_hook(self, start, end, handler: Callable[[int, int, Any], None], user_data=None):
        """ Add a hook on a read access to a specific address range
        The handler requires the following arguments:

        def handler(address, size, user_data):
            pass
        """
        pass

    @abstractmethod
    def rem_read_hook(self, hook_id):
        pass

    @abstractmethod
    def move_mem_hook(self, hook_id, start, end):
        pass

    @abstractmethod
    def add_write_hook(self, start, end, handler, user_data=None):
        """ Add a hook on a write access to a specific address range
        The handler requires the following arguments:

        def handler(address, size, value, user_data):
            pass
        """
        pass

    @abstractmethod
    def rem_write_hook(self, hook_id):
        """Remove a hook created via add_write_hook
        """
        pass

    @abstractmethod
    def trace_dma_write(self, buf_addr, val: bytes, fuzz_offset=None):
        pass

    def resolve_symbol(self, sym_or_addr):
        """Resolve a configuration value to the corresponding integer.
        For integers,
        """
        if type(sym_or_addr) == int:
            return sym_or_addr
        else:
            return None
