from binascii import hexlify

from ..peripheral import Peripheral
from .. import MMIO_HANDLE_RES_PASSTHROUGH, MMIO_HANDLE_RES_FORWARD_TO_DEFAULT

DEFAULT_BASE_ADDR = 0x40020000
DEFAULT_SIZE = 0x100
DEFAULT_IRQ_NUM = 27
""" Config entry in config.yml
  my_sample_peripheral:
    class: fuzzware_harness.peripherals.example.SampleDMAPeripheral
    base_addr: 0x40020000
    size: 0x100
    owned_irqs:
        - 27
"""

NUM_CHANNELS = 7
class SampleDMAPeripheral(Peripheral):
    enabled_channels = NUM_CHANNELS * [False]

    # Is it's the device's turn to insert input atm?
    # This is steered by filling contents + raising interrupts (to transfer ownership from device to fw)
    # and by the fw writing to the interrupt clear register
    device_owns_buffer = NUM_CHANNELS * [True]

    def __init__(self, name, addr, size, owned_irqs, emu, comm, config=None, **kwargs):
        if addr is None:
            addr = DEFAULT_BASE_ADDR

        if size is None:
            size = DEFAULT_SIZE

        if not owned_irqs:
            owned_irqs = (DEFAULT_IRQ_NUM, )

        super().__init__(name, addr, size, owned_irqs, emu, comm, config, kwargs=kwargs)

    def take_snapshot(self):
        parent_snapshot = super().take_snapshot()

        # Messing up value after the snapshot is taken
        # We could put custom snapshot taking logic here

    def restore_snapshot(self):
        super().restore_snapshot()

        # We could put custom restoration logic here

    def can_pend_interrupt(self, irq_num):
        return True

    def on_interrupt_entry(self, irq_num):
        print(f"[SampleDMAPeripheral] irq num: {irq_num}")

    def on_interrupt_exit(self, irq_num):
        print(f"[SampleDMAPeripheral] irq num: {irq_num}")

    # MMIO read
    def hw_read(self, offset, size):
        # We handle the registers in place in memory, so pass reads through
        status = MMIO_HANDLE_RES_PASSTHROUGH
        val = None

        # If we wanted to have default modeling take care of the access, we
        # can either:
        # 1. use this status instead
        # status = MMIO_HANDLE_RES_FORWARD_TO_DEFAULT
        # 2. or return None
        # return None

        # Alternate format: int value for successful handling, None for MMIO modeling forward
        # if handled:
        #   val = 0x1337
        # else:
        #   val = None
        # return val

        return status, val

    # MMIO write
    def hw_write(self, offset, size, value):
        print(f"hw_write called. offset: {offset:#x}, value: {value:#x}")
