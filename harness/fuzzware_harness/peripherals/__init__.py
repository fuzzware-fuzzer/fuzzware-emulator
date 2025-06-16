import importlib
import logging
import os
import sys
from typing import List, Tuple
from unicorn import UC_HOOK_MEM_WRITE

from .peripheral import Peripheral, MMIO_HANDLE_RES_IS_HANDLED, MMIO_HANDLE_RES_FORWARD_TO_DEFAULT, MMIO_HANDLE_RES_PASSTHROUGH
from .unicorn_emu import UnicornEmu
from .comm_interface import FuzzwareCommunicator

from .. import native
from ..snapshot import subscribe_state_snapshotting
from ..exceptions import OutOfFuzzingInputException

CONFIG_NAME_PERIPHERALS = 'peripherals'
CONFIG_NAME_BASE_ADDR = 'base_addr'
CONFIG_NAME_REGION_SIZE = 'size'
CONFIG_NAME_IRQS = 'irqs'

logger = logging.getLogger("DMA")
peripherals = []
irq_to_periph_assignments = {}

def import_class(path) -> Peripheral:
    try:
        # Resolve the class name
        module_path, class_name = path.rsplit('.', 1)
        print(module_path, class_name)

        mod = importlib.import_module(module_path)
        class_obj = getattr(mod, class_name)
        return class_obj
    except (ModuleNotFoundError, AttributeError):
        import traceback
        logger.error(f"Unable to import class {class_name} for path: {path}")
        traceback.print_exc()
        os._exit(1)

def parse_peripheral_configs(uc, config_map: dict, mmio_ranges: List[Tuple[int, int]], rw_ram_ranges: List[Tuple[int, int]], dma_tracing_enabled: bool):
    """ Parses a list of (DMA) controller peripheral configs
    """
    emu_interface = UnicornEmu(uc, mmio_ranges, rw_ram_ranges)
    comm = FuzzwareCommunicator()

    config_map = config_map.get(CONFIG_NAME_PERIPHERALS, {})
    if not config_map:
        return []

    configured_peripherals = []
    for device_name, dev_config in config_map.items():
        logger.debug(f"Parsing peripheral config entry {dev_config}")

        class_path = dev_config.get('class', '')
        if not class_path:
            logger.error(f"Config error: DMA peripheral configuration is missing 'class' entry. Please provide a valid class path.")
            os._exit(1)

        base_addr = dev_config.get(CONFIG_NAME_BASE_ADDR, None)
        if base_addr is None:
            logger.warning(f"Config warning: DMA peripheral configuration is missing '{CONFIG_NAME_BASE_ADDR}' entry. Relying on the peripheral to provide its own default base address.")
        region_size = dev_config.get(CONFIG_NAME_REGION_SIZE, None)
        if region_size is None:
            logger.warning(f"Config warning: DMA peripheral configuration is missing '{CONFIG_NAME_REGION_SIZE}' entry. Relying on the peripheral to provide its own default MMIO region size.")
        owned_irqs = dev_config.get(CONFIG_NAME_IRQS, ())
        if not owned_irqs:
            logger.warning(f"Config warning: DMA peripheral configuration is missing '{CONFIG_NAME_IRQS}' entry. Peripheral owns no irqs and the fuzzer will inject interrupts for it.")

        device = import_class(class_path)(device_name, base_addr, region_size, owned_irqs, emu_interface, comm, dev_config, enable_tracing=dma_tracing_enabled)
        configured_peripherals.append(device)

    # add memory listeners to ranges
    start_addrs, end_addrs = [], []
    for device in configured_peripherals:
        register_peripheral_for_snapshotting(device)

        # Take note of the irq assignments
        for irq in device.owned_irqs:
            assert(irq not in irq_to_periph_assignments)
            irq_to_periph_assignments[irq] = device

        # TODO: check overlaps between device MMIO ranges
        start_addr, size = device.address, device.size
        if size is not None and size > 0:
            # register device region(s) with native component
            start_addrs.append(start_addr)
            end_addrs.append(start_addr + size - 1)

    device_handle = native.register_py_handled_device_regions(start_addrs, end_addrs)
    for device_ind, (start, end) in enumerate(zip(start_addrs, end_addrs)):
        uc.hook_add(UC_HOOK_MEM_WRITE, handle_device_mem_write, device_ind, start, end)

    if irq_to_periph_assignments:
        pend_allowed_cb = handle_is_interrupt_pend_allowed
        interrupt_entry_cb = handle_interrupt_entry
        interrupt_exit_cb = handle_interrupt_exit
    else:
        # TODO: in case perf becomes an issue, add more fine-grained decision about whether devices want access to these hooks
        pend_allowed_cb = 0
        interrupt_entry_cb = 0
        interrupt_exit_cb = 0

    print(f"[DMA Device Setup] Got irq assignments for irqs: {sorted(irq_to_periph_assignments.keys())}, setting callback")
    native.set_interrupt_callbacks(pend_allowed_cb, interrupt_entry_cb, interrupt_exit_cb)

    peripherals = configured_peripherals
    if peripherals:
        subscribe_state_snapshotting(uc, take_snapshot_callback, restore_snapshot_callback, discard_snapshot_callback)

def handle_interrupt_entry(irqnum: int) -> None:
    dev = irq_to_periph_assignments.get(irqnum, None)

    if dev is not None:
        try:
            dev.on_interrupt_entry(irqnum)
        except OutOfFuzzingInputException as e:
            # Ran out of fuzz
            return True
        except Exception as e:
            # TODO: exit emulation run only
            print("[ERROR] got exception while handling handle_interrupt_entry: {e}")
            import traceback; traceback.print_exc()
            os._exit(1)

def handle_interrupt_exit(irqnum: int) -> None:
    dev = irq_to_periph_assignments.get(irqnum, None)

    if dev is not None:
        try:
            dev.on_interrupt_exit(irqnum)
        except OutOfFuzzingInputException as e:
            # Ran out of fuzz
            return True
        except Exception as e:
            # TODO: exit emulation run only
            print("[ERROR] got exception while handling handle_interrupt_exit: {e}")
            import traceback; traceback.print_exc()
            os._exit(1)

def handle_is_interrupt_pend_allowed(irqnum) -> bool:
    dev = irq_to_periph_assignments.get(irqnum, None)
    if dev is None:
        for per in peripherals:
            per.interrupt_pending_trigger(irqnum)
        return True

    try:
        return dev.can_pend_interrupt(irqnum)
    except OutOfFuzzingInputException as e:
        # Ran out of fuzz
        return True
    except Exception as e:
        # TODO: exit emulation run only
        print("[ERROR] got exception while handling handle_is_interrupt_pend_allowed: {e}")
        import traceback; traceback.print_exc()
        os._exit(1)

# MMIO device read forwarding is done via the native MMIO handler:
# 1. For each MMIO access, the native component will check whether it falls into a device region
# 2. If it does, we get here with an indication which device the region was registered for
# 3. We let the device handle the MMIO read
# 4. We indicate whether the device wants an underlying MMIO fallback (None value) to the native handler
def handle_device_mem_read(device_ind, addr, access_size):
    dev = peripherals[device_ind]
    # logger.debug(f"[{dev.name}] [{dev.emu.read_register('pc'):x}] read  {access_size} [{addr:x}]")

    # wire access through to the device
    try:
        res = dev.hw_read(addr-dev.address, access_size)
    except OutOfFuzzingInputException as e:
        # Ran out of fuzz
        res = None
    except Exception as e:
        # TODO: exit emulation run only
        print(f"[ERROR] got exception while handling dev.hw_read: {e}")
        import traceback; traceback.print_exc()
        os._exit(1)

    if type(res) == tuple:
        status, val = res
    else:
        val = res
        status = MMIO_HANDLE_RES_FORWARD_TO_DEFAULT if val is None else MMIO_HANDLE_RES_IS_HANDLED

    # indicate the result
    # 1. handled + write memory
    # 2. not handled, but passthrough (take value already in memory)
    # 3. not handled, forward to device
    if status == MMIO_HANDLE_RES_IS_HANDLED:
        dev.emu.write_memory(addr, access_size, val)
        # logger.debug(f"[READ] handled by device, resulted in value: {val:#x}")
        return MMIO_HANDLE_RES_IS_HANDLED
    elif status == MMIO_HANDLE_RES_PASSTHROUGH:
        val = dev.emu.read_memory(addr, access_size)
        # logger.debug(f"[READ] device wants a passthrough to ordinary memory, current val: {val:#x}")
        return MMIO_HANDLE_RES_IS_HANDLED
    else:
        # logger.debug("[READ] forwarding to MMIO models")
        return MMIO_HANDLE_RES_FORWARD_TO_DEFAULT

# MMIO device write forwarding is done via an ordinary mem access handler
# Accordingly, this is in plain unicorn memory hook format
def handle_device_mem_write(uc, access, address, size, value, user_data):
    # User data here is the device index
    device_ind = user_data

    dev = peripherals[device_ind]
    # logger.debug(f"[{dev.name}] [{dev.emu.read_register('pc'):x}] write {size} [{address:x}] = {value:#x}")

    try:
        dev.hw_write(address-dev.address, size, value)
    except OutOfFuzzingInputException as e:
        # Ran out of fuzz
        return True
    except Exception as e:
        # TODO: exit emulation run only
        logger.error(f"got exception while handling dev.hw_read: {e}")
        import traceback; traceback.print_exc()
        os._exit(1)

def register_peripheral_for_snapshotting(peripheral):
    peripherals.append(peripheral)

def has_py_peripherals_to_snapshot():
    return len(peripherals) != 0

def take_snapshot_callback(uc):
    # TODO: make uc the actual object, currently this seems to be the pointer address
    # print("[Py Peripheral Snapshotting] take_snapshot_callback")

    for periph in peripherals:
        periph.take_snapshot()

    return None

def restore_snapshot_callback(uc, snapshot):
    # TODO: make uc the actual object, currently this seems to be the pointer address
    # print("[Py Peripheral Snapshotting] restore_snapshot_callback")
    # print(snapshot)

    for periph in peripherals:
        periph.restore_snapshot()

def discard_snapshot_callback(uc, snapshot):
    # TODO: make uc the actual object, currently this seems to be the pointer address
    # print("[Py Peripheral Snapshotting] discard_snapshot_callback")
    # print(snapshot)

    for periph in peripherals:
        periph.discard_snapshot()
