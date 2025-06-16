import copy
import logging
from unicorn import UC_HOOK_MEM_READ_AFTER, UC_HOOK_MEM_WRITE, UC_MEM_WRITE
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_PC

from .. import native
from ..exit import add_exit_hook
from ..snapshot import subscribe_state_snapshotting

from .serialization import dump_mmio_trace_file, dump_ram_line
from ..native import next_trace_event_id

logger = logging.getLogger("emulator")

# Static after config
mmio_outfile = None
ram_outfile = None

# Requires snapshotting
mmio_events = []
ram_events = []

def mem_hook_trace_mmio_access(uc, access, address, size, value, user_data):
    mmio_events.append((next_trace_event_id(uc), uc.reg_read(UC_ARM_REG_PC), uc.reg_read(UC_ARM_REG_LR), "w" if access == UC_MEM_WRITE else "r", size, 0 if access == UC_MEM_WRITE else native.get_latest_mmio_fuzz_access_index(), 0 if access == UC_MEM_WRITE else native.get_latest_mmio_fuzz_access_size(), address, value))

def mem_hook_trace_ram_access(uc, access, address, size, value, user_data):
    ram_events.append((next_trace_event_id(uc), uc.reg_read(UC_ARM_REG_PC), uc.reg_read(UC_ARM_REG_LR), "w" if access == UC_MEM_WRITE else "r", size, address, value))

def exit_hook_dump_mmio_access_events(uc):
    dump_mmio_trace_file(mmio_events, mmio_outfile)

def exit_hook_dump_ram_access_events(uc):
    global ram_trace_already_dumped
    if ram_trace_already_dumped:
        logger.error("Cannot generate BB trace from python multiple times (are we running under fork server?).")
        exit(1)
    ram_trace_already_dumped = True
    _dump_ram_access_events(uc, ram_outfile, ram_events)

def _dump_ram_access_events(uc, outfile, events):
    last_mode, last_size, last_address, last_pc, last_lr = None, None, None, None, None
    base_event_id = None
    values = []
    pl = ""
    for event_id, pc, lr, mode, size, address, value in events:
        if last_mode is None:
            # Very first entry
            values.append(value)
            base_event_id = event_id
        else:
            if not(address == last_address and mode == last_mode and size == last_size and pc == last_pc and lr == last_lr):
                # We got a new line, dump it
                line = dump_ram_line(base_event_id, last_pc, last_lr, last_mode, last_size, last_address, values)
                pl += line + "\n"
                values.clear()
                base_event_id = event_id
            values.append(value)

        last_mode = mode
        last_size = size
        last_address = address
        last_pc = pc
        last_lr = lr

    if values:
        pl += dump_ram_line(base_event_id, last_pc, last_lr, last_mode, last_size, last_address, values) + "\n"

    with open(outfile, "w") as f:
        f.write(pl)

def snapshot_take_mmiotrace(uc):
    global mmio_events

    return copy.deepcopy(mmio_events)

def snapshot_restore_mmiotrace(uc, snapshot):
    global mmio_events

    mmio_events = copy.deepcopy(snapshot)

def snapshot_discard_mmiotrace(uc, snapshot):
    pass

def snapshot_take_ramtrace(uc):
    global ram_events

    return copy.deepcopy(ram_events)

def snapshot_restore_ramtrace(uc, snapshot):
    global ram_events

    ram_events = copy.deepcopy(snapshot)

def snapshot_discard_ramtrace(uc, snapshot):
    pass

def register_mmio_access_handler(uc, start, end):
    global mmio_outfile

    if mmio_outfile is not None:
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ_AFTER, mem_hook_trace_mmio_access, None, start, end)

def register_ram_access_handler(uc, start, end):
    global ram_outfile

    if ram_outfile is not None:
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ_AFTER, mem_hook_trace_ram_access, None, start, end)

def init_mmio_tracing(uc, trace_file, ranges):
    global mmio_outfile

    if trace_file is not None:
        mmio_outfile = trace_file
        add_exit_hook(exit_hook_dump_mmio_access_events)
        subscribe_state_snapshotting(uc, snapshot_take_mmiotrace, snapshot_restore_mmiotrace, snapshot_discard_mmiotrace)

        for start, end in ranges:
            logger.info("Tracing mmio accesses from 0x{:08x} to 0x{:08x}".format(start, end))
            register_mmio_access_handler(uc, start, end)

STACK_SIZE=0
def init_ram_tracing(uc, trace_file, config):
    global ram_outfile

    if trace_file is not None:
        ram_outfile = trace_file

        # trace everything but mmio
        for region_name in config['memory_map']:
            if 'mmio' in region_name.lower():
                continue

            start = config['memory_map'][region_name]['base_addr']
            end = start + config['memory_map'][region_name]['size']

            logger.info("Tracing ram accesses from 0x{:08x} to 0x{:08x}".format(start, end))
            register_ram_access_handler(uc, start, end)
        add_exit_hook(exit_hook_dump_ram_access_events)
        subscribe_state_snapshotting(uc, snapshot_take_ramtrace, snapshot_restore_ramtrace, snapshot_discard_ramtrace)
