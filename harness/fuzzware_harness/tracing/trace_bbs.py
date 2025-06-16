import copy
import logging
import os

from ..exit import add_exit_hook
from ..user_hooks import add_uncond_block_hook
from .serialization import dump_bbl_trace_file
from ..snapshot import subscribe_state_snapshotting

from ..native import next_trace_event_id

logger = logging.getLogger("emulator")

# Static after initialization
outfile = None

# Requires snapshotting
bb_addrs = []
curr_cycle_len = 0
curr_cycle_offset = 0
MAX_CYCLE_LEN = 4

# Snapshot
snapshot_bb_addr_set = None
snapshot_curr_cycle_len = 0
snapshot_curr_cycle_offset = 0

def collect_bb_event(uc, address, size=None, user_data=None):
    global curr_cycle_len
    global curr_cycle_offset
    found = False

    if curr_cycle_len != 0 and bb_addrs[-curr_cycle_len + curr_cycle_offset][1] == address:
        bb_addrs[-curr_cycle_len + curr_cycle_offset][2] += 1
        curr_cycle_offset = (curr_cycle_offset + 1) % curr_cycle_len
    else:
        curr_cycle_len = 0

        if bb_addrs:
            if bb_addrs and bb_addrs[-1][1]==address:
                bb_addrs[-1][2] += 1
                return

        if len(bb_addrs) >= 2*MAX_CYCLE_LEN:
            for prefix_len in range(MAX_CYCLE_LEN, 1, -1):
                if found:
                    break
                # Start of cycle fits
                if address == bb_addrs[-prefix_len][1] == bb_addrs[-2*prefix_len][1]:
                    found = True
                    for i in range(1, prefix_len):
                        if bb_addrs[-prefix_len + i][1] != bb_addrs[-2 * prefix_len + i][1]:
                            found = False
                            break

                    # We found a cycle. Tick up the counters and set the current cycle metadata
                    if found:
                        curr_cycle_len = prefix_len
                        curr_cycle_offset = 1
                        bb_addrs[-prefix_len][2] += 1
                        return

        bb_addrs.append([next_trace_event_id(uc), address, 0])

def collect_bb_event_no_cyclic_compression(uc, address, size, user_data):
    if bb_addrs and bb_addrs[-1][1]==address:
        bb_addrs[-1][2] += 1
    else:
        bb_addrs.append([next_trace_event_id(uc), address, 0])

def exit_hook_dump_bb_trace(uc):
    dump_current_bb_trace(uc)

def dump_current_bb_trace(uc, custom_outfile_path=None, num_latest_entries=0):
    global outfile

    if custom_outfile_path is None:
        used_outfile_path = outfile
    else:
        used_outfile_path = custom_outfile_path

    if num_latest_entries == 0 or len(bb_addrs) >= num_latest_entries:
        dump_bbl_trace_file(bb_addrs, used_outfile_path)
    else:
        dump_bbl_trace_file(bb_addrs[-num_latest_entries:], used_outfile_path)

    logger.info(f"Dumped bb trace to {used_outfile_path}")

def snapshot_take_bbtrace(uc):
    global bb_addrs, snapshot_bb_addrs
    global curr_cycle_len, snapshot_curr_cycle_len
    global curr_cycle_offset, snapshot_curr_cycle_offset

    snapshot_bb_addrs = copy.deepcopy(bb_addrs)
    snapshot_curr_cycle_len = curr_cycle_len
    snapshot_curr_cycle_offset = curr_cycle_offset

    return None

def snapshot_restore_bbtrace(uc, snapshot):
    global bb_addrs, snapshot_bb_addrs
    global curr_cycle_len, snapshot_curr_cycle_len
    global curr_cycle_offset, snapshot_curr_cycle_offset

    bb_addrs = copy.deepcopy(snapshot_bb_addrs)
    curr_cycle_len = snapshot_curr_cycle_len
    curr_cycle_offset = snapshot_curr_cycle_offset

def snapshot_discard_bbtrace(uc, snapshot):
    pass

def init_bb_tracing(uc, trace_file):
    global outfile, outfile_bb_set

    if trace_file is not None:
        add_uncond_block_hook(uc, collect_bb_event)
        outfile = trace_file
        add_exit_hook(exit_hook_dump_bb_trace)
        subscribe_state_snapshotting(uc, snapshot_take_bbtrace, snapshot_restore_bbtrace, snapshot_discard_bbtrace)
