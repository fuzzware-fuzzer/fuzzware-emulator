import logging

from ..exit import do_exit
from ..snapshot import subscribe_state_snapshotting

logger = logging.getLogger("emulator")

# Static after initialization
event_id_limit = 0

# Requires snapshotting
event_id = -1

def next_event_id(uc):
    global event_id
    global event_id_limit
    event_id += 1
    if event_id_limit != 0 and event_id >= event_id_limit:
        logger.info("[*] Event id limit reached, exiting")
        do_exit(uc, 0)
    return event_id

def snapshot_take_trace_id(uc):
    global event_id

    return event_id

def snapshot_restore_trace_id(uc, snapshot):
    global event_id

    event_id = snapshot

def snapshot_discard_trace_id(uc, snapshot):
    pass

def init_trace_ids(uc, limit):
    global event_id_limit
    event_id_limit = limit

    subscribe_state_snapshotting(uc, snapshot_take_trace_id, snapshot_restore_trace_id, snapshot_discard_trace_id)
