""" Logic to subscribe to in-process snapshotting

Note: For the logic that creates state dumps to pass to MMIO modeling, see tracing.state_dump
"""

import traceback
import os, sys
import logging

logger = logging.getLogger("SNAP")
logger.setLevel(logging.WARNING)

snapshot_take_cbs = []
snapshot_restore_cbs = []
snapshot_discard_cbs = []
snapshots = []
snapshotting_triggered = False

def subscribe_state_snapshotting(uc, snapshot_take_cb, snapshot_restore_cb, snapshot_discard_cb):
    global snapshotting_triggered

    snapshot_take_cbs.append(snapshot_take_cb)
    snapshot_restore_cbs.append(snapshot_restore_cb)
    snapshot_discard_cbs.append(snapshot_discard_cb)

    if snapshotting_triggered:
        logger.warning("State snapshotting subscribed to after a first snapshot had already been triggered")
        snapshots.append(snapshot_take_cb(uc))

def trigger_snapshotting(uc):
    global snapshotting_triggered
    assert not snapshotting_triggered, "Can only trigger snapshotting once"

    logger.debug(f"State snapshot creation triggered (#snapshots: {len(snapshot_take_cbs)})")

    snapshots.clear()
    for cb in snapshot_take_cbs:
        try:
            snapshots.append(cb(uc))
        except Exception as e:
            print(f"[ERROR] Got exception while trying run a state snapshot create hook: {e}")
            print(traceback.format_exc())
            sys.stdout.flush()
            os._exit(1)

def trigger_restore(uc=None, snapshot=None):
    assert len(snapshots) == len(snapshot_restore_cbs)
    logger.debug(f"State snapshot restoration triggered (#snapshots: {len(snapshots)})")
    for i in range(len(snapshots)):
        try:
            snapshot_restore_cbs[i](uc, snapshots[i])
        except Exception as e:
            print(f"[ERROR] Got exception while trying run a state snapshot restore hook: {e}")
            print(traceback.format_exc())
            sys.stdout.flush()
            os._exit(1)

def trigger_teardown(uc, snapshot=None):
    assert len(snapshots) == len(snapshot_discard_cbs)
    assert uc is not None
    logger.debug(f"State snapshot teardown triggered (#snapshots: {len(snapshots)})")

    for i in range(len(snapshots)):
        try:
            snapshot_discard_cbs[i](uc, snapshots[i])
        except Exception as e:
            print(f"[ERROR] Got exception while trying run a state snapshot discard hook: {e}")
            print(traceback.format_exc())
            sys.stdout.flush()
            os._exit(1)

def is_snapshot_created():
    global snapshotting_triggered
    return snapshotting_triggered
