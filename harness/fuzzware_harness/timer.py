import importlib
import logging
import os
import sys
import traceback

from unicorn.arm_const import UC_ARM_REG_PC

from . import globs, native
from .exit import do_exit
from .user_hooks import add_func_hook, remove_bb_hook
from .snapshot import is_snapshot_created

logger = logging.getLogger("emulator")

DEFAULT_TIMER_RELOAD_VAL = 0x1000

callback_by_native_index = {}
native_index_by_timer_id = {}
# map {start_at_1: [timer_id_1, timer_id_2], start_at_2: [timer_id_x]}
delayed_timers = {}
cur_timer_id = 1

def timer_start_block_hook(uc):
    assert not is_snapshot_created(), "Invalid delayed timer configuration: Activation basic block needs to be hit before snapshot is taken (i.e., before first fuzzing input is consumed)"

    address = uc.reg_read(UC_ARM_REG_PC)
    if address in delayed_timers:
        # Remove the timer along the way
        for timer_id in delayed_timers.pop(address):
            logger.info("Starting delayed timer '{}' at {:08x}".format(timer_id, address))
            resume_timer(timer_id)

        # We only ever want to start the timer once
        remove_bb_hook(uc, address, timer_start_block_hook)

def central_timer_hook(uc, internal_timer_id, userdata):
    try:
        callback_by_native_index[internal_timer_id](uc)
    except Exception as e:
        print(f"[ERROR] Got exception while trying to run a block hook: {e}")
        print(traceback.format_exc())
        sys.stdout.flush()
        os._exit(1)

def ticks():
    return native.get_global_ticker()

def add_timer(timer_rate, timer_func_irq, start=False):
    """
    Add a timer.

    :param timer_rate:  The timer's 'rate', in ticks. After this many ticks, the event will occur.
    :param timer_func_irq: What to do when the timer elapses.  If this is an int, inject that interrupt.  If it
    is a function object, just call that instead.
    :param start: Whether to immediately start the timer
    :return: The id of the allocated timer.
    """

    timer_id = generate_timer_id()
    if isinstance(timer_func_irq, int):
        native_ind = native.add_timer(timer_rate, isr_num=timer_func_irq)
    else:
        native_ind = native.add_timer(timer_rate, callback=timer_func_irq)

    callback_by_native_index[native_ind] = timer_func_irq
    native_index_by_timer_id[timer_id] = native_ind

    if start:
        start_timer(timer_id)

    return timer_id

def start_timer(timer_id):
    """
    Start a timer.

    :param timer_id: The 'id' of the timer.  This is either its name, or a base address.
    Generally anything we need to identify that timer again later.
    :return:
    """
    native_ind = native_index_by_timer_id[timer_id]

    native.start_timer(globs.uc, native_ind)

    logger.info(f"Starting timer {timer_id} (internal id: {native_ind})")

def configure_timers(uc, config):
    if 'use_timers' in config and config['use_timers'] is True:
        # Parse config for timer function handlers
        if 'timers' in config:
            for timer_id, timer_config in config['timers'].items():
                if 'reload_val' in timer_config:
                    reload_val = timer_config['reload_val']
                else:
                    reload_val = DEFAULT_TIMER_RELOAD_VAL
                    logger.warning(f"did not find 'reload_val' for timer '{timer_id}', assigning default of {reload_val}")

                if 'handler' in timer_config:
                    # Register handler function
                    func = timer_config['handler']

                    try:
                        # Resolve the function name
                        mod_name, func_name = func.rsplit('.', 1)
                        mod = importlib.import_module(mod_name)
                        func_obj = getattr(mod, func_name)
                    except:
                        import traceback
                        logger.info(f"Unable to hook function {func} for timer {timer_id}")
                        traceback.print_exc()
                        do_exit(uc, 1)
                    timer_func_irq = func_obj
                elif 'irq' in timer_config:
                    # Register with an irq number
                    timer_func_irq = timer_config['irq']
                else:
                    logger.error("[Timer Config ERROR] For a timer configuration, either 'irq' or 'handler' is required")
                    sys.exit(-1)

                add_timer(timer_id, reload_val, timer_func_irq, start=True)

                # See if there is a particular address in the firmware execution to start the timer at
                if 'start_at' in timer_config:
                    logger.warning("The 'start_at' timer configuration is valid only if the activation occurs before the snapshot")
                    stop_timer(timer_id)
                    addr = timer_config['start_at'] & 0xfffffffe
                    if not delayed_timers:
                        add_func_hook(uc, addr, timer_start_block_hook, do_return=False)
                    if addr not in delayed_timers:
                        delayed_timers[addr] = []
                    delayed_timers[addr].append(timer_id)

def timer_exists(timer_id):
    return timer_id in native_index_by_timer_id

def generate_timer_id():
    global cur_timer_id
    new_id = cur_timer_id
    cur_timer_id += 1
    assert new_id < 1<<32, "Timer id overflow"
    return new_id

def remove_timer(timer_id):
    if timer_id not in native_index_by_timer_id:
        logger.warning(f"UH OH: We do not have an active timer {timer_id}")
        return
    native.rem_timer(globs.uc, timer_id)

def stop_timer(timer_id):
    logger.info(f"Stopping timer {timer_id}")

    if timer_id not in native_index_by_timer_id:
        logger.warning(f"UH OH: We never started timer {timer_id}")
        return
    native.stop_timer(globs.uc, native_index_by_timer_id[timer_id])

def is_running(timer_id):
    if timer_id not in native_index_by_timer_id:
        logger.warning(f"UH OH: We never created timer {timer_id}")
        return False
    return native.is_running(native_index_by_timer_id[timer_id])

def resume_timer(timer_id):
    logger.debug(f"Resuming timer {timer_id}")
    if timer_id not in native_index_by_timer_id:
        logger.warning(f"UH OH: We never started timer {timer_id}")
        return
    native.start_timer(globs.uc, native_index_by_timer_id[timer_id])

def reset_timer(timer_id):
    if timer_id not in native_index_by_timer_id:
        logger.warning(f"UH OH: We never started timer {timer_id}")
        return
    native.reload_timer(native_index_by_timer_id[timer_id])

def set_timer_reload_val(timer_id, reload_val):
    if timer_id not in native_index_by_timer_id:
        logger.warning(f"UH OH: We never created timer {timer_id}")
        return
    native.set_timer_reload_val(timer_id, reload_val)
