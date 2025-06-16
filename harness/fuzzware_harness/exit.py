import sys
import logging


logger = logging.getLogger("emulator")

exit_hooks = []
exit_hooks_disabled = False

def add_exit_hook(fn):
    global exit_hooks_disabled
    assert not exit_hooks_disabled, "Initialization ran in the wrong order (native init has already been called with no exit hooks)"

    exit_hooks.append(fn)

def has_exit_hooks():
    global exit_hooks
    global exit_hooks_disabled

    has_hooks = len(exit_hooks) != 0
    if not has_hooks:
        exit_hooks_disabled = True

    return has_hooks

def invoke_exit_callbacks(status, kill_signal=-1):
    """
    Common exit hook. Be aware that this function is called from within the
    native hooks so any change in prototype has to be reflected
    1. In the native code itself
    2. In the construction of the C-callable function object
    """
    global exit_hooks

    from .globs import uc

    for fn in exit_hooks:
        logger.debug(f"Calling exit hook {exit_hooks}")
        try:
            fn(uc)
        except:
            import traceback
            traceback.print_exc()
            sys.exit(1)

def do_exit(uc, status, kill_signal=-1):
    from .native import do_exit as native_do_exit

    # Relay to native code to make sure any native exit hooks are invoked
    native_do_exit(uc, status, kill_signal)
