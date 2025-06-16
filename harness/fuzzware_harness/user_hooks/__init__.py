import binascii
import importlib
import re
import struct
import sys
import logging

from unicorn import UC_HOOK_BLOCK_UNCONDITIONAL

from ..exit import do_exit
from ..snapshot import is_snapshot_created

logger = logging.getLogger("emulator")

bb_hooks_by_addr = {}

def can_modify_block_hooks():
    # Post snapshotting, emulation results become inconsistent
    return not is_snapshot_created()

def add_bb_hook(uc, addr, func):
    global bb_hooks_by_addr
    assert addr & 1 == 0, "Basic block address thumb bit should not be set"
    assert can_modify_block_hooks(), "Can only add basic block hooks before snapshotting"

    bb_hooks_by_addr.setdefault(addr, []).append(func)

    from ..native import add_py_hooked_block_addr
    add_py_hooked_block_addr(uc, addr)

    return addr, func

def remove_bb_hook(uc, address, func):
    assert func in bb_hooks_by_addr.get(address, ())
    assert can_modify_block_hooks(), "Basic Block hook cannot be deleted after snapshotting"

    bb_hooks_by_addr[address].remove(func)
    # is the address fully gone?
    if not bb_hooks_by_addr[address]:
        del bb_hooks_by_addr[address]
        from .. import native
        native.remove_py_hooked_block_addr(uc, address)

""" ASM
ldr r0, =0x90909090
bx lr
NOP
"""
LDR_R0_LITERAL_POOL_RET = b"\x00\x48\x70\x47"
THUMB_NOP = b"\xC0\x46"

# bx lr
THUMB_RET = b'\x70\x47'

native_ret_regex        = r"retu?r?n?_0?x?([0-9a-fA-F]+)"
native_inline_asm_regex = r"inline_asm_([0-9a-fA-f]+)"
def patch_native_handler(uc, addr, magic_funcname):
    logger.info(f"Native patch handler looking at {magic_funcname}")

    # native.return_0xdeadbeef
    if re.match(native_ret_regex, magic_funcname):
        val = int(re.match(native_ret_regex, magic_funcname).group(1), 16)
        if val > 1<<32:
            logger.error(f"[Native handler] too large value {val:x}")
            sys.exit(1)
        patch = LDR_R0_LITERAL_POOL_RET + struct.pack("<I", val)
        # For unaligned addresses, align the instruction first for a correct pc-relative load
        if addr & 2 == 2:
            patch = THUMB_NOP + patch
    elif re.match(native_inline_asm_regex, magic_funcname):
        inline_patch_hex = re.match(native_inline_asm_regex, magic_funcname).group(1)
        try:
            patch = binascii.unhexlify(inline_patch_hex)
        except binascii.Error:
            logger.error(f"[Native handler] invalid hex: {inline_patch_hex}")
            sys.exit(1)
    else:
        logger.error(f"[Native handler] Unknown native function: {magic_funcname}")
        sys.exit(1)

    uc.mem_write(addr, patch)

def add_func_hook(uc, addr, func, do_return=True):
    """
    Add a function hook.

    If func is None (and do_return is True) this is effectively a nop-out without using a real hook!
    Makes it faster to not have to call into python for hooks we don't need.
    """

    assert can_modify_block_hooks(), "Can only add function hooks before snapshotting"

    real_addr = addr & 0xFFFFFFFE  # Drop the thumb bit
    func_obj = None
    if func:
        if isinstance(func, str):
            try:
                # Resolve the function name
                mod_name, func_name = func.rsplit('.', 1)
                if mod_name == "native":
                    patch_native_handler(uc, addr, func_name)
                    return None, None

                mod = importlib.import_module(mod_name)
                func_obj = getattr(mod, func_name)
            except (ModuleNotFoundError, AttributeError):
                import traceback
                logger.error("Unable to hook function %s at address %#08x" % (repr(func), addr))
                traceback.print_exc()
                do_exit(uc, 1)
                sys.exit(1)
        else:
            func_obj = func

        real_addr, func_obj = add_bb_hook(uc, real_addr, func_obj)

    if do_return:
        uc.mem_write(real_addr, THUMB_RET)

    return real_addr, func_obj

def func_hook_handler(uc, addr, size, user_data):
    for hook in bb_hooks_by_addr[addr]:
        if logger.level <= logging.DEBUG:
            logger.debug(f"Calling hook {hook.__name__} at {addr:#08x}")
        try:
            hook(uc)
        except:
            import traceback
            traceback.print_exc()
            do_exit(uc, 1)

def add_uncond_block_hook(uc, hook):
    assert can_modify_block_hooks(), "Can only add unconditional block hooks before snapshotting"

    def hook_wrap(uc, address, size=0, user_data=None):
        try:
            hook(uc, address, size, user_data)
        except:
            import traceback
            traceback.print_exc()
            do_exit(uc, 1)

    uc.hook_add(UC_HOOK_BLOCK_UNCONDITIONAL, hook_wrap)
