import logging
from unicorn import UC_HOOK_MEM_READ_AFTER, UC_HOOK_MEM_WRITE, UC_MEM_WRITE
from unicorn.arm_const import (UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
                               UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
                               UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
                               UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9,
                               UC_ARM_REG_R10, UC_ARM_REG_R11, UC_ARM_REG_R12,
                               UC_ARM_REG_SP, UC_ARM_REG_XPSR)
import capnp
from ..exit import add_exit_hook
from ..user_hooks import add_block_hook
from .bintrace_capnp import TraceEvent
from .trace_mem import STACK_SIZE

logger = logging.getLogger("emulator")

trace_file = None

def trace_mem_access(uc, target, access, address, size, value):
    global trace_file
    access_type = access
    event = TraceEvent.new_message()
    access = event.init('access')
    access.target = target
    access.type = "write" if access_type == UC_MEM_WRITE else "read"
    access.size = size
    access.pc = uc.reg_read(UC_ARM_REG_PC)
    access.address = address
    access.value = value
    event.write(trace_file)

def mem_hook_ram_access(uc, access, address, size, value, user_data):
    trace_mem_access(uc, "ram", access, address, size, value)

def mem_hook_mmio_access(uc, access, address, size, value, user_data):
    trace_mem_access(uc, "mmio", access, address, size, value)

def mem_hook_stack_access(uc, access, address, size, value, user_data):
    trace_mem_access(uc, "stack", access, address, size, value)

def trace_basic_block(uc, address, size, user_data):
    global trace_file
    event = TraceEvent.new_message()
    basicBlock = event.init('basicBlock')
    basicBlock.pc = uc.reg_read(UC_ARM_REG_PC)
    basicBlock.lr = uc.reg_read(UC_ARM_REG_LR)
    event.write(trace_file)

def trace_registers(uc):
    global trace_file
    event = TraceEvent.new_message()
    dump = event.init('dump')
    dump.r0 = uc.reg_read(UC_ARM_REG_R0)
    dump.r1 = uc.reg_read(UC_ARM_REG_R1)
    dump.r2 = uc.reg_read(UC_ARM_REG_R2)
    dump.r3 = uc.reg_read(UC_ARM_REG_R3)
    dump.r4 = uc.reg_read(UC_ARM_REG_R4)
    dump.r5 = uc.reg_read(UC_ARM_REG_R5)
    dump.r6 = uc.reg_read(UC_ARM_REG_R6)
    dump.r7 = uc.reg_read(UC_ARM_REG_R7)
    dump.r8 = uc.reg_read(UC_ARM_REG_R8)
    dump.r9 = uc.reg_read(UC_ARM_REG_R9)
    dump.r10 = uc.reg_read(UC_ARM_REG_R10)
    dump.r11 = uc.reg_read(UC_ARM_REG_R11)
    dump.r12 = uc.reg_read(UC_ARM_REG_R12)
    dump.lr = uc.reg_read(UC_ARM_REG_LR)
    dump.pc = uc.reg_read(UC_ARM_REG_PC)
    dump.sp = uc.reg_read(UC_ARM_REG_SP)
    dump.xpsr = uc.reg_read(UC_ARM_REG_XPSR)
    event.write(trace_file)

def exit_hook(uc):
    global trace_file

    # dump registers on exit
    trace_registers(uc)

    # flush and close trace
    trace_file.flush()
    trace_file.close()
    trace_file = None


def init_tracing(trace_path, uc, config, mmio_ranges):
    global trace_file

    # load protocol, open file
    trace_file = open(trace_path, 'w+b')

    # add mmio memory hooks
    for start, end in mmio_ranges:
        logger.info("Tracing mmio accesses from 0x{:08x} to 0x{:08x}".format(start, end))
        uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ_AFTER, mem_hook_mmio_access, None, start, end)

    # add ram memory hook
    for region_name in config['memory_map']:
        if 'ram' in region_name.lower():
            start = config['memory_map']['ram']['base_addr']
            end = config['initial_sp'] - STACK_SIZE

            logger.info("Tracing ram accesses from 0x{:08x} to 0x{:08x}".format(start, end))
            uc.hook_add(UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ_AFTER, mem_hook_ram_access, None, start, end)

    # add basic block hook
    add_block_hook(trace_basic_block)

    # add exit hook
    add_exit_hook(exit_hook)
