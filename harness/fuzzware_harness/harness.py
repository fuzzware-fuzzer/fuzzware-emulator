import argparse
import gc
import os
import sys
import logging

from unicorn import (UC_ARCH_ARM, UC_MODE_MCLASS, UC_MODE_THUMB, Uc, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC)
from unicorn.arm_const import UC_ARM_REG_PC, UC_ARM_REG_SP

from . import globs, interrupt_triggers, native, timer, user_hooks
from .gdbserver import GDBServer
from .mmio_models import parse_mmio_model_config
from .sparkle import add_sparkles
from .tracing import state_dump, trace_bbs, trace_mem
from .user_hooks import add_uncond_block_hook, add_func_hook
from .util import (bytes2int, load_config_deep, parse_address_value,
                   parse_symbols, resolve_region_file_paths, closest_symbol,
                   resolve_region_base_addrs)

from .peripherals import parse_peripheral_configs


logging.basicConfig(stream=sys.stdout, level=logging.WARNING)
logger = logging.getLogger("emulator")

def unicorn_trace_syms(uc, pc, size=0, user_data=None):
    if pc in uc.syms_by_addr:
        print(f"Calling function: {uc.syms_by_addr[pc][0]}", flush=False, end="")
        lr = uc.regs.lr
        lr_sym = closest_symbol(uc.syms_by_addr, lr)[0]
        if lr_sym:
            print(f" from {lr_sym}", flush=False, end="")
        print(f" (PC: {pc:#x}, LR: {lr:#x})", flush=True)
        sys.stdout.flush()

def configure_unicorn(args):
    logger.info(f"Loading configuration in {str(args.config)}")
    config = load_config_deep(args.config)

    native_lib_path = os.path.dirname(os.path.realpath(__file__))+'/native/native_hooks.so'
    if not os.path.exists(native_lib_path):
        logger.error(f"Native library {str(native_lib_path)} does not exist! Exiting...")
        sys.exit(1)
    else:
        native.load_native_lib(native_lib_path)

    limits = config.get("limits")
    if limits:
        if 'translation_blocks' in limits:
            args.basic_block_limit = limits['translation_blocks']
        if 'interrupts' in limits:
            args.interrupt_limit = limits['interrupts']
        if 'fuzz_consumption_timeout' in limits:
            args.fuzz_consumption_timeout = limits['fuzz_consumption_timeout']

    # Step 2: Set up the memory map
    if 'memory_map' not in config:
        logger.error("Memory Configuration must be in config file")
        sys.exit(1)

    # Create the unicorn
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_MCLASS)
    globs.uc = uc
    uc.symbols, uc.syms_by_addr = parse_symbols(config)
    uc = add_sparkles(uc, args)
    # Register python basic block callback wrapper. Hooks are added individually via native.add_py_hooked_block_addr
    native.register_cond_py_handler_hook(uc)

    regions = {}
    vtor = globs.NVIC_VTOR_NONE
    resolve_region_file_paths(args.config, config)
    resolve_region_base_addrs(config, uc.symbols)

    # Entry region recovery
    file_backed_regions = {rname: region for rname, region in config['memory_map'].items() if 'file' in region}
    num_entry_regions = [region.get('is_entry', False) is True for region in file_backed_regions.values()].count(True)
    if num_entry_regions > 1:
        logger.error("cannot have multiple 'is_entry' memory regions")
        sys.exit(1)
    elif num_entry_regions == 0:
        has_single_file = len(set([c['file'] for c in file_backed_regions.values() if 'file' in c])) == 1
        if not has_single_file:
            logger.error("Multiple file-backed regions found, but no explit is_entry set")
            sys.exit(1)
        # Single file found, take the region with the lowest base
        entry_region = min(file_backed_regions.values(), key=lambda region: region['base_addr'])
        entry_region['is_entry'] = True

    # Load and register region contents
    for rname, region in sorted(config['memory_map'].items(), key=lambda r: 1 if r[1].get('overlay', False) else 0):
        prot = 0
        if 'permissions' not in region:
            logger.warning(f"defaulting to RWX permissions for region {rname}")
            prot = 7 # UC_PROT_ALL
        else:
            if 'r' in region['permissions'].lower():
                prot |= UC_PROT_READ
            if 'w' in region['permissions'].lower():
                prot |= UC_PROT_WRITE
            if 'x' in region['permissions'].lower():
                prot |= UC_PROT_EXEC

        # Derive memory region size from backing file
        if 'size' not in region and 'file' in region:
            region['size'] = os.stat(region['file']).st_size

        for attr_name in ('base_addr', 'size'):
            if attr_name not in region:
                logger.error(f"'{attr_name}' missing for region '{rname}'. Please complete the memory region definition.")
                sys.exit(1)

        start, size = region['base_addr'], region['size']
        logger.debug(f"Mapping region {str(rname)} at {hex(size)}, perms: {int(prot)}")

        if not region.get('overlay', False):
            if size & (globs.PAGE_SIZE-1) != 0:
                logger.warning(f"Size 0x{size:x} of region '{rname}' not page aligned. Aligning to next page boundary size.")
                size -= size & (globs.PAGE_SIZE-1)
                size += globs.PAGE_SIZE

            if start & (globs.PAGE_SIZE-1) != 0:
                logger.warning(f"Start of region '{rname}' is not page aligned. Aligning to previous page boundary.")
                unalignment = start & (globs.PAGE_SIZE-1)
                start -= unalignment
                # Make sure file contents and vector table still end up where they were supposed to
                region['load_offset'] = (region.get('load_offset') or 0) + unalignment
                region['ivt_offset'] = (region.get('ivt_offset') or 0) + unalignment

            # Check for memory region overlaps
            own_end = start + size
            for region_name, (other_start, other_size, _) in regions.items():
                other_end = other_start + other_size
                if (
                    start <= other_start < own_end or
                    start < other_end <= own_end or
                    other_start <= start < other_end or
                    other_start < own_end <= other_end
                ):
                    logger.error(f"Region '{rname}' (0x{start:x}-0x{own_end:x}) overlaps with region '{region_name}' (0x{other_start:x}-0x{other_end:x})")
                    sys.exit(1)

            uc.mem_map(start, size, prot)

        regions[rname] = (start, size, prot)
        f = region.get('file')
        if f:
            file_offset = region.get('file_offset') or 0
            load_offset = region.get('load_offset') or 0
            file_size = size - load_offset
            if 'file_size' in region:
                file_size = region['file_size']

            logger.info(f"Using file {str(f)}, offset {file_offset:08x}, load_offset: {load_offset:08x}, file_size: {file_size:08x}")

            with open(f, 'rb') as fp:
                fp.seek(file_offset)
                region_data = fp.read(file_size)
                logger.info(f"Loading {len(region_data):08x} bytes at {start + load_offset:08x}")
                uc.mem_write(start + load_offset, region_data)

            if region.get('is_entry') == True:
                vtor = start + (region.get('ivt_offset') or 0)
                logger.debug(f"setting vtor: {vtor:#x}")

    globs.regions = regions

    if not ('entry_point' in config and 'initial_sp' in config):
        # If we don't have explicit configs, try recovering from IVT
        if vtor is globs.NVIC_VTOR_NONE:
            logger.error("Binary entry point missing! Make sure 'entry_point is in your configuration")
            sys.exit(1)
        config['initial_sp'] = bytes2int(uc.mem_read(vtor, 4))
        config['entry_point'] = bytes2int(uc.mem_read(vtor + 4, 4))

        logger.debug(f"Recovered entry points: {config['entry_point']:08x}, initial_sp: {config['initial_sp']:08x}")

    # Set the program entry point and stack pointer
    uc.reg_write(UC_ARM_REG_PC, config['entry_point'])
    # The stack pointer is aligned during CPU reset
    uc.reg_write(UC_ARM_REG_SP, config['initial_sp'] & 0xfffffffc)

    mmio_ranges = [(start, start + size) for rname, (start, size, prot) in regions.items() if rname.lower().startswith('mmio')]
    if not mmio_ranges:
        logger.error("No mmio region(s) configured. Did you forget to add a 'mmio*' memory_map entry?")
        sys.exit(1)
    ram_ranges = [(start, start + size) for rname, (start, size, prot) in regions.items() if not rname.lower().startswith('mmio')]

    # Stuff which needs to be executed on exit. We need to register those before initializing the native module
    if args.dump_state_filename is not None:
        state_dump.init_state_dumping(uc, args.dump_state_filename, args.dump_mmio_states, mmio_ranges, args.dumped_mmio_contexts, args.dumped_mmio_name_prefix)
        if args.dump_mmio_states:
            if args.bb_trace_file is None:
                args.bb_trace_file = "/dev/null"

    need_trace_ids = False
    if args.force_slow_tracing:
        logger.warning("Using legacy python traces instead of faster, native ones")
        if args.mmio_trace_file is not None:
            trace_mem.init_mmio_tracing(uc, args.mmio_trace_file, mmio_ranges)
            args.mmio_trace_file = None
            need_trace_ids = True

        if args.ram_trace_file is not None:
            trace_mem.init_ram_tracing(uc, args.ram_trace_file, config)
            args.ram_trace_file = None
            need_trace_ids = True

        if args.bb_trace_file is not None:
            trace_bbs.init_bb_tracing(uc, args.bb_trace_file)
            args.bb_trace_file = None
            need_trace_ids = True

    if args.exit_at_bbl != globs.EXIT_AT_NONE:
        exit_at_bbls = [parse_address_value(uc.symbols, args.exit_at_bbl)]
    elif config.get('exit_at') and (config.get('use_exit_at') is not False):
        exit_at_bbls = []
        # Allow just specifying a symbol without value in yaml file and skip any unresolved symbols
        for name, entry in config['exit_at'].items():
            # Do we have an explicit address / symbol? Then use that
            if entry is not None:
                name = entry
            addr = parse_address_value(uc.symbols, name, enforce=False)
            if addr is None:
                logger.warning(f"Could not find exit-at symbol or address value: '{str(name)}', skipping")
            else:
                exit_at_bbls.append(addr)
    else:
        exit_at_bbls = []

    # Timer Setup
    global_timer_scale = config['global_timer_scale'] if 'global_timer_scale' in config else 1
    native.init_timer_hook(uc, global_timer_scale)
    timer.configure_timers(uc, config)

    dma_tracing_enabled = args.dma_trace_file is not None
    if dma_tracing_enabled:
        from .tracing.trace_dma import init_dma_tracing
        init_dma_tracing(args.dma_trace_file)
        need_trace_ids = True

    rw_ram_ranges = [(start, start + size) for rname, (start, size, prot) in regions.items() if not rname.lower().startswith('mmio') and (prot & UC_PROT_READ != 0) and (prot & UC_PROT_WRITE != 0) ]
    parse_peripheral_configs(uc, config, mmio_ranges, rw_ram_ranges, dma_tracing_enabled)

    # Step 3: Set the handlers
    if 'handlers' in config and config['handlers']:
        for fname, handler_desc in config['handlers'].items():
            if handler_desc is None:
                handler_desc = {}
            elif isinstance(handler_desc, str):
                handler_desc = {'handler': handler_desc}
            if 'addr' in handler_desc:
                addr_val = handler_desc['addr']
                # This handler is always at a fixed address
                if isinstance(addr_val, int):
                    addr_val &= 0xFFFFFFFE # Clear thumb bit
                    uc.syms_by_addr[addr_val] = fname
            else:
                addr_val = fname
            # look in the symbol table, if required
            addr = parse_address_value(uc.symbols, addr_val, enforce=False)

            if addr is None:
                if not uc.symbols:
                    logger.error("Need symbol table in order to hook named functions!")
                    sys.exit(1)
                if fname not in uc.symbols:
                    # We can't hook this
                    logger.info(f"No symbol found for {str(fname)}")
                    continue

            handler_desc.setdefault('do_return', True)
            handler_desc.setdefault('handler', None)

            # Actually hook the thing
            logger.info(f"Handling function {str(fname)} at {addr:#10x} with {str(handler_desc['handler'])}")
            add_func_hook(uc, addr, handler_desc['handler'], do_return=handler_desc['do_return'])

    # Native mmio fuzzing
    native.init(uc, mmio_ranges, exit_at_bbls, args.exit_at_hit_num, args.print_exit_info, args.print_fork_child_output, args.fuzz_consumption_timeout, args.basic_block_limit)

    # Timer Setup
    global_timer_scale = config['global_timer_scale'] if 'global_timer_scale' in config else 1
    native.init_timer_hook(uc, global_timer_scale)
    timer.configure_timers(uc, config)

    # MMIO modeling and listener setup
    parse_mmio_model_config(uc, config)
  
    # We enable systick by default
    use_systick = ('use_systick' not in config or ('use_systick' in config and config['use_systick'] is True))
    use_nvic = use_systick or ('use_nvic' in config and config['use_nvic'] is True)
    # Implementation detail: Interrupt triggers need to be configured before the nvic (to enable multiple interrupt enabling)
    if use_nvic and 'interrupt_triggers' in config and config['interrupt_triggers']:
        interrupt_triggers.init_triggers(uc, config['interrupt_triggers'])

    if use_systick:
        systick_cfg = config.get('systick', {})
        systick_reload_val = systick_cfg.get('reload_val', globs.SYSTICK_RELOAD_VAL_NONE)
        native.init_systick(uc, systick_reload_val)

    if args.debug and args.trace_funcs:
        add_uncond_block_hook(uc, unicorn_trace_syms)

    mock_hardfp = config.get('mock_hardfp', False)
    # Configure nvic. We need to be a bit verbose here as we need to auto-enable the nvic for isr fuzzing
    if use_nvic:
        nvic_cfg = config.get('nvic', {})
        num_vecs = nvic_cfg.get('num_vecs', globs.DEFAULT_NUM_NVIC_VECS)
        num_prio_bits = nvic_cfg.get('num_prio_bits', globs.DEFAULT_NUM_NVIC_PRIO_BITS)
        disabled_interrupts = nvic_cfg.get('disabled_irqs', ())
        native.init_nvic(uc, vtor, num_vecs, num_prio_bits, args.interrupt_limit, disabled_interrupts, mock_hardfp)
    elif mock_hardfp:
        logger.error("Configuration is invalid. Enabling mock_hardfp requires use_nvic (or use_systick).")
        sys.exit(1)

    if args.debug and args.trace_memory:
        native.register_native_debug_hooks(uc)

    # Add unconditional trace hooks late so that python and native tracing sees them at the same time
    if any((need_trace_ids, args.bb_set_file, args.mmio_set_file, args.bb_hash_file, args.bb_trace_file, args.ram_trace_file, args.mmio_trace_file, args.interrupt_trace_file)):
       native.init_native_tracing(uc, need_trace_ids, args.bb_set_file, args.bb_hash_file, args.mmio_set_file, args.bb_trace_file, args.ram_trace_file, args.mmio_trace_file, args.interrupt_trace_file, mmio_ranges, ram_ranges)

    if args.gdb_port != 0:
        from . import gdbserver
        uc.gdb = GDBServer(uc, args.gdb_port)
    else:
        uc.gdb = None

    return uc

def sym_or_addr(x):
    try:
        return int(x, 16)
    except ValueError:
        return x

def populate_parser(parser):
    parser.add_argument('input_file', type=str, help="Path to the file containing the mutated input to load")
    parser.add_argument('--prefix-input', dest='prefix_input_path', type=str, help="(Optional) Path to the file containing a constant input to load")
    parser.add_argument('-c', '--config', default="config.yml", help="The emulator configuration to use. Defaults to 'config.yml'")

    # Verbosity switches
    parser.add_argument('-d', '--debug', default=False, action="store_true", help="Enables debug mode (required for -t and -M) (SLOW!)")
    parser.add_argument('-v', '--print-exit-info', default=False, action="store_true", help="Print some information about the exit reason.")
    parser.add_argument('-M', '--trace-memory', default=False, action="store_true", dest='trace_memory', help="Enables memory tracing")
    parser.add_argument('-t', '--trace-funcs', dest='trace_funcs', default=False, action='store_true')
    parser.add_argument('--print-fork-child-output', default=False, action='store_true', help="Diagnostics: print output of discovery fork child (only interesting in case of early errors)")

    # Debugging switches
    parser.add_argument("-b", '--breakpoint', dest='breakpoints', action='append', default=[])
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-g", '--gdb', dest='gdb_port', type=int, default=0, help='Spawn gdb server at specified port (experimental, known to have issues)')
    group.add_argument("-S", '--shell', default=True, action='store_false', help='Invoke ipdb shell upon breakpoints (default)')

    # Argument-based limits
    parser.add_argument('-l', '--translation-block-limit', dest='basic_block_limit', type=int, default=globs.DEFAULT_BASIC_BLOCK_LIMIT, help=f"Maximum number of basic blocks to execute. 0: no limit. Default: {globs.DEFAULT_BASIC_BLOCK_LIMIT:d}")
    parser.add_argument('--fuzz-consumption-timeout', dest='fuzz_consumption_timeout', type=int, default=globs.DEFAULT_FUZZ_CONSUMPTION_TIMEOUT, help=f"Maximum number of basic blocks to execute while no input is read. 0: no limit. Default: {globs.DEFAULT_FUZZ_CONSUMPTION_TIMEOUT:d}")
    parser.add_argument('--interrupt-limit', dest='interrupt_limit', type=int, default=globs.DEFAULT_MAX_INTERRUPTS, help=f"Maximum number of interrupts to raise. 0: no limit. Default: {globs.DEFAULT_MAX_INTERRUPTS:d}")
    parser.add_argument('--exit-at', dest='exit_at_bbl', default=globs.EXIT_AT_NONE, type=sym_or_addr, help="Exit at the given basic block address.")
    parser.add_argument('--exit-at-hit-num', dest='exit_at_hit_num', type=int, default=1, help="Number of hits of basic block at which to exit. Defaults to 1 (exit on first hit).")

    # Trace file generation
    parser.add_argument('--mmio-trace-out', dest='mmio_trace_file', default=None)
    parser.add_argument('--ram-trace-out', dest='ram_trace_file', default=None)
    parser.add_argument('--bb-trace-out', dest='bb_trace_file', default=None)
    parser.add_argument('--bb-set-out', dest='bb_set_file', default=None, help="Trace (compact) set of visited basic blocks into binary file.")
    parser.add_argument('--mmio-set-out', dest='mmio_set_file', default=None, help="Trace (compact) set of MMIO access contexts into binary file.")
    parser.add_argument('--bb-hash-out', dest='bb_hash_file', default=None, help="Hash together all sequentially visited basic blocks into binary file. This can be used to compare executions.")
    parser.add_argument('--interrupt-trace-out', dest='interrupt_trace_file', default=None, help="Trace interrupt entries and exits.")
    parser.add_argument('--dma-trace-out', dest='dma_trace_file', default=None)
    parser.add_argument('--force-slow-tracing', default=False, action="store_true", help="Force legacy tracing via python instead of natively. Useful to check compatibility between the two.")

    # MMIO access state generation
    parser.add_argument('--state-out', dest='dump_state_filename', default=None, help="Destination of output state(s). If all MMIO accesses are to be dumped, pass a directory here.")
    parser.add_argument('--dump-mmio-states', dest='dump_mmio_states', default=False, action='store_true', help="Dump states at every unique MMIO access.")
    parser.add_argument('--dumped-mmio-contexts', default='', help="Restrict the (pc, mmio_address) contexts for which to dump states for. Format: pc1:mmio1,pc2:mmio2,...,pcX:mmioX")
    parser.add_argument('--dumped-mmio-name-prefix', default='', help="Add a prefix to each generated MMIO state name for distinguishability")

def main():
    parser = argparse.ArgumentParser(description="Fuzzware emulation harness")
    populate_parser(parser)

    args = parser.parse_args()
    globs.input_file_name = os.path.basename(args.input_file)

    if not os.path.exists(args.config):
        logger.error(f"config file '{args.config}' does not exist")
        sys.exit(1)

    if os.path.exists(args.input_file) and not os.path.isfile(args.input_file):
        logger.error("input file is no regular file")
        sys.exit(1)

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logging.getLogger("DMA").setLevel(logging.DEBUG)
        logging.getLogger("GDMA").setLevel(logging.DEBUG)
        logging.getLogger("GDMABuf").setLevel(logging.DEBUG)
        logging.getLogger("SNAP").setLevel(logging.DEBUG)

    debug_flags = [args.trace_memory, args.trace_funcs, args.breakpoints, args.gdb_port != 0]
    if any(debug_flags):
        args.debug = True

    uc = configure_unicorn(args)

    logger.info(f"Passing control to native code to start emulation. Running for input file '{args.input_file}'")
    sys.stdout.flush()

    # Collect garbage once in order to avoid doing so while fuzzing
    gc.collect()
    # gc.set_threshold(0, 0, 0)

    # We do everything in native code from here to avoid any python overhead after configuration is done
    native.emulate(uc, args.input_file, args.prefix_input_path)


if __name__ == "__main__":
    main()
