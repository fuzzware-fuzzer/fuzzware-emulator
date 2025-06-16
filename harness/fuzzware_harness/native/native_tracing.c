#include "native_tracing.h"

// 0. Constants
#define DEFAULT_INITIAL_MMIO_ACCESS_CONTEXT_TRACE_SET_CAPACITY 0x10000
#define DEFAULT_INITIAL_PC_TRACE_SET_CAPACITY 0x10000

// 1. Static (after initialization) configs
char *bbl_set_trace_path = NULL;
char *bbl_hash_path = NULL;
char *mmio_set_trace_path = NULL;
char *bbl_trace_path = NULL;
char *ram_trace_path = NULL;
char *mmio_trace_path = NULL;
char *interrupt_trace_path = NULL;

// 3. Dynamic State (required for state restore)
struct TraceState trace_state = {
    .trace_event_id_base = 0,
    .trace_event_id = 0,
    .bb_hash_base = 0,
    .bb_hash = 0,
    .kh_basic_block_set = NULL,
    .kh_scratch_basic_block_set = NULL,
    .kh_mmio_access_context_set_reads = NULL,
    .kh_scratch_mmio_access_context_set_reads = NULL,
    .kh_mmio_access_context_set_writes = NULL,
    .kh_scratch_mmio_access_context_set_writes = NULL,
    .bb_trace = NULL,
    .mmio_base_trace = NULL,
    .ram_base_trace = NULL,
    .ram_scratch_trace = NULL,
    .mmio_scratch_trace = NULL,
};

uint32_t get_next_trace_event_id() {
    #ifdef DEBUG_TRACING
    printf("Getting trace ID: %#x\n", trace_state.trace_event_id);fflush(stdout);
    #endif

    return trace_state.trace_event_id++;
}

static uint64_t dw_sdbm_hash(uint64_t state, uint32_t value)
{
    return value + (state << 6) + (state << 16) - state;
}

void hook_block_trace_set(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    int kh_res;

    if(kh_get(32, trace_state.kh_basic_block_set, address) == kh_end(trace_state.kh_basic_block_set)) {
        kh_put(32, trace_state.kh_scratch_basic_block_set, address, &kh_res);
    }
}

void hook_block_trace_hash_bbs(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    trace_state.bb_hash = dw_sdbm_hash(trace_state.bb_hash, address);
}

void hook_block_trace_bbs(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    #ifdef DEBUG_TRACING
    printf("[BB Full Trace] %#lx\n", address);fflush(stdout);
    #endif

    /*
     * Here we have to handle the BB trace cyclic compression feature.
     */
    struct BBTrace *trace = trace_state.bb_trace;
    if(bbtrace_cyclicly_compress(trace, address)) {
        /*
         * Address part of cycle, no new entry required.
         */
        return;
    }

    struct BBTraceEntry *entry = bbtrace_next_entry(trace);

    // uint32_t event_id, uint32_t pc
    entry->event_id = get_next_trace_event_id();
    entry->pc = address;
    entry->repetitions = 0;
}

#define ENCODE_MMIO_ACCESS_CONTEXT(PC, ADDR) (((uint64_t)(PC))<<32 | (uint64_t)(ADDR))
#define DECODE_MMIO_ACCESS_CONTEXT_PC(ENCODED_VAL) ((uint32_t)((ENCODED_VAL) >> 32))
#define DECODE_MMIO_ACCESS_CONTEXT_ADDR(ENCODED_VAL) ((uint32_t)((ENCODED_VAL) & 0xffffffff))

void hook_mem_trace_mmio_access(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    uint32_t pc;
    int kh_res;
    uint64_t context;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);

    if(mmio_set_trace_path) {
        // MMIO Access Context tracing
        context = ENCODE_MMIO_ACCESS_CONTEXT(pc, addr);

        #ifdef DEBUG_TRACING
        printf("[MMIO Trace] %s event [%#x] access to %#lx -> %#lx\n", type == UC_MEM_WRITE ? "WRITE" : "READ", pc, addr, value);fflush(stdout);
        #endif

        // We do not currently need write contexts, otherwise, this would need to be executed
        if(type == UC_MEM_WRITE) {
            //if( kh_get(64, trace_state.kh_mmio_access_context_set_writes, context)
            //        == kh_end(trace_state.kh_mmio_access_context_set_writes)) {
            //    kh_put(64, trace_state.kh_scratch_mmio_access_context_set_writes, context, &kh_res);
            //}
        } else {
            if( kh_get(64, trace_state.kh_mmio_access_context_set_reads, context)
                    == kh_end(trace_state.kh_mmio_access_context_set_reads)) {
                kh_put(64, trace_state.kh_scratch_mmio_access_context_set_reads, context, &kh_res);
            }
        }
    }

    if(mmio_trace_path) {
        // Full MMIO Access tracing
        uint32_t event_id = get_next_trace_event_id();

        bool is_read;
        uint32_t fuzz_offset;
        uint8_t consumed_fuzz_size;

        if(type == UC_MEM_WRITE) {
            is_read = false;
            fuzz_offset = 0;
            consumed_fuzz_size = 0;
        } else {
            is_read = true;
            fuzz_offset = get_latest_mmio_fuzz_access_index();
            consumed_fuzz_size = get_latest_mmio_fuzz_access_size();
        }

        struct MMIOTraceEntry *entry = mmiotrace_next_entry(trace_state.mmio_scratch_trace);

        entry->mem_entry.event_id = event_id;
        entry->mem_entry.pc = pc;
        // entry->mem_entry.lr = lr;
        uc_reg_read(uc, UC_ARM_REG_LR, &entry->mem_entry.lr);
        entry->mem_entry.address = addr;
        entry->mem_entry.value = value;
        entry->mem_entry.is_read = is_read;
        entry->mem_entry.size = size;
        entry->fuzz_offset = fuzz_offset;
        entry->consumed_fuzz_size = consumed_fuzz_size;
    }
}

void hook_mem_trace_ram_access(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    assert(ram_trace_path != NULL);

    struct RAMTraceEntry *entry = ramtrace_next_entry(trace_state.ram_scratch_trace);

    #ifdef DEBUG_TRACING
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("[RAM Trace] %s event [%#x] access to %#lx -> %#lx\n", type == UC_MEM_WRITE ? "WRITE" : "READ", pc, addr, value);fflush(stdout);
    #endif

    // uint32_t event_id, uint32_t pc, uint32_t lr, uint32_t address, uint32_t value, bool is_read, uint8_t size
    entry->event_id = get_next_trace_event_id();
    uc_reg_read(uc, UC_ARM_REG_PC, &entry->pc);
    uc_reg_read(uc, UC_ARM_REG_LR, &entry->lr);
    entry->address = addr;
    entry->value = value;
    entry->is_read = type != UC_MEM_WRITE;
    entry->size = size;
}

void interrupt_trace_add_event(bool is_entry, uint32_t num) {
    struct InterruptTrace *trace = trace_state.interrupt_scratch_trace;

    struct InterruptTraceEntry *entry = interrupt_trace_next_entry(trace);

    entry->event_id = get_next_trace_event_id();
    entry->num = num;
    entry->is_entry = is_entry;
}

void exit_hook_write_traces(int status, int sig)
{
    FILE *f;

    if(bbl_set_trace_path) {
        f = fopen(bbl_set_trace_path, "w");

        uint32_t bbl_addr;
        kh_foreach_key(trace_state.kh_basic_block_set, bbl_addr, {
            fprintf(f, "%x\n", bbl_addr);
        });
        kh_foreach_key(trace_state.kh_scratch_basic_block_set, bbl_addr, {
            fprintf(f, "%x\n", bbl_addr);
        });

        fflush(f);
        fclose(f);
    }

    if(bbl_hash_path) {
        f = fopen(bbl_hash_path, "w");
        fprintf(f, "%016lx\n", trace_state.bb_hash);

        fflush(f);
        fclose(f);
    }

    if(mmio_set_trace_path) {
        f = fopen(mmio_set_trace_path, "w");

        uint64_t access_context;
        kh_foreach_key(trace_state.kh_mmio_access_context_set_reads, access_context, {
            fprintf(f, "%x %x r\n", DECODE_MMIO_ACCESS_CONTEXT_PC(access_context), DECODE_MMIO_ACCESS_CONTEXT_ADDR(access_context));
        });
        kh_foreach_key(trace_state.kh_scratch_mmio_access_context_set_reads, access_context, {
            fprintf(f, "%x %x r\n", DECODE_MMIO_ACCESS_CONTEXT_PC(access_context), DECODE_MMIO_ACCESS_CONTEXT_ADDR(access_context));
        });

        kh_foreach_key(trace_state.kh_mmio_access_context_set_writes, access_context, {
            fprintf(f, "%x %x w\n", DECODE_MMIO_ACCESS_CONTEXT_PC(access_context), DECODE_MMIO_ACCESS_CONTEXT_ADDR(access_context));
        });
        kh_foreach_key(trace_state.kh_scratch_mmio_access_context_set_writes, access_context, {
            fprintf(f, "%x %x w\n", DECODE_MMIO_ACCESS_CONTEXT_PC(access_context), DECODE_MMIO_ACCESS_CONTEXT_ADDR(access_context));
        });

        fflush(f);
        fclose(f);
    }

    if(bbl_trace_path) {
        dump_bb_trace(bbl_trace_path, trace_state.bb_trace);
    }

    if(ram_trace_path) {
        dump_ram_trace(ram_trace_path, trace_state.ram_base_trace, trace_state.ram_scratch_trace);
    }

    if(mmio_trace_path) {
        dump_mmio_trace(mmio_trace_path, trace_state.mmio_base_trace, trace_state.mmio_scratch_trace);
    }

    if(interrupt_trace_path) {
        dump_interrupt_trace(interrupt_trace_path, trace_state.interrupt_base_trace, trace_state.interrupt_scratch_trace);
    }
}

void *tracing_take_snapshot(uc_engine *uc) {
    int kh_res;

    if(trace_state.kh_basic_block_set) {
        // Copy all entries from scratch set to base set and erase scratch
        uint32_t bbl_addr;

        kh_foreach_key(trace_state.kh_scratch_basic_block_set, bbl_addr, {
            kh_put(32, trace_state.kh_basic_block_set, bbl_addr, &kh_res);
        });
        kh_clear(32, trace_state.kh_scratch_basic_block_set);
    }

    if(bbl_hash_path) {
        trace_state.bb_hash_base = trace_state.bb_hash;
    }

    if(trace_state.kh_mmio_access_context_set_reads && trace_state.kh_mmio_access_context_set_writes) {
        // Copy all entries from scratch set to base set and erase scratch
        uint64_t context;

        kh_foreach_key(trace_state.kh_scratch_mmio_access_context_set_reads, context, {
            kh_put(64, trace_state.kh_mmio_access_context_set_reads, context, &kh_res);
        });
        kh_clear(64, trace_state.kh_scratch_mmio_access_context_set_reads);

        kh_foreach_key(trace_state.kh_scratch_mmio_access_context_set_writes, context, {
            kh_put(64, trace_state.kh_mmio_access_context_set_writes, context, &kh_res);
        });
        kh_clear(64, trace_state.kh_scratch_mmio_access_context_set_writes);
    }

    if(bbl_trace_path) {
        // Save current state. We also need to include the current cycle info in the state.
        assert(trace_state.bb_trace != NULL);
        bbtrace_save_state(trace_state.bb_trace);
    }

    if(ram_trace_path) {
        // Move scratch trace ptr to base trace, shrink it, and allocate new
        assert(trace_state.ram_base_trace == NULL);
        assert(trace_state.ram_scratch_trace != NULL);
        trace_state.ram_base_trace = trace_state.ram_scratch_trace;
        ramtrace_shrink(trace_state.ram_base_trace);
        trace_state.ram_scratch_trace = ramtrace_new();
    }

    if(mmio_trace_path) {
        // Move scratch trace ptr to base trace, shrink it, and allocate new
        assert(trace_state.mmio_base_trace == NULL);
        assert(trace_state.mmio_scratch_trace != NULL);
        trace_state.mmio_base_trace = trace_state.mmio_scratch_trace;
        mmiotrace_shrink(trace_state.mmio_base_trace);
        trace_state.mmio_scratch_trace = mmiotrace_new();
    }

    if(interrupt_trace_path) {
        // Move scratch trace ptr to base trace, shrink it, and allocate new
        assert(trace_state.interrupt_base_trace == NULL);
        assert(trace_state.interrupt_scratch_trace != NULL);
        trace_state.interrupt_base_trace = trace_state.interrupt_scratch_trace;
        interrupt_trace_shrink(trace_state.interrupt_base_trace);
        trace_state.interrupt_scratch_trace = interrupt_trace_new();
    }

    trace_state.trace_event_id_base = trace_state.trace_event_id;

    return NULL;
}

void tracing_restore_snapshot(uc_engine *uc, void *snapshot) {
    // Restoring is just emptying the scratch buffer
    if(trace_state.kh_basic_block_set) {
        kh_clear(32, trace_state.kh_scratch_basic_block_set);
    }

    if(trace_state.kh_mmio_access_context_set_reads) {
        kh_clear(64, trace_state.kh_scratch_mmio_access_context_set_reads);
    }

    if(trace_state.kh_mmio_access_context_set_writes) {
        kh_clear(64, trace_state.kh_scratch_mmio_access_context_set_writes);
    }

    if(bbl_hash_path) {
        trace_state.bb_hash = trace_state.bb_hash_base;
    }

    if(bbl_trace_path) {
        bbtrace_restore_state(trace_state.bb_trace);
    }

    if(ram_trace_path) {
        ramtrace_reset(trace_state.ram_scratch_trace);
    }

    if(mmio_trace_path) {
        mmiotrace_reset(trace_state.mmio_scratch_trace);
    }

    if(interrupt_trace_path) {
        interrupt_trace_reset(trace_state.interrupt_scratch_trace);
    }

    trace_state.trace_event_id = trace_state.trace_event_id_base;
}

void tracing_discard_snapshot(uc_engine *uc, void *snapshot) {
    // NOP, as we did not allocate anything.
    // At the same time, be aware that we can only hold one snapshot at a time
}

uc_err init_tracing(uc_engine *uc, int force_trace_ids, char *p_bbl_set_trace_path, char *p_bbl_hash_path, char *p_mmio_set_trace_path, char *p_bbl_trace_path, char *p_ram_trace_path, char *p_mmio_trace_path, char *p_interrupt_trace_path, int num_mmio_ranges, uint64_t *mmio_starts, uint64_t *mmio_ends, int num_ram_ranges, uint64_t *ram_starts, uint64_t *ram_ends) {
    uc_hook tmp_hook;

    bool has_native_traces = p_bbl_set_trace_path || p_bbl_hash_path || p_mmio_set_trace_path || p_bbl_trace_path || p_ram_trace_path || p_mmio_trace_path || p_interrupt_trace_path;
    if (has_native_traces) {
        #ifdef DEBUG_TRACING
        printf("[init_tracing] uc: %p, num mmio regions: %x\nbbl set path: %s\nbb hash path: %s\nmmio set path: %s\nbb trace path: %s\nram trace path: %s\nmmio trace path: %s\n\n", uc, num_mmio_ranges, p_bbl_set_trace_path, p_bbl_hash_path, p_mmio_set_trace_path, p_bbl_trace_path, p_ram_trace_path, p_mmio_trace_path);
        for(int i = 0; i < num_mmio_ranges; ++i) {
            printf("[%d] %#lx - %#lx\n", i, mmio_starts[i], mmio_ends[i]);
        }
        fflush(stdout);
        #endif

        add_exit_hook(exit_hook_write_traces);

        if (p_bbl_set_trace_path) {
            bbl_set_trace_path = strdup(p_bbl_set_trace_path);

            trace_state.kh_basic_block_set = kh_init(32);
            trace_state.kh_scratch_basic_block_set = kh_init(32);

            // Tracing basic blocks is done via a single block hook
            uc_hook_add(uc, &tmp_hook, UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_trace_set, NULL, 1, 0);
        }

        if(p_bbl_hash_path) {
            bbl_hash_path = strdup(p_bbl_hash_path);

            // Tracing basic blocks is done via a single block hook
            uc_hook_add(uc, &tmp_hook, UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_trace_hash_bbs, NULL, 1, 0);
        }

        if(p_mmio_set_trace_path) {
            mmio_set_trace_path = strdup(p_mmio_set_trace_path);

            trace_state.kh_mmio_access_context_set_writes = kh_init(64);
            trace_state.kh_mmio_access_context_set_reads = kh_init(64);
            trace_state.kh_scratch_mmio_access_context_set_writes = kh_init(64);
            trace_state.kh_scratch_mmio_access_context_set_reads = kh_init(64);
        }

        // If we have any MMIO tracing, add hooks for MMIO regions
        if(p_mmio_set_trace_path || p_mmio_trace_path) {
            // For tracing MMIO, we need to register hooks for all MMIO regions
            for (int i = 0; i < num_mmio_ranges; ++i) {
                uc_hook_add(uc, &tmp_hook, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ_AFTER, hook_mem_trace_mmio_access, NULL, mmio_starts[i], mmio_ends[i]);
            }
        }

        if(p_bbl_trace_path) {
            bbl_trace_path = strdup(p_bbl_trace_path);

            trace_state.bb_trace = bbtrace_new();

            uc_hook_add(uc, &tmp_hook, UC_HOOK_BLOCK_UNCONDITIONAL, hook_block_trace_bbs, NULL, 1, 0);
        }

        if(p_ram_trace_path) {
            ram_trace_path = strdup(p_ram_trace_path);

            trace_state.ram_base_trace = NULL;
            trace_state.ram_scratch_trace = ramtrace_new();

            for (int i = 0; i < num_ram_ranges; ++i) {
                uc_hook_add(uc, &tmp_hook, UC_HOOK_MEM_WRITE | UC_HOOK_MEM_READ_AFTER, hook_mem_trace_ram_access, NULL, ram_starts[i], ram_ends[i]);
            }
        }

        if(p_mmio_trace_path) {
            mmio_trace_path = strdup(p_mmio_trace_path);

            trace_state.mmio_base_trace = NULL;
            trace_state.mmio_scratch_trace = mmiotrace_new();
        }

        if(p_interrupt_trace_path) {
            interrupt_trace_path = strdup(p_interrupt_trace_path);

            trace_state.interrupt_base_trace = NULL;
            trace_state.interrupt_scratch_trace = interrupt_trace_new();
        }
    }

    if(force_trace_ids || has_native_traces) {
        subscribe_state_snapshotting(uc, tracing_take_snapshot, tracing_restore_snapshot, tracing_discard_snapshot);
    }
    return UC_ERR_OK;
}
