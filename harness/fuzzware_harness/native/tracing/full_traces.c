#include "full_traces.h"

#define INITIAL_BB_TRACE_CAPACITY 0x80000
#define INITIAL_RAM_TRACE_CAPACITY INITIAL_BB_TRACE_CAPACITY
#define INITIAL_MMIO_TRACE_CAPACITY INITIAL_BB_TRACE_CAPACITY

#define BB_TRACE_CAPACITY_INCREMENT INITIAL_BB_TRACE_CAPACITY
#define RAM_TRACE_CAPACITY_INCREMENT INITIAL_BB_TRACE_CAPACITY
#define MMIO_TRACE_CAPACITY_INCREMENT INITIAL_BB_TRACE_CAPACITY

/* TODO: Potentially large memory reservations due to fully cached trace entries

- To avoid high memory reservations, make these a ring buffer and write to file in chunks?
    - Added complexity: BB cycle detection would need to use ring-aware indices
    - inotify-based pipeline could cause race? Check and may need to switch to job state-based result communication in pipeline

- Some quick math of maxima for default case:
    - BB trace
        - Default limit: 3 MIO entries
        - sizeof(struct BBTraceEntry) == 3 x sizeof(uint32_t) == 12 bytes
        - Expected memory footprint: 12 bytes * 3 MIO * 0.5 ~~ 20MB
        - Absolute worst case: 25 MIO entries -> 8 * 40MB = 320 MB per trace generation worker
        - In reality
            - loops get compressed, so likely 50%-90% of entries saved
            - full limit is rarely reached due to interrupt limits + fuzz consumption timeout
        - Expected memory footprint of BB trace for generation worker: ~20MB
    - RAM trace
        - sizeof(struct RAMTraceEntry) == 7 * sizeof(uint32_t) == 28 bytes
        - Expected number of accesses: 100k
        - Expected number of accesses: up to 1 MIO (which would generate huge trace files)
        - Expected memory footprint: 300k * 28 bytes ~~ 10 MB
        - Expected max memory footprint: 30 MB
    - MMIO trace: Based on Fuzzing entries
        - sizeof(struct MMIOTraceEntry) == sizeof(struct RAMTraceEntry) + 2 * sizeof(uint32_t) == 36 bytes
        - Expected number of accesses: see RAM ~~ 10
        - Expected memory footprint: 300k * 36 bytes ~~ 15 MB
    - Overall:
        - Expected footprint: 20MB + 10MB + 15 MB ~~ 50 MB per trace worker
        - Server with 100 parallel 1-core pipelines: 100 * 50MB ~~ 5GB RAM
        - -> This should be fine for now
*/

#define BB_CYCLE_LEN_DEFAULT 1
struct BBTrace *bbtrace_new() {
    struct BBTrace *res = calloc(1, sizeof(struct BBTrace));
    assert(res != NULL);
    res->capacity = INITIAL_BB_TRACE_CAPACITY;
    res->in_use = 0;
    res->entries = calloc(INITIAL_BB_TRACE_CAPACITY, sizeof(*res->entries));
    assert(res->entries != NULL);
    res->cur_cycle_len = BB_CYCLE_LEN_DEFAULT;
    res->cur_cycle_offset = 0;
    res->saved_cycle_len = res->saved_cycle_offset = BB_CYCLE_LEN_DEFAULT;
    return res;
}

void bbtrace_save_state(struct BBTrace *trace) {
    size_t in_use = trace->in_use;
    size_t cycle_len = trace->cur_cycle_len;
    trace->saved_cycle_len = cycle_len;
    trace->saved_cycle_offset = trace->cur_cycle_offset;
    trace->saved_inuse = in_use;

    // If we already have trace events, save the current cycle entries (to be able to reset )
    if(in_use) {
        for(int i = 0; i < cycle_len; ++i) {
            trace->saved_cycle_repetitions[i] = trace->entries[in_use-cycle_len+i].repetitions;
        }
    }
}

void bbtrace_restore_state(struct BBTrace *trace) {
    size_t in_use = trace->saved_inuse;
    size_t cycle_len = trace->saved_cycle_len;

    trace->in_use = in_use;
    trace->cur_cycle_len = cycle_len;
    trace->cur_cycle_offset = trace->saved_cycle_offset;

    // If we already have trace events, restore the current cycle entries
    if(in_use) {
        for(int i = 0; i < cycle_len; ++i) {
            trace->entries[in_use-cycle_len+i].repetitions = trace->saved_cycle_repetitions[i];
        }
    }
}

struct BBTraceEntry *bbtrace_next_entry(struct BBTrace *trace) {
    if(trace->capacity <= trace->in_use) {
        trace->capacity += BB_TRACE_CAPACITY_INCREMENT;
        trace->entries = reallocarray(trace->entries, trace->capacity, sizeof(*trace->entries));
    }

    struct BBTraceEntry *entry = &trace->entries[trace->in_use++];

    return entry;
}

bool bbtrace_cyclicly_compress(struct BBTrace *trace, uint32_t pc) {
    /*
     * Originally implemented Python: fuzzware_harness.tracing.trace_bbs.py#collect_bb_event
     *
     * The idea here is to save PC trace entries for loops. This is done by detecting whether
     * the same basic series of blocks are taken over and over. We check this up to a maximum
     * length of MAX_BB_TRACE_CYCLE_LEN (which is 4 in the original implementation).
     */
    size_t inuse = trace->in_use;
    if(inuse == 0) {
        return false;
    }

    // 1. Are we currently tracking a cycle?
    uint32_t cycle_len = trace->cur_cycle_len;
    // 1.1 Are we staying in the cycle (or are we repeating the last BB?)
    int reference_index = inuse - cycle_len + trace->cur_cycle_offset;
    struct BBTraceEntry *reference_entry = &trace->entries[reference_index];
    if(pc == reference_entry->pc) {
        // In a cycle! Update the re-visit count and we are done here.
        ++reference_entry->repetitions;

        #ifdef DEBUG_TRACING
        printf("[BB Full Trace] cyclic compression continuation hit with cycle_len: %u\n", cycle_len);fflush(stdout);
        #endif

        if(cycle_len > 1) {
            trace->cur_cycle_offset = (trace->cur_cycle_offset + 1) % cycle_len;
        }
        return true;
    } else if(cycle_len != BB_CYCLE_LEN_DEFAULT) {
        // Not in a cycle (anymore), reset metadata if it is not the default
        trace->cur_cycle_len = BB_CYCLE_LEN_DEFAULT;
        trace->cur_cycle_offset = 0;
    }

    // 2. We are not in a cycle, yet. Are we beginning one?
    if(inuse >= 2*MAX_BB_TRACE_CYCLE_LEN) {
        #ifdef DEBUG_TRACING
        printf("[BB Full Trace] cyclic compression: looking for cycle\n");fflush(stdout);
        #endif

        bool found = false;
        for(int prefix_len = MAX_BB_TRACE_CYCLE_LEN; prefix_len > 1; --prefix_len) {
            // We start scanning two cycles back
            struct BBTraceEntry *cursor = &trace->entries[inuse - 2 * prefix_len];

            if(pc == cursor->pc && pc == cursor[prefix_len].pc) {
                // The first member fits, check the remaining ones
                found = true;
                for(int i = 1; i < prefix_len; ++i) {
                    if(cursor[i].pc != cursor[prefix_len+i].pc) {
                        found = false;
                        break;
                    }
                }

                if(found) {
                    trace->cur_cycle_len = prefix_len;
                    trace->cur_cycle_offset = 1;
                    ++cursor[prefix_len].repetitions;
                    assert(&cursor[prefix_len] == &trace->entries[inuse - prefix_len]);

                    #ifdef DEBUG_TRACING
                    printf("[BB Full Trace] cyclic compression started hit with cycle_len: %u\n", prefix_len);fflush(stdout);
                    #endif
                    return true;
                }
            }
        }
    }

    return false;
}

struct RAMTrace *ramtrace_new() {
    struct RAMTrace *res = calloc(1, sizeof(struct RAMTrace));
    assert(res != NULL);
    res->capacity = INITIAL_RAM_TRACE_CAPACITY;
    res->in_use = 0;
    res->entries = calloc(INITIAL_RAM_TRACE_CAPACITY, sizeof(*res->entries));
    assert(res->entries != NULL);
    return res;
}

void ramtrace_reset(struct RAMTrace *trace) {
    trace->in_use = 0;
}

void ramtrace_shrink(struct RAMTrace *trace) {
    trace->entries = reallocarray(trace->entries, trace->in_use, sizeof(*trace->entries));
    assert(trace->in_use == 0 || trace->entries != NULL);
}

struct RAMTraceEntry *ramtrace_next_entry(struct RAMTrace *trace) {
    if(trace->capacity <= trace->in_use) {
        trace->capacity += RAM_TRACE_CAPACITY_INCREMENT;
        trace->entries = reallocarray(trace->entries, trace->capacity, sizeof(*trace->entries));
    }

    struct RAMTraceEntry *entry = &trace->entries[trace->in_use++];
    return entry;
}

struct MMIOTrace *mmiotrace_new() {
    struct MMIOTrace *res = calloc(1, sizeof(struct MMIOTrace));
    assert(res != NULL);
    res->capacity = INITIAL_MMIO_TRACE_CAPACITY;
    res->in_use = 0;
    res->entries = calloc(INITIAL_MMIO_TRACE_CAPACITY, sizeof(*res->entries));
    assert(res->entries != NULL);
    return res;
}

void mmiotrace_reset(struct MMIOTrace *trace) {
    trace->in_use = 0;
}

void mmiotrace_shrink(struct MMIOTrace *trace) {
    trace->entries = reallocarray(trace->entries, trace->in_use, sizeof(*trace->entries));
    assert(trace->in_use == 0 || trace->entries != NULL);
}

struct MMIOTraceEntry *mmiotrace_next_entry(struct MMIOTrace *trace) {
    if(trace->capacity <= trace->in_use) {
        trace->capacity += MMIO_TRACE_CAPACITY_INCREMENT;
        trace->entries = reallocarray(trace->entries, trace->capacity, sizeof(*trace->entries));
    }

    struct MMIOTraceEntry *entry = &trace->entries[trace->in_use++];
    return entry;
}