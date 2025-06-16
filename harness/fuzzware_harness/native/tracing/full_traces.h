#ifndef NATIVE_FULL_TRACES
#define NATIVE_FULL_TRACES

#include <stdint.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

#include "../native_hooks.h"

// def dump_bbl_line(event_id, bb_addr, count):
struct BBTraceEntry {
    uint32_t event_id;
    uint32_t pc;
    uint32_t repetitions;
};

// def _dump_ram_access_events(uc, outfile, events):
//    for event_id, pc, lr, mode, size, address, value in events:
// def dump_ram_line(event_id, pc, lr, mode, size, address, values):
struct RAMTraceEntry {
    uint32_t event_id;
    uint32_t pc;
    uint32_t lr;
    uint32_t address;
    uint32_t value;
    bool is_read;
    uint8_t size;
};

// def dump_mmio_line(event_id, pc, lr, mode, orig_access_size, fuzz_offset, consumed_fuzz_size, address, value):
struct MMIOTraceEntry {
    struct RAMTraceEntry mem_entry;
    uint32_t fuzz_offset;
    uint8_t consumed_fuzz_size;
};

#define MAX_BB_TRACE_CYCLE_LEN 4
struct BBTrace {
    size_t capacity;
    size_t in_use;
    size_t saved_inuse;
    uint32_t cur_cycle_len;
    uint32_t saved_cycle_len;
    uint32_t cur_cycle_offset;
    uint32_t saved_cycle_offset;
    uint32_t saved_cycle_repetitions[MAX_BB_TRACE_CYCLE_LEN];
    struct BBTraceEntry *entries;
};

struct RAMTrace {
    size_t capacity;
    size_t in_use;
    struct RAMTraceEntry *entries;
};

struct MMIOTrace {
    size_t capacity;
    size_t in_use;
    struct MMIOTraceEntry *entries;
};

struct BBTrace *bbtrace_new();
struct RAMTrace *ramtrace_new();
struct MMIOTrace *mmiotrace_new();

void ramtrace_reset(struct RAMTrace *trace);
void mmiotrace_reset(struct MMIOTrace *trace);

// Shrink entries to just the required size
void bbtrace_shrink(struct BBTrace *trace);
void ramtrace_shrink(struct RAMTrace *trace);
void mmiotrace_shrink(struct MMIOTrace *trace);

struct BBTraceEntry *bbtrace_next_entry(struct BBTrace *trace);
struct RAMTraceEntry *ramtrace_next_entry(struct RAMTrace *trace);
struct MMIOTraceEntry *mmiotrace_next_entry(struct MMIOTrace *trace);

/*
 * Check whether the PC is part of a loop and update current trace state
 * in case a cycle has been detected.
 *
 * Returns true in case a cycle has been detected and fully handled, false otherwise.
 */
bool bbtrace_cyclicly_compress(struct BBTrace *trace, uint32_t pc);

void bbtrace_save_state(struct BBTrace *trace);
void bbtrace_restore_state(struct BBTrace *trace);

#endif