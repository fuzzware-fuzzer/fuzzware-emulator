#ifndef FUZZWARE_NATIVE_TRACING
#define FUZZWARE_NATIVE_TRACING

#include <unicorn/unicorn.h>
#include <string.h>

#include "native_hooks.h"
#include "state_snapshotting.h"
#include "tracing/full_traces.h"
#include "tracing/interrupt_trace.h"
#include "tracing/serialization.h"

#include "khash.h"

KHASH_SET_INIT_INT64(64);
KHASH_SET_INIT_INT(32);

extern char *interrupt_trace_path;

/*
 * To support snapshotting, keep one base set around as well as
 * one scratch set. We store all contexts already collected upon
 * taking a snapshot in the base sets, and add to the scratch set
 * when running from a snapshot. Restoring the snapshot then means
 * only wiping the scratch set.
 *
 * Note that nested snapshotting (which we are currently not using)
 * is not supported by this.
 */
struct TraceState {
    uint32_t trace_event_id_base;
    uint32_t trace_event_id;
    uint64_t bb_hash_base;
    uint64_t bb_hash;
    // Set-based traces
    khash_t(32) *kh_basic_block_set;
    khash_t(64) *kh_mmio_access_context_set_writes;
    khash_t(64) *kh_mmio_access_context_set_reads;
    khash_t(32) *kh_scratch_basic_block_set;
    khash_t(64) *kh_scratch_mmio_access_context_set_writes;
    khash_t(64) *kh_scratch_mmio_access_context_set_reads;
    // Full traces
    struct BBTrace *bb_trace;
    struct RAMTrace *ram_base_trace;
    struct MMIOTrace *mmio_base_trace;
    struct RAMTrace *ram_scratch_trace;
    struct MMIOTrace *mmio_scratch_trace;
    struct InterruptTrace *interrupt_base_trace;
    struct InterruptTrace *interrupt_scratch_trace;
};

uc_err init_tracing(uc_engine *uc, int force_trace_ids, char *p_bbl_set_trace_path, char *p_bbl_hash_path, char *p_mmio_set_trace_path, char *p_bbl_trace_path, char *p_ram_trace_path, char *p_mmio_trace_path, char *p_interrupt_trace_path, int num_mmio_ranges, uint64_t *mmio_starts, uint64_t *mmio_ends, int num_ram_ranges, uint64_t *ram_starts, uint64_t *ram_ends);

/*
 * Get the next trace ID
 */
uint32_t get_next_trace_event_id();

void interrupt_trace_add_event(bool is_entry, uint32_t num);

#endif