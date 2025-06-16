#ifndef NATIVE_INTERRUPT_TRACE
#define NATIVE_INTERRUPT_TRACE

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

struct InterruptTraceEntry {
    uint32_t event_id;
    uint32_t num;
    bool is_entry;
};

struct InterruptTrace {
    size_t capacity;
    size_t in_use;
    struct InterruptTraceEntry *entries;
};

struct InterruptTrace *interrupt_trace_new();

void interrupt_trace_reset(struct InterruptTrace *trace);

// Shrink entries to just the required size
void interrupt_trace_shrink(struct InterruptTrace *trace);

struct InterruptTraceEntry *interrupt_trace_next_entry(struct InterruptTrace *trace);

void interrupt_trace_reset(struct InterruptTrace *trace);

#endif