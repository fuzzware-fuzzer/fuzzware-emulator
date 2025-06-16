#include "interrupt_trace.h"

// see globs.py#DEFAULT_MAX_INTERRUPTS
#define INITIAL_INTERRUPT_TRACE_CAPACITY 3000
#define INTERRUPT_TRACE_CAPACITY_INCREMENT INITIAL_INTERRUPT_TRACE_CAPACITY

struct InterruptTrace *interrupt_trace_new() {
    struct InterruptTrace *res = calloc(1, sizeof(struct InterruptTrace));
    assert(res != NULL);
    res->capacity = INITIAL_INTERRUPT_TRACE_CAPACITY;
    res->in_use = 0;
    res->entries = calloc(INITIAL_INTERRUPT_TRACE_CAPACITY, sizeof(*res->entries));
    assert(res->entries != NULL);
    return res;
}

void interrupt_trace_reset(struct InterruptTrace *trace) {
    trace->in_use = 0;
}

void interrupt_trace_shrink(struct InterruptTrace *trace) {
    trace->entries = reallocarray(trace->entries, trace->in_use, sizeof(*trace->entries));
    assert(trace->in_use == 0 || trace->entries != NULL);
}

struct InterruptTraceEntry *interrupt_trace_next_entry(struct InterruptTrace *trace) {
    if(trace->capacity <= trace->in_use) {
        trace->capacity += INTERRUPT_TRACE_CAPACITY_INCREMENT;
        trace->entries = reallocarray(trace->entries, trace->capacity, sizeof(*trace->entries));
    }

    struct InterruptTraceEntry *entry = &trace->entries[trace->in_use++];
    return entry;
}
