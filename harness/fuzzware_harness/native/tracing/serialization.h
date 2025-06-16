#ifndef NATIVE_TRACE_SERIALIZATION
#define NATIVE_TRACE_SERIALIZATION

#include "full_traces.h"
#include "interrupt_trace.h"

void dump_bb_trace(char *out_path, struct BBTrace *trace);
void dump_ram_trace(char *out_path, struct RAMTrace *base_trace, struct RAMTrace *scratch_trace);
void dump_mmio_trace(char *out_path, struct MMIOTrace *base_trace, struct MMIOTrace *scratch_trace);
void dump_interrupt_trace(char *out_path, struct InterruptTrace *base_trace, struct InterruptTrace *scratch_trace);

#endif