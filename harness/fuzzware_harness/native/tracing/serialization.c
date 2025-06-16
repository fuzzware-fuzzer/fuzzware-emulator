#include "serialization.h"

void write_bb_trace_to_file(FILE *f, struct BBTrace *trace) {
    for(int i = 0; i < trace->in_use; ++i) {
        struct BBTraceEntry *entry = &trace->entries[i];

        fprintf(f, "%04x %x %d\n", entry->event_id, entry->pc, entry->repetitions);
    }
}

void dump_bb_trace(char *out_path, struct BBTrace *scratch_trace) {
    FILE *f = fopen(out_path, "w");
    assert(scratch_trace != NULL);

    write_bb_trace_to_file(f, scratch_trace);

    fflush(f);
    fclose(f);
}

void write_ram_trace_to_file(FILE *f, struct RAMTrace *trace) {
    int cursor = 0;
    while(cursor < trace->in_use) {
        int i;
        struct RAMTraceEntry *entry = &trace->entries[cursor];
        fprintf(f, "%04x: %x %x %c %d 0x%08x:%x", entry->event_id, entry->pc,
                    entry->lr, entry->is_read ? 'r' : 'w',
                    entry->size, entry->address, entry->value);
        for(i = cursor + 1; i < trace->in_use; ++i) {
            if( trace->entries[i].pc != entry->pc || trace->entries[i].lr != entry->lr ||
                trace->entries[i].address != entry->address || trace->entries[i].size != entry->size ||
                trace->entries[i].is_read != entry->is_read) {
                    break;
            } else {
                fprintf(f, " %x", trace->entries[i].value);
            }
        }
        cursor = i;
        fputc('\n', f);
    }
}

void dump_ram_trace(char *out_path, struct RAMTrace *base_trace, struct RAMTrace *scratch_trace) {
    FILE *f = fopen(out_path, "w");
    assert(scratch_trace != NULL);

    if(base_trace) {
        write_ram_trace_to_file(f, base_trace);
    }
    write_ram_trace_to_file(f, scratch_trace);

    fflush(f);
    fclose(f);
}

void write_mmio_trace_to_file(FILE *f, struct MMIOTrace *trace) {
    for(int i = 0; i < trace->in_use; ++i) {
        struct MMIOTraceEntry *entry = &trace->entries[i];

        fprintf(f, "%04x: %x %x %c %d %d %d 0x%08x:%x\n", entry->mem_entry.event_id, entry->mem_entry.pc,
                entry->mem_entry.lr, entry->mem_entry.is_read ? 'r' : 'w',
                entry->mem_entry.size, entry->fuzz_offset, entry->consumed_fuzz_size,
                entry->mem_entry.address, entry->mem_entry.value);
    }
}

void dump_mmio_trace(char *out_path, struct MMIOTrace *base_trace, struct MMIOTrace *scratch_trace) {
    FILE *f = fopen(out_path, "w");
    assert(scratch_trace != NULL);

    if(base_trace) {
        write_mmio_trace_to_file(f, base_trace);
    }
    write_mmio_trace_to_file(f, scratch_trace);

    fflush(f);
    fclose(f);
}

void write_interrupt_trace_to_file(FILE *f, struct InterruptTrace *trace) {
    for(int i = 0; i < trace->in_use; ++i) {
        struct InterruptTraceEntry *entry = &trace->entries[i];

        fprintf(f, "%04x: %s %u\n", entry->event_id, entry->is_entry ? "entry" : "exit", entry->num);
    }
}

void dump_interrupt_trace(char *out_path, struct InterruptTrace *base_trace, struct InterruptTrace *scratch_trace) {
    FILE *f = fopen(out_path, "w");
    assert(scratch_trace != NULL);

    if(base_trace) {
        write_interrupt_trace_to_file(f, base_trace);
    }
    write_interrupt_trace_to_file(f, scratch_trace);

    fflush(f);
    fclose(f);
}