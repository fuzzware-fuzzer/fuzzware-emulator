# TODO: Implement snapshotting

from .trace_ids import next_event_id

from ..exit import add_exit_hook

from .serialization import dump_dma_trace_file

dma_events = []
dma_trace_file_path = None

def add_dma_event(pc, lr, address, fuzz_offset, contents, is_receive=True):
    global dma_events
    from ..globs import uc
    event_id = next_event_id(uc)
    dma_events.append((event_id, is_receive, pc, lr, address, fuzz_offset, contents))

def exit_hook_dump_dma_trace(uc):
    global dma_events
    global dma_trace_file_path
    # TODO: this seems to be called multiple times?
    dump_dma_trace_file(dma_events, dma_trace_file_path)

def init_dma_tracing(trace_file):
    global dma_trace_file_path

    # Already initialized?
    if dma_trace_file_path:
        return

    if trace_file is not None:
        dma_trace_file_path = trace_file
        add_exit_hook(exit_hook_dump_dma_trace)
