#ifndef NATIVE_HOOKS_H
#define NATIVE_HOOKS_H

#include "unicorn/unicorn.h"
#include "state_snapshotting.h"
#include "uc_snapshot.h"

//#define DEBUG
//#define DEBUG_STATE_RESTORE
//#define DEBUG_SYSTICK
//#define DEBUG_TIMER
//#define DEBUG_INJECT_TIMER
//#define DEBUG_TIMER_TICKS
//#define DEBUG_NVIC
//#define DEBUG_INTERRUPT_TRIGGERS
//#define DEBUG_STATE_SNAPSHOTTING
//#define DEBUG_TRACING


#define DEBUG_TIMER_TIMEOUT 100

extern int do_print_exit_info;
extern int do_print_nvic_log;

extern uint32_t num_mmio_regions;
extern uint64_t *mmio_region_starts;
extern uint64_t *mmio_region_ends;

struct linear_mmio_model_config {
    uint32_t step;
    uint32_t val;
};

struct constant_mmio_model_config {
    uint32_t val;
};

struct bitextract_mmio_model_config {
    uint8_t byte_size;
    uint8_t left_shift;
    uint8_t mask_hamming_weight;
    uint32_t mask;
};

struct value_set_mmio_model_config {
    uint32_t num_vals;
    uint32_t *values;
};

struct mmio_callback
{
    uint64_t start;
    uint64_t end;
    uint32_t pc;
    void *user_data;
    uc_cb_hookmem_t callback;
};

enum mmio_handle_res_t {
    IS_HANDLED = 0,
    FORWARD_TO_DEFAULT = 1,
    PASSTHROUGH = 2
};

struct py_hle_hooked_addr_state {
    int num_inuse;
    uint64_t *addrs;
    int capacity;
};

typedef enum mmio_handle_res_t (*devmem_access_cb_t)(int, uint64_t, int);

typedef void (*exit_hook_t)(int, int);
typedef void (*mmio_region_added_cb_t)(uint64_t, uint64_t);

void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void hook_block_exit_at(uc_engine *uc, uint64_t address, uint32_t size, void *user_data);
void do_exit(uc_engine * uc, uc_err err);
void force_crash(uc_engine *uc, uc_err error);
void add_exit_hook(exit_hook_t hook);
uc_err load_fuzz(const char *path);

/**
 * Returns 0 upon success, 1 if no input is present.
 **/
bool get_fuzz(uc_engine *uc, uint8_t *buf, unsigned int size);

/**
 * Version handing out a pointer into the fuzz input buffer instead of copying contents.
 * One use case for this is to avoid excessive copying on the c->python boundary.
 **/
uint8_t *get_fuzz_ptr(uc_engine *uc, uint32_t size);

/**
 * Get the current number of fuzzing bytes consumed
 **/
uint32_t fuzz_consumed();
uint32_t fuzz_remaining();

uint32_t get_latest_mmio_fuzz_access_size();
uint32_t get_latest_mmio_fuzz_access_index();

uc_err init(uc_engine *uc, exit_hook_t p_exit_hook, int p_num_mmio_regions, uint64_t *p_mmio_starts, uint64_t *p_mmio_ends, void *p_py_default_mmio_user_data, uint32_t num_exit_at_bbls, uint64_t *exit_at_bbls, uint32_t p_exit_at_hit_limit, int p_do_print_exit_info, int p_do_print_fork_child_output, uint64_t p_fuzz_consumption_timeout, uint64_t p_instr_limit, snapshot_take_handler_t py_snapshot_take_handler, snapshot_restore_handler_t py_snapshot_restore_handler, snapshot_discard_handler_t py_snapshot_discard_handler);
uc_err add_mmio_region(uc_engine *uc, uint64_t begin, uint64_t end);
uc_err add_mmio_subregion_handler(uc_engine *uc, uc_cb_hookmem_t callback, uint64_t start, uint64_t end, uint32_t pc, void *user_data);
uc_err add_unmapped_mem_hook(uc_engine *uc);
uc_err add_debug_hooks(uc_engine *uc);
uc_err register_py_handled_mmio_ranges(uc_engine *uc, uc_cb_hookmem_t py_callback, uint64_t *starts, uint64_t *ends, int num_ranges);
uc_err register_py_handled_device_regions(devmem_access_cb_t py_mmio_callback, uint64_t *starts, uint64_t *ends, int num_regions);
uc_err register_linear_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *init_vals, uint32_t *steps, int num_ranges);
uc_err register_constant_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *vals, int num_ranges);
uc_err register_bitextract_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint8_t *byte_sizes, uint8_t *left_shifts, uint32_t *masks, int num_ranges);
uc_err register_value_set_mmio_models(uc_engine *uc, uint64_t *starts, uint64_t *ends, uint32_t *pcs, uint32_t *value_nums, uint32_t **value_lists, int num_ranges);
uc_err set_ignored_mmio_addresses(uint64_t *addresses, uint32_t *pcs, int num_addresses);
uc_err remove_function_handler_hook_address(uc_engine *uc, uint64_t address);

/**
 * Make the c-callable python function known that distributes python-based, single-address callbacks
 *
 * The hook indirection is used instead of direct uc.hook_add hooks to avoid growing and translation
 * blocks which could change the emulator behavior when hooks are inserted depending on emulator arguments
 * (e.g., for debug hooks).
 **/
uc_err register_cond_py_handler_hook(uc_engine *uc, uc_cb_hookcode_t py_callback, void *user_data);

/**
 * Add an actual c-callable python callback (which gets distributed via the python hook set via register_cond_py_handler_hook)
 **/
uc_err add_py_hooked_block_addr(uc_engine * uc, uint64_t address);
uc_err remove_py_hooked_block_addr(uc_engine * uc, uint64_t address);

uc_err emulate(uc_engine *uc, char *p_input_path, char *prefix_input_path);
#endif
