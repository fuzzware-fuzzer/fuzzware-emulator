#include "cortexm_nvic.h"

// We implement recalculating states lazily, but can disable that behavior
// #define DISABLE_LAZY_RECALCS

// We may not want to allow nested interrupts
#define DISABLE_NESTED_INTERRUPTS
// We can react to interrupt-related MMIO writes from the access handler
#define DISABLE_IMMEDIATE_MMIOWRITE_RESPONSE

// We are allowing SVC to be activated more leniently
#define FORCE_SVC_ACTIVATION
#define SKIP_CHECK_SVC_ACTIVE_INTERRUPT_PRIO

// 0. Constants
// Some Cortex M3 specific constants
uint32_t EXCEPT_MAGIC_RET_MASK = 0xfffffff0;
#define NVIC_VTOR_NONE 0xffffffff
#define NVIC_NONE_ACTIVE 0

#define NUM_SAVED_REGS 8

const uint8_t nvic_id[] = {
    0x00, 0xb0, 0x1b, 0x00, 0x0d, 0xe0, 0x05, 0xb1
};

static int saved_reg_ids[NUM_SAVED_REGS] = {
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
    UC_ARM_REG_R12, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_XPSR
};

#define NUM_SAVED_HARDFP_REGS 17
static int saved_hardfp_reg_ids[NUM_SAVED_HARDFP_REGS] = {
    UC_ARM_REG_S0, UC_ARM_REG_S1, UC_ARM_REG_S2, UC_ARM_REG_S3,
    UC_ARM_REG_S4, UC_ARM_REG_S5, UC_ARM_REG_S6, UC_ARM_REG_S7,
    UC_ARM_REG_S8, UC_ARM_REG_S9, UC_ARM_REG_S10, UC_ARM_REG_S11,
    UC_ARM_REG_S12, UC_ARM_REG_S13, UC_ARM_REG_S14, UC_ARM_REG_S15,
    UC_ARM_REG_FPSCR
};

// 1. Static (after initialization) configs
uc_hook nvic_block_hook_handle = -1, nvic_exception_return_hook_handle=-1,
    hook_mmio_write_handle = -1, hook_mmio_read_handle = -1, hook_svc_handle = -1;
uint32_t *reg_curr_sp_mode_is_psp_ptr = NULL;   // UC_ARM_REG_CURR_SP_MODE_IS_PSP
uint8_t prio_mask = 0xff; // Default value for 8 prio bits
uint32_t interrupt_limit = 0;
uint32_t num_config_disabled_interrupts = 0;
uint32_t *config_disabled_interrupts = NULL;
uint32_t intlinesnum = INTLINESNUM;
int do_print_nvic_log = false; // This is set externally by debug log enabling
bool enable_hardfp = false;

interrupt_pending_allowed_cb_t interrupt_pending_allowed_cb;
interrupt_entry_cb_t interrupt_entry_cb;
interrupt_exit_cb_t interrupt_exit_cb;

// 2. Transient variables (not required to be included in state restore)
static struct {
    uint32_t r0, r1, r2, r3, r12, lr, pc_retaddr, xpsr_retspr;
} saved_regs;
#define BASIC_FRAME_SIZE (NUM_SAVED_REGS * sizeof(uint32_t))

static struct {
    uint32_t s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, fpscr, RESERVED;
} saved_hardfp_regs;
#define EXTENDED_FRAME_SIZE ((NUM_SAVED_HARDFP_REGS + 1) * sizeof(uint32_t))

static uint32_t *saved_reg_ptrs[NUM_SAVED_REGS] = {
    &saved_regs.r0,
    &saved_regs.r1, &saved_regs.r2,
    &saved_regs.r3, &saved_regs.r12,
    &saved_regs.lr, &saved_regs.pc_retaddr,
    &saved_regs.xpsr_retspr
};

static uint32_t *saved_hardfp_reg_ptrs[NUM_SAVED_HARDFP_REGS + 1] = {
    &saved_hardfp_regs.s0, &saved_hardfp_regs.s1,
    &saved_hardfp_regs.s2, &saved_hardfp_regs.s3,
    &saved_hardfp_regs.s4, &saved_hardfp_regs.s5,
    &saved_hardfp_regs.s6, &saved_hardfp_regs.s7,
    &saved_hardfp_regs.s8, &saved_hardfp_regs.s9,
    &saved_hardfp_regs.s10, &saved_hardfp_regs.s11,
    &saved_hardfp_regs.s12, &saved_hardfp_regs.s13,
    &saved_hardfp_regs.s14, &saved_hardfp_regs.s15,
    &saved_hardfp_regs.fpscr, &saved_hardfp_regs.RESERVED
};


// 3. Dynamic State (required for state restore)
struct CortexmNVIC nvic __attribute__ ((aligned (64))) = {
    .prev_basepri = -1
};

/*
 * Access wrappers for interrupt-related registers
 */
static inline uint8_t GET_PRIMASK() {
    return *nvic.reg_daif_ptr & CPSR_IRQ_MASK_BIT;
}

static inline int32_t GET_BASEPRI() {
    return *nvic.reg_basepri_ptr;
}

// Versions of the above that assume an existing NVIC pointer
static inline uint8_t GET_PRIMASK_NVIC(struct CortexmNVIC *p_nvic) {
    return *p_nvic->reg_daif_ptr & CPSR_IRQ_MASK_BIT;
}

static inline int32_t GET_BASEPRI_NVIC(struct CortexmNVIC *p_nvic) {
    return *p_nvic->reg_basepri_ptr;
}

static inline uint32_t GET_CURR_SP_MODE_IS_PSP () {
    return *reg_curr_sp_mode_is_psp_ptr;
}

static inline bool IS_HARDFP_ENABLED(uc_engine *uc) {
    uint32_t fpexc;
    uc_reg_read(uc, UC_ARM_REG_FPEXC, &fpexc);
    return (fpexc & 0x40000000) == 0x40000000;
}

#define is_exception_ret(pc) ((pc & EXCEPT_MAGIC_RET_MASK) == EXCEPT_MAGIC_RET_MASK)


// Forward declarations
static void ExceptionEntry(uc_engine *uc, bool is_tail_chained, bool skip_instruction);

// Armv7-M ARM B1.5.8
static int get_group_prio(int raw_prio) {
    return raw_prio & nvic.group_prio_mask;
}

// B1.5.4
static int get_boosted_prio(int raw_prio) {
    if(GET_PRIMASK()
    #ifdef FORCE_SVC_ACTIVATION
        && nvic.pending_irq != EXCEPTION_NO_SVC
    #endif
    ) {
        return 0;
    }

    int basepri = GET_BASEPRI();
    if(basepri != 0) {
        basepri = get_group_prio(basepri);
        return min(basepri, raw_prio);
    } else {
        return raw_prio;
    }
}

static bool pending_exception_can_be_activated() {
    #ifdef DEBUG_NVIC
    printf("[NVIC] pending_exception_can_be_activated: nvic.pending_prio < get_boosted_prio(nvic.active_group_prio)? %d < %d ? -> %d\n", nvic.pending_prio, get_boosted_prio(nvic.active_group_prio), nvic.pending_prio < get_boosted_prio(nvic.active_group_prio)); fflush(stdout);
    #endif

    #ifdef DISABLE_NESTED_INTERRUPTS
    if(nvic.active_irq != NVIC_NONE_ACTIVE) {
        #ifdef DEBUG_NVIC
        puts("Already in handler, short-cutting exec prio to 0 to disable nesting/preemption."); fflush(stdout);
        #endif
        return 0;
    }
    #endif

    return nvic.pending_prio < get_boosted_prio(nvic.active_group_prio);
}

/*
 * Re-calculate nvic interrupt prios and indicate whether
 * things have changed (i.e., a higher-prio interrupt is now pending).
 */
static bool recalc_prios() {
    int highest_pending_prio = 256;
    int num_active = 0;

    // Track the raw active prio before priority boosting (masking / basepri)
    int highest_active_group_prio = 256;
    int highest_pending_irq = EXCEPTION_NONE_ACTIVE;

    for(int i = EXCEPTION_NO_SVC; i <= nvic.highest_ever_enabled_exception_no; ++i) {
        int curr_prio = nvic.ExceptionPriority[i];

        // IPSR values of the exception handlers
        if(nvic.ExceptionActive[i]) {
            ++num_active;
            if (curr_prio < highest_active_group_prio) {
                // Increase to flag group prio (highest subprio)
                highest_active_group_prio = get_group_prio(curr_prio);
            }
        }

        if(nvic.ExceptionPending[i]) {
            if (curr_prio < highest_pending_prio) {
                #ifdef DEBUG_NVIC
                printf("[recalc_prios] curr_prio < highest_pending_prio for irq %d: curr: %d < new highest: %d\n", i, curr_prio, highest_pending_prio);
                #endif

                // We are tracking the full pending prio here to be able to
                // check whether we actually need updates elsewhere
                highest_pending_prio = curr_prio;
                highest_pending_irq = i;
            }
        }
    }

    nvic.num_active = num_active;

    bool pending_prio_now_surpasses_active =
        // Pending previously not higher prio
        !(nvic.pending_prio < nvic.active_group_prio) &&
        // But now higher prio
        highest_pending_prio < highest_active_group_prio;

    // Now update the prio info
    nvic.active_group_prio = highest_active_group_prio;
    nvic.pending_prio = highest_pending_prio;
    nvic.pending_irq = highest_pending_irq;

    /* HACK: We are abusing the prev_basepri field here to make
     * the unconditional block hook hot path aware of changes.
     */
    if(pending_prio_now_surpasses_active) {
        nvic.prev_basepri = -1;
    }

    return pending_prio_now_surpasses_active;
}

bool is_disabled_by_config(uint32_t exception_no) {
    for(int i = 0; i < num_config_disabled_interrupts; ++i) {
        if(config_disabled_interrupts[i] == exception_no) {
            return true;
        }
    }

    return false;
}

void pend_interrupt(uc_engine *uc, int exception_no) {
    #ifdef DEBUG_NVIC
    printf("[pend_interrupt] exception_no=%d\n", exception_no);
    fflush(stdout);
    #endif
    if(nvic.ExceptionPending[exception_no] == 0) {
        nvic.ExceptionPending[exception_no] = 1;

        #ifndef DISABLE_LAZY_RECALCS
        // we only need to update if we pend a high-prio or a lower same-prio interrupt
        if(exception_no < nvic.pending_irq ||
            nvic.ExceptionPriority[exception_no] < nvic.pending_prio) {
        #endif
            recalc_prios();
        #ifndef DISABLE_LAZY_RECALCS
        }
        #endif
    }
}

static void maybe_activate(uc_engine *uc, bool skip_instruction) {
    #ifdef DEBUG_NVIC
    printf("[maybe_activate] skip_instruction: %d\n", skip_instruction);
    #endif

    /*
     * We only activate an exception (preempt running exception or freshly activate)
     * in case we have a higher-prio exception (post boosting) pended.
     */
    if(pending_exception_can_be_activated()) {
        ExceptionEntry(uc, false, skip_instruction);
    }
}

void clear_pend_interrupt(uc_engine *uc, int exception_no) {
    if(nvic.ExceptionPending[exception_no] == 1) {
        nvic.ExceptionPending[exception_no] = 0;

        #ifndef DISABLE_LAZY_RECALCS
        // We only need to update if we clear the currently pending interrupt
        if(nvic.pending_irq == exception_no) {
        #endif
            recalc_prios();
        #ifndef DISABLE_LAZY_RECALCS
        }
        #endif
    }
}

// Armv7-M ARM B3.4.3
void hook_nvic_mmio_read(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    uint32_t access_offset = addr - NVIC_BASE;
    // Caution: Implicit bounds check here
    uint32_t base_ind = EXCEPTION_NO_EXTERNAL_START + ((access_offset & NVIC_REGISTER_OFFSET_MASK) * 8);
    uint32_t out_val = 0;

    // Interrupt Set-Enable Registers
    // NVIC register read
    switch (access_offset & 0x780) {
        case NVIC_IREG_RANGE(NVIC_ISER): // Interrupt Set-Enable Registers
            // Both NVIC_ISER and NVIC_ICER reads yield enabled flags.
        case NVIC_IREG_RANGE(NVIC_ICER): // Interrupt Clear-Enable Registers
            for(int i = size * 8 - 1; i >= 0; --i) {
                out_val <<= 1;
                out_val |= nvic.ExceptionEnabled[base_ind + i];
            }
            uc_mem_write(uc, addr, &out_val, size);
            break;
        case NVIC_IREG_RANGE(NVIC_ISPR): // Interrupt Set-Pending Registers
            // Both NVIC_ISPR and NVIC_ICPR reads yield pending flags.
        case NVIC_IREG_RANGE(NVIC_ICPR): // Interrupt Clear-Pending Registers
            for(int i = size * 8 - 1; i >= 0; --i) {
                out_val <<= 1;
                out_val |= nvic.ExceptionPending[base_ind + i];
            }
            uc_mem_write(uc, addr, &out_val, size);
            break;
        case NVIC_IREG_RANGE(NVIC_IABR): // Interrupt Active Bit Registers+
            for(int i = size * 8 - 1; i >= 0; --i) {
                out_val <<= 1;
                out_val |= nvic.ExceptionActive[base_ind * 4 + i];
            }
            uc_mem_write(uc, addr, &out_val, size);
            break;
        case NVIC_IPR_RANGE(NVIC_IPR): // Interrupt Priority Registers
            base_ind = EXCEPTION_NO_EXTERNAL_START + ((access_offset - NVIC_IPR) & 0x1ff);
            if(base_ind <= NVIC_NUM_SUPPORTED_INTERRUPTS - 4) {
                for(int i = size-1; i >= 0; --i) {
                    out_val <<= 8;
                    out_val |= nvic.ExceptionPriority[base_ind + i];
                }
                uc_mem_write(uc, addr, &out_val, size);
            }
            break;
        default:
            break;
    }
}

static bool enable_irq(uc_engine *uc, int to_be_enabled) {
    /*
     * Enable an irq and return whether an nvic prio recalc is required.
     *
     * Assumes that to_be_enabled is a valid exception index.
     */
    if(nvic.ExceptionEnabled[to_be_enabled] != 1 && !is_disabled_by_config(to_be_enabled)) {
        nvic.ExceptionEnabled[to_be_enabled] = 1;

        if(to_be_enabled > nvic.highest_ever_enabled_exception_no) {
            nvic.highest_ever_enabled_exception_no = to_be_enabled;
        }

        // Take note of the interrupt number choice for fuzzing
        if(to_be_enabled >= EXCEPTION_NO_EXTERNAL_START) {
            int i = 0;
            // Add it in in a sorted manner in case we preserve previous behavior
            for(; i < nvic.num_enabled; ++i) {
                if(nvic.enabled_irqs[i] > to_be_enabled) {
                    memmove(&nvic.enabled_irqs[i+1], &nvic.enabled_irqs[i], (nvic.num_enabled-i) * sizeof(nvic.enabled_irqs[0]));
                    break;
                }
            }
            nvic.enabled_irqs[i] = to_be_enabled;
            ++nvic.num_enabled;

            // The alternative implementation which does not preserve ordering would be:
            // Add at the end of the list
            // nvic.enabled_irqs[nvic.num_enabled++] = to_be_enabled;
        }

        #ifdef DISABLE_LAZY_RECALCS
        return true;
        #else
        // We need to update in case we enabled a pending, high-prio exception
        return nvic.ExceptionPending[to_be_enabled] &&
            nvic.ExceptionPriority[to_be_enabled] < nvic.pending_irq;
        #endif
    }
    return false;
}

static void remove_fuzzable_interrupt_no(int to_be_removed) {
    /*
     * Remove the an irq from the ones available to fuzzing
     */
    for(int i = 0; i < nvic.num_enabled; ++i) {
        if(nvic.enabled_irqs[i] == to_be_removed) {
            // Remove it while maintaining a sorted list if we are backward compatible
            memmove(&nvic.enabled_irqs[i], &nvic.enabled_irqs[i+1], (nvic.num_enabled-i-1) * sizeof(nvic.enabled_irqs[0]));

            // The alternative implementation which does not preserve ordering would be:
            // Copy the end of the list into the blank space and shrink the list.
            // nvic.enabled_irqs[i] = nvic.enabled_irqs[nvic.num_enabled];

            --nvic.num_enabled;
            return;
        }
    }

    /*
     * We assume that we are only removing one which is actually present.
     * If not, we need to know about it.
     */
    assert(false);
}

static bool disable_irq(uc_engine *uc, int to_be_disabled) {
    /*
     * Disable an irq and return whether an nvic prio recalc is required.
     *
     * Assumes that to_be_enabled is a valid exception index.
     */
    if(nvic.ExceptionEnabled[to_be_disabled] != 0) {
        nvic.ExceptionEnabled[to_be_disabled] = 0;

        // Unregister the interrupt number choice from fuzzing
        remove_fuzzable_interrupt_no(to_be_disabled);

        #ifdef DISABLE_LAZY_RECALCS
        return true;
        #else
        // We only need to update if we disable the pending interrupt
        return to_be_disabled == nvic.pending_irq;
        #endif
    }
    return false;
}

/*
 * Sets the prigroup fields from a given prigroup value.
 * prigroup itself is a shift amount which determines
 * group prio and sub prio masks.
 */
static void set_prigroup(uint8_t new_prigroup) {
    nvic.prigroup_shift = new_prigroup;
    nvic.sub_prio_mask = (2 << new_prigroup) - 1;
    nvic.group_prio_mask = ~nvic.sub_prio_mask;
}

static bool set_prio(int to_be_prio_changed, int new_prio) {
    /*
     * Set priority and return whether an nvic prio recalc is required.
     */
    new_prio &= prio_mask;

    if(new_prio != nvic.ExceptionPriority[to_be_prio_changed] && !is_disabled_by_config(to_be_prio_changed)) {
        #ifdef DEBUG_NVIC
        printf("[NVIC] set priority for %d -> %d\n", to_be_prio_changed, new_prio); fflush(stdout);
        #endif
        nvic.ExceptionPriority[to_be_prio_changed] = new_prio;

        // We have to update in different cases here, so just do it in any case
        // Cases to update:
        // 1. active and changing active group prio
        // 2. enabled && pending && changing pending prio ()
        // 3. ?
        return true;
    }
    return false;
}

void hook_nvic_mmio_write(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    uint32_t access_offset = addr - NVIC_BASE;
    // Caution: Implicit bounds check here
    uint32_t base_ind = EXCEPTION_NO_EXTERNAL_START + ((access_offset & NVIC_REGISTER_OFFSET_MASK) * 8);
    bool need_update = false;

    #ifdef DEBUG_NVIC
    printf("[NVIC] hook_nvic_mmio_write: Write to %08lx, value: %08lx\n", addr, value);
    fflush(stdout);
    #endif

    // NVIC register write
    switch (access_offset & 0x780) {
        case NVIC_IREG_RANGE(NVIC_ISER): // Interrupt Set-Enable Registers
            #ifdef DEBUG_NVIC
            printf("[NVIC] hook_nvic_mmio_write: NVIC_ISER\n"); fflush(stdout);
            #endif
            for(int i = 0; i < size * 8; ++i) {
                if((value & 1)) {
                    int to_be_enabled = base_ind + i;
                    #ifdef DEBUG_NVIC
                    printf("[NVIC] NVIC_ISER: got enabled bit at i=%d. to_be_enabled = %d\n", i, to_be_enabled); fflush(stdout);
                    #endif

                    need_update |= enable_irq(uc, to_be_enabled);
                }
                value >>= 1;
            }

            if(need_update) {
                recalc_prios();
            }
            break;
        case NVIC_IREG_RANGE(NVIC_ICER): // Interrupt Clear-Enable Registers
            #ifdef DEBUG_NVIC
            printf("[NVIC] hook_nvic_mmio_write: NVIC_ICER\n"); fflush(stdout);
            #endif
            for(int i = 0; i < size * 8; ++i) {
                if((value & 1)) {
                    int to_be_disabled = base_ind + i;

                    need_update |= disable_irq(uc, to_be_disabled);
                }
                value >>= 1;
            }

            if(need_update) {
                recalc_prios();
            }
            break;
        case NVIC_IREG_RANGE(NVIC_ISPR): // Interrupt Set-Pending Registers
            #ifdef DEBUG_NVIC
            printf("[NVIC] hook_nvic_mmio_write: NVIC_ISPR\n"); fflush(stdout);
            #endif
            for(int i = 0; i < size * 8; ++i) {
                if((value & 1)) {
                    uint32_t to_pend = base_ind + i;
                    if(!is_disabled_by_config(to_pend)) {
                        // We may want to directly react to such writes.
                        #ifdef DISABLE_IMMEDIATE_MMIOWRITE_RESPONSE
                        pend_interrupt(uc, to_pend);
                        #else
                        pend_from_mem_write(uc, to_pend);
                        #endif
                    }
                }
                value >>= 1;
            }
            break;
        case NVIC_IREG_RANGE(NVIC_ICPR): // Interrupt Clear-Pending Registers
            #ifdef DEBUG_NVIC
            printf("[NVIC] hook_nvic_mmio_write: NVIC_ICPR\n"); fflush(stdout);
            #endif
            for(int i = 0; i < size * 8; ++i) {
                if((value & 1)) {
                    clear_pend_interrupt(uc, base_ind + i);
                }
                value >>= 1;
            }
            break;
        case NVIC_IREG_RANGE(NVIC_IABR): // Interrupt Active Bit Registers
            // Read-only register: ignore
            break;
        case NVIC_IPR_RANGE(NVIC_IPR): // Interrupt Priority Registers
            #ifdef DEBUG_NVIC
            printf("[NVIC] hook_nvic_mmio_write: NVIC_IPR\n"); fflush(stdout);
            #endif
            base_ind = EXCEPTION_NO_EXTERNAL_START + ((access_offset - NVIC_IPR) & 0x1ff);

            if(base_ind <= NVIC_NUM_SUPPORTED_INTERRUPTS - 4) {
                for(int i = 0; i < size; ++i) {
                    uint8_t new_prio = value;
                    uint8_t to_be_prio_changed = base_ind + i;

                    need_update |= set_prio(to_be_prio_changed, new_prio);
                    value >>= 8;
                }

                if(need_update) {
                    recalc_prios();
                }
            }
            break;
        default:
            break;
    }
}

static uint32_t calc_icsr() {
    uint32_t res = 0;

    // ISRPREEMPT
    // debug state register, which we don't support

    // ISRPENDING
    // this is not the exact semantic, but we give some indication
    // (highest irq does not need to be external, could be SYSTICK / PENDSV)
    res |= (nvic.pending_irq > EXCEPTION_NO_SYSTICK) << SCB_ICSR_ISRPENDING_Pos;

    // VECTPENDING
    res |= (nvic.pending_irq << SCB_ICSR_VECTPENDING_Pos) & SCB_ICSR_VECTPENDING_Msk;

    // RETTOBASE
    res |= (nvic.num_active <= 1) << SCB_ICSR_RETTOBASE_Pos;

    // VECTACTIVE
    res |= nvic.active_irq & SCB_ICSR_VECTACTIVE_Msk;
    return res;
}

void hook_sysctl_mmio_read(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    #ifdef DEBUG_NVIC
    value = 0;
    uc_mem_read(uc, addr, &value, size);
    printf("[NVIC] hook_sysctl_mmio_read: Read from %08lx, raw value: %08lx\n", addr, value);
    fflush(stdout);
    #endif
    
    if(addr >= SYSTICK_BASE && addr <= SYSTICK_END) {
        hook_syst_mmio_read(uc, type, addr, size, value, user_data);
        return;
    } else if (addr >= NVIC_MMIO_BASE && addr <= NVIC_MMIO_END) {
        hook_nvic_mmio_read(uc, type, addr, size, value, user_data);
        return;
    }

    uint32_t out_val = 0, base_ind;

    switch(addr & ~3) {
        case SYSCTL_ICTR: // Interrupt Controller Type Register
            // number of supported interrupts
            uc_mem_write(uc, addr, &intlinesnum, sizeof(intlinesnum));
            break;
        case SYSCTL_ICSR: // Interrupt Control and State Register
            out_val = calc_icsr();
            uc_mem_write(uc, addr, &out_val, sizeof(out_val));
            break;
        case SYSCTL_VTOR: // Vector Table Offset Register
            // NOP: fall through to normal read
            break;
        case SYSCTL_AIRCR: // Application Interrupt and Reset Control Register.
            out_val = VECTKEY_HIWORD_MAGIC_READ;
            // Implicit: little endian
            // out_val |= 0 << SCB_AIRCR_ENDIANESS_Pos;
            out_val |= nvic.prigroup_shift << SCB_AIRCR_PRIGROUP_Pos;
            #ifdef DEBUG_NVIC
            printf("Generated out_val for SYSCTL_AIRCR: %#010x\n", out_val); fflush(stdout);
            #endif
            uc_mem_write(uc, addr, &out_val, sizeof(out_val));
            break;
        case SYSCTL_STIR: // Software Triggered Interrupt Register
            // Ignore, write-only
            break;
        case SYSCTL_SHCSR: // System Handler Control and State Register
            // NOT IMPLEMENTED
            break;
        case SYSCTL_SHPR1 ... SYSCTL_SHPR3+3: // System Handler Priority Register 1
            if (addr + size > SYSCTL_SHPR3+4)
                break;

            // Handle priorities for exceptions 4-15
            base_ind = 4 + (addr - SYSCTL_SHPR1);

            for(int i = size-1; i >= 0; --i) {
                out_val <<= 8;
                out_val |= nvic.ExceptionPriority[base_ind + i];
            }

            uc_mem_write(uc, addr, &out_val, size);
            break;
        case SYSCTL_CPACR:
            break;
        default:
            break;

    }
}

static void pend_from_mem_write(uc_engine *uc, int exception_no) {
    /*
    * For write-based register pends, we need an immediate activation
    * We also need to skip the currently executing write
    * instruction, as we would return to another write
    * otherwise
    */
    pend_interrupt(uc, exception_no);
    maybe_activate(uc, true);
}

static void handle_icsr_write(uc_engine *uc, uint32_t value) {
    if(value & SCB_ICSR_PENDSVSET_Msk) {
        pend_from_mem_write(uc, EXCEPTION_NO_PENDSV);
    }

    if(value & SCB_ICSR_PENDSVCLR_Msk) {
        clear_pend_interrupt(uc, EXCEPTION_NO_PENDSV);
    }

    if(value & SCB_ICSR_PENDSTSET_Msk) {
        pend_from_mem_write(uc, EXCEPTION_NO_SYSTICK);
    }

    if(value & SCB_ICSR_PENDSTCLR_Msk) {
        clear_pend_interrupt(uc, EXCEPTION_NO_SYSTICK);
    }

    if(value & SCB_ICSR_NMIPENDSET_Msk) {
        pend_interrupt(uc, EXCEPTION_NO_NMI);
    }
}

static void handle_aircr_write(uc_engine *uc, uint32_t value) {
    // VECTCLRACTIVE: Only valid in debug state, which we don't support
    // VECTRESET: Only valid in debug state, which we don't support
    if(value & SCB_AIRCR_SYSRESETREQ_Msk) {
        if(do_print_exit_info) {
            puts("SYSCTL_AIRCR write indicated system reset, stopping emulation");
        }
        do_exit(uc, UC_ERR_OK);
    }

    // PRIGROUP
    uint32_t new_prigroup = (value & SCB_AIRCR_PRIGROUP_Msk) >> SCB_AIRCR_PRIGROUP_Pos;
    if(new_prigroup != nvic.prigroup_shift) {
        #ifdef DEBUG_NVIC
        printf("[NVIC] SYSCTL_AIRCR write: Setting prigroup to new value. Old value: %#04x, new value: %#04x\n", new_prigroup, nvic.prigroup_shift);
        fflush(stdout);
        #endif
        set_prigroup(new_prigroup);

        recalc_prios();
    }
    #ifdef DEBUG_NVIC
    else {
        printf("[NVIC] SYSCTL_AIRCR write: extracted prigroup %x from value %08x. It stayed the same.\n", new_prigroup, value); fflush(stdout);
    }
    #endif
}

void hook_sysctl_mmio_write(uc_engine *uc, uc_mem_type type,
                      uint64_t addr, int size, int64_t value, void *user_data) {
    #ifdef DEBUG_NVIC
    printf("[NVIC] hook_sysctl_mmio_write: Write to %08lx, value: %08lx\n", addr, value);
    fflush(stdout);
    #endif

    if(addr >= SYSTICK_BASE && addr <= SYSTICK_END) {
        hook_syst_mmio_write(uc, type, addr, size, value, user_data);
        return;
    } else if (addr >= NVIC_MMIO_BASE && addr <= NVIC_MMIO_END) {
        hook_nvic_mmio_write(uc, type, addr, size, value, user_data);
        return;
    }

    uint32_t to_pend, base_ind;

    switch(addr & ~3) {
        case SYSCTL_ICTR: // Interrupt Controller Type Register
            // Ignore, read-only
            break;
        case SYSCTL_ICSR: // Interrupt Control and State Register
            handle_icsr_write(uc, value);
            break;
        case SYSCTL_VTOR: // Vector Table Offset Register
            nvic.vtor = value;
            break;
        case SYSCTL_AIRCR: // Application Interrupt and Reset Control Register.
            if((value & 0xffff0000u) == VECTKEY_HIWORD_MAGIC_WRITE) {
                // Valid key, process write
                handle_aircr_write(uc, value);
            }
            break;
        case SYSCTL_CCR: // Configuration and Control Register
            break;
        case SYSCTL_STIR: // Software Triggered Interrupt Register
            to_pend = EXCEPTION_NO_EXTERNAL_START + (value & 0xff);
            if(to_pend < EXCEPTION_NO_MAX && !is_disabled_by_config(to_pend)) {
                pend_from_mem_write(uc, to_pend);
            }
            break;
        case SYSCTL_SHCSR: // System Handler Control and State Register
            break;
        case SYSCTL_SHPR1 ... SYSCTL_SHPR3+3: // System Handler Priority Register 1-3
            if(addr + size > SYSCTL_SHPR3+4)
                break;

            bool need_update = false;
            // Handle priorities for exceptions 4-15
            base_ind = 4 + (addr - SYSCTL_SHPR1);

            for(int i = 0; i < size; ++i) {
                uint8_t new_prio = value;
                uint8_t to_be_prio_changed = base_ind + i;

                need_update |= set_prio(to_be_prio_changed, new_prio);
                value >>= 8;
            }

            if(need_update) {
                recalc_prios();
            }
            break;
        case SYSCTL_CPACR:
            uc_reg_write(uc, UC_ARM_REG_C1_C0_2, &value);
            if (enable_hardfp) {
                int32_t fpexc = (value & 0xf00000) == 0xf00000 ? 0x40000000 : 0;
                uc_reg_write(uc, UC_ARM_REG_FPEXC, &fpexc);
            }
            break;
        default:
            break;
    }
}

// Armv7-M ARM B1.5.8
void PopStack(uc_engine *uc) {
    bool hardfp_enabled = IS_HARDFP_ENABLED(uc);
    uint32_t frameptr;
    uc_reg_read(uc, UC_ARM_REG_SP, &frameptr);
    uc_err err;

    #ifdef DEBUG_NVIC
    puts("************ PRE PopStack");
    print_state(uc);
    #endif

    if((err = uc_mem_read(uc, frameptr, &saved_regs, BASIC_FRAME_SIZE)) != UC_ERR_OK) {
        if(do_print_exit_info) {
            printf("[NVIC] PopStack: reading saved basic context frame during interrupt exit failed for frameptr= 0x%08x: (%s)\n", frameptr, uc_strerror(err));
            fflush(stdout);
        }

        force_crash(uc, err);
    }
    frameptr += BASIC_FRAME_SIZE;

    if (hardfp_enabled) {
        if((err = uc_mem_read(uc, frameptr, &saved_hardfp_regs, EXTENDED_FRAME_SIZE)) != UC_ERR_OK) {
            if(do_print_exit_info) {
                printf("[NVIC] PopStack: reading saved extended context frame during interrupt exit failed for frameptr= 0x%08x: (%s)\n", frameptr, uc_strerror(err));
                fflush(stdout);
            }

            force_crash(uc, err);
        }
        frameptr += EXTENDED_FRAME_SIZE;
    }

    // Re-align the stack
    if ((saved_regs.xpsr_retspr & (1 << 9)) != 0)
    {
        frameptr += 4;
    }

    // Restore registers
    if((err = uc_reg_write_batch(uc, &saved_reg_ids[0], (void **)(&saved_reg_ptrs[0]), NUM_SAVED_REGS)) != UC_ERR_OK){
        if(do_print_exit_info) {
            puts("[NVIC ERROR] PopStack: restoring registers failed\n");
            print_state(uc);
            fflush(stdout);
        }
        force_crash(uc, err);
    }

    if (hardfp_enabled) {
        if ((err = uc_reg_write_batch(uc, &saved_hardfp_reg_ids[0], (void **)(&saved_hardfp_reg_ptrs[0]), NUM_SAVED_HARDFP_REGS)) != UC_ERR_OK){
            if(do_print_exit_info) {
                puts("[NVIC ERROR] PopStack: restoring registers failed\n");
                print_state(uc);
                fflush(stdout);
            }
            force_crash(uc, err);
        }
     }

    if ((err = uc_reg_write(uc, UC_ARM_REG_SP, &frameptr)) != UC_ERR_OK){
        if(do_print_exit_info) {
            puts("[NVIC ERROR] PopStack: restoring registers failed\n");
            print_state(uc);
            fflush(stdout);
        }
        force_crash(uc, err);
    }

    // Restore the stored active irq
    nvic.active_irq = saved_regs.xpsr_retspr & xPSR_ISR_Msk;

    #ifdef DEBUG_NVIC
    puts("************ POST PopStack");
    print_state(uc);
    #endif
}

// B1.5.6
void PushStack(uc_engine *uc, bool skip_instruction) {
    bool hardfp_enabled = IS_HARDFP_ENABLED(uc);
    int frame_size = BASIC_FRAME_SIZE;
    uc_err err;

    #ifdef DEBUG_NVIC
    puts("************ PRE PushStack");
    print_state(uc);
    #endif

    /*
     * Push the pre-exception register stack to the stack.
     * We do not deal with SP_process vs. SP_main here, though.
     * Instead, we use the current SP (which will return whatever
     * the correct value is) and push to that.
     * We assume that the calling function rotates out SP_process
     * when coming from thread mode and SP_process is used.
     */

    // The standard mentions (but deprecates) only guarateeing a
    // 4-byte alignment. We force a 8-byte stack alignment
    uint32_t frameptr, frameptralign;
    uint32_t spmask = ~(1 << 2);

    // Read the registers which are to be pushed afterwards
    if((err = uc_reg_read_batch(uc, &saved_reg_ids[0], (void **)(&saved_reg_ptrs[0]), NUM_SAVED_REGS)) != UC_ERR_OK) {
        if(do_print_exit_info) {
            puts("[NVIC ERROR] PushStack: Failed reading registers\n");
            fflush(stdout);
        }
        force_crash(uc, err);
    }

    if (hardfp_enabled) {
        frame_size += EXTENDED_FRAME_SIZE;

        if((err = uc_reg_read_batch(uc, &saved_hardfp_reg_ids[0], (void **)(&saved_hardfp_reg_ptrs[0]), NUM_SAVED_HARDFP_REGS)) != UC_ERR_OK) {
            if(do_print_exit_info) {
                puts("[NVIC ERROR] PushStack: Failed reading registers\n");
                fflush(stdout);
            }
            force_crash(uc, err);
        }
    }

    if((err = uc_reg_read(uc, UC_ARM_REG_SP, &frameptr)) != UC_ERR_OK) {
        if(do_print_exit_info) {
            puts("[NVIC ERROR] PushStack: Failed reading registers\n");
            fflush(stdout);
        }
        force_crash(uc, err);
    }

    if(skip_instruction) {
        uint64_t insn = 0;
        #ifdef DEBUG_NVIC
        uint32_t prev_pc = saved_regs.pc_retaddr;
        #endif
        uc_mem_read(uc, saved_regs.pc_retaddr, &insn, 2);

        saved_regs.pc_retaddr += get_instruction_size(insn, true);
        #ifdef DEBUG_NVIC
        printf("[PushStack, skip_curr_instruction] adjusted pc from 0x%x to 0x%x\n", prev_pc, saved_regs.pc_retaddr); fflush(stdout);
        #endif
    }

    // Make space for the context frame
    frameptralign = (frameptr & ~spmask) >> 2;
    frameptr -= frame_size;
    frameptr &= spmask;

    // Save the stack pointer with additional space
    uc_reg_write(uc, UC_ARM_REG_SP, &frameptr);

    // Adjust xpsr with alignment info
    saved_regs.xpsr_retspr |= (frameptralign << 9);

    // Push the context frame itself
    if((err = uc_mem_write(uc, frameptr,  &saved_regs, BASIC_FRAME_SIZE)) != UC_ERR_OK){
        if(do_print_exit_info) {
            printf("[NVIC] PopStack: writing saved context frame during interrupt entry failed (INVALID WRITE, frameptr= 0x%08x)\n", frameptr);
            print_state(uc);
            fflush(stdout);
        }
        force_crash(uc, err);
    }

    if (hardfp_enabled) {
        if((err = uc_mem_write(uc, frameptr + BASIC_FRAME_SIZE,  &saved_hardfp_regs, EXTENDED_FRAME_SIZE)) != UC_ERR_OK){
            if(do_print_exit_info) {
                printf("[NVIC] PopStack: writing saved context frame during interrupt entry failed (INVALID WRITE, frameptr= 0x%08x)\n", frameptr);
                print_state(uc);
                fflush(stdout);
            }
            force_crash(uc, err);
        }
    }

    #ifdef DEBUG_NVIC
    puts("************ POST PushStack");
    print_state(uc);
    #endif
}

// B1.5.8
void ExceptionReturn(uc_engine *uc, uint32_t ret_pc) {
    uint32_t ReturningExceptionNumber = nvic.active_irq;

    // Notify peripherals of Exception Exit
    if (interrupt_exit_cb) {
        // printf("[ExceptionReturn] calling interrupt_exit_cb(%d)\n", ReturningExceptionNumber);
        // fflush(stdout);
        interrupt_exit_cb(ReturningExceptionNumber);
    }

    // DeActivate(ReturningExceptionNumber)
    nvic.ExceptionActive[ReturningExceptionNumber] = 0;
    // Unicorn does not seem to handle faultmask
    // unset_faultmask();

    if(ReturningExceptionNumber == NVIC_NONE_ACTIVE) {
        if(do_print_exit_info) {
            puts("[NVIC ERROR] ExceptionReturn: Inconsistent state: no exception is active. This probably means we got here via a corrupted pc...");
            print_state(uc);
            fflush(stdout);
        }

        force_crash(uc, UC_ERR_FETCH_PROT);
        return;
    }

    #ifdef DEBUG_NVIC
    uint32_t sp_mode, other_sp, sp, lr;
    sp_mode = GET_CURR_SP_MODE_IS_PSP();
    uc_reg_read(uc, UC_ARM_REG_OTHER_SP, &other_sp);
    uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);
    printf("[ExceptionReturn] UC_ARM_REG_CURR_SP_MODE_IS_PSP=%d, UC_ARM_REG_OTHER_SP=%08x, UC_ARM_REG_SP=%08x, lr=%08x\n", sp_mode, other_sp, sp, lr); fflush(stdout);
    #endif

    /* 
     * After deactivating the exception, re-calc to see if a
     * pending exception can now be taken.
     */
    recalc_prios();

    if(do_print_nvic_log) {
        printf("=== Interrupt Exit: returning from %d ===\n", ReturningExceptionNumber);fflush(stdout);
    }
    if(interrupt_trace_path) {
        interrupt_trace_add_event(false, ReturningExceptionNumber);
    }

    // Unset the active interrupt to allow active prio to drop
    nvic.active_irq = NVIC_NONE_ACTIVE;
    if(pending_exception_can_be_activated()) {
        // Can we tail-chain?
        ExceptionEntry(uc, true, false);
        return;
    }

    // If we don't tail-chain, we need to pop the current stack state

    // Are we returning to thread mode?
    if(ret_pc & NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG) {
        // Need to change stack to SP_process
        if(ret_pc & NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG) {
            // We are coming from Handler Mode (which always uses SP_main) and
            // return to Thread Mode which uses SP_process. Switch to SP_process
            uint32_t new_SPSEL_now_psp = 1;
            uint32_t SP_process, SP_main;
            uc_reg_read(uc, UC_ARM_REG_SP, &SP_main);
            uc_reg_read(uc, UC_ARM_REG_OTHER_SP, &SP_process);

            // Back up SP_main
            uc_reg_write(uc, UC_ARM_REG_OTHER_SP, &SP_main);
            uc_reg_write(uc, UC_ARM_REG_SP, &SP_process);

            // Switch the CPU state to indicate the new SPSEL state
            // 1. In pstate register
            uc_reg_write(uc, UC_ARM_REG_SPSEL, &new_SPSEL_now_psp);
            // 2. In cached spsel field
            uc_reg_write(uc, UC_ARM_REG_CURR_SP_MODE_IS_PSP, &new_SPSEL_now_psp);
        }
    }

    PopStack(uc);

    if(((ret_pc & NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG) != 0) != (nvic.active_irq == NVIC_NONE_ACTIVE)) {
        if(do_print_exit_info) {
            puts("[ExceptionReturn] expected thread mode return to end up with nvic.active_irq == NVIC_NONE_ACTIVE and vice versa.");
            fflush(stdout);
        }
        force_crash(uc, UC_ERR_FETCH_PROT);
    }
}

// idea: just hook code for the magic is_exception_ret address range
// prerequisites: tail-chaining of interrupts needs to work and the MMIO ranges need to be used
static void nvic_exception_return_hook(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    #ifdef DEBUG_NVIC
    uint32_t lr;
    uc_reg_read(uc, UC_ARM_REG_LR, &lr);
    printf("#################### Returning from interrupt (addr: 0x%lx, lr: 0x%08x)...\n", address, lr); fflush(stdout);
    #endif

    ExceptionReturn(uc, address);

    #ifdef DEBUG_NVIC
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("############## Returned from interrupt. From: 0x%08lx to 0x%08x\n", address, pc); fflush(stdout);
    fflush(stdout);
    #endif
}

static void handler_svc(uc_engine *uc, uint32_t intno, void *user_data) {
    #ifdef DEBUG_NVIC
    uint32_t pc;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("[SVC HOOK %08x] native SVC hook called, intno: %d\n", pc, intno); fflush(stdout);
    #endif

    // Make sure we are actually asked to perform a syscall
    if(intno == 2) {
        #ifndef SKIP_CHECK_SVC_ACTIVE_INTERRUPT_PRIO
        if(nvic.active_group_prio <= nvic.ExceptionPriority[EXCEPTION_NO_SVC]) {
            if(do_print_exit_info) {
                uint32_t pc;
                uc_reg_read(uc, UC_ARM_REG_PC, &pc);
                printf("[SVC HOOK %08x] primask is set, so interrupts are masked. SVC prio: %d. As this would escalate to hardfault, exiting\n", pc, nvic.ExceptionPriority[EXCEPTION_NO_SVC]); fflush(stdout);
            }
            do_exit(uc, UC_ERR_EXCEPTION);
            return;
        }
        #endif
        // SVCs are enabled by default. Just pend the SVC exception here
        pend_interrupt(uc, EXCEPTION_NO_SVC);
        maybe_activate(uc, false);
    } else {
        // Alternatives could be breakpoints and the like, which we do not handle.
        if(do_print_exit_info) {
            uint32_t pc;
            uc_reg_read(uc, UC_ARM_REG_PC, &pc);
            printf("[SVC HOOK %08x] %d is NOT an SVC, exiting\n", pc, intno); fflush(stdout);
        }
        do_exit(uc, UC_ERR_OK);
    }
}

// B1.5.6
static void ExceptionEntry(uc_engine *uc, bool is_tail_chained, bool skip_instruction) {
    uint32_t new_lr = NVIC_INTERRUPT_ENTRY_LR_BASE;

    #ifdef DEBUG_NVIC
    printf("[NVIC] ExceptionEntry(is_tail_chained=%d, skip_instruction=%d)\n", is_tail_chained, skip_instruction); fflush(stdout);
    #endif

    // Bookkeep number of interrupts except SysTick
    if (nvic.pending_irq != EXCEPTION_NO_SYSTICK) {
        if (++nvic.interrupt_count >= interrupt_limit) {
            if(do_print_exit_info) {
                printf("Interrupt activation limit of %d reached, exiting\n", interrupt_limit); fflush(stdout);
            }

            do_exit(uc, UC_ERR_OK);
            return;
        }
    }

    // Notify peripherals of Exception Entry
    if (interrupt_entry_cb) {
        // printf("[ExceptionEntry] calling interrupt_entry_cb(%d)\n", nvic.pending_irq);
        // fflush(stdout);
        interrupt_entry_cb(nvic.pending_irq);
    }

    if (!is_tail_chained) {
        /*
         * We are interrupting execution. We are either preempting an existing interrupt
         * (Handler Mode) or coming from normal execution (Thread Mode). So save frame.
         */
        PushStack(uc, skip_instruction);

        /*
        * Figure out stack pointer to push exception context to:
        * We need to handle the situation where we come from thread mode (no exception being handled),
        * and use the SP_process stack instead of the SP_main stack (which is always used in handler mode).
        */
        if(nvic.active_irq == NVIC_NONE_ACTIVE) {
            // We are coming from Thread mode in case we are not tail-chained and had no previously active IRQ
            new_lr |= NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG;

            if(GET_CURR_SP_MODE_IS_PSP()) {
                // We are coming from Thread Mode which uses SP_process. Switch it to SP_main
                uint32_t new_SPSEL_not_psp = 0;
                uint32_t SP_process, SP_main;
                uc_reg_read(uc, UC_ARM_REG_SP, &SP_process);
                uc_reg_read(uc, UC_ARM_REG_OTHER_SP, &SP_main);

                // Back up SP_process
                uc_reg_write(uc, UC_ARM_REG_OTHER_SP, &SP_process);
                uc_reg_write(uc, UC_ARM_REG_SP, &SP_main);

                // Switch the CPU state to indicate the new SPSEL state
                // 1. In pstate register
                uc_reg_write(uc, UC_ARM_REG_SPSEL, &new_SPSEL_not_psp);
                // 2. In cached spsel field
                uc_reg_write(uc, UC_ARM_REG_CURR_SP_MODE_IS_PSP, &new_SPSEL_not_psp);

                // Finally: Indicate that we switched in the LR value
                new_lr |= NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG;
            }
        }
    } else {
        // Tail Chaining: going from handler mode to handler mode. No stack switching required
        uint32_t prev_lr;
        // If we are chained, maintain the previous lr's SP switch and thread mode bits
        uc_reg_read(uc, UC_ARM_REG_PC, &prev_lr);
        new_lr |= (prev_lr & (NVIC_INTERRUPT_ENTRY_LR_PSPSWITCH_FLAG | NVIC_INTERRUPT_ENTRY_LR_THREADMODE_FLAG));
    }

    // In any case we need to set our new LR
    uc_reg_write(uc, UC_ARM_REG_LR, &new_lr);

    // We inline ExceptionTaken here

    // Find the ISR entry point and set it
    uint32_t ExceptionNumber = nvic.pending_irq;
    uint32_t isr_entry;
    uc_mem_read(uc, nvic.vtor + 4 * ExceptionNumber, &isr_entry, sizeof(isr_entry));
    uc_reg_write(uc, UC_ARM_REG_PC, &isr_entry);

    #ifdef DEBUG_NVIC
    printf("Redirecting irq %d to isr: %08x\n", ExceptionNumber, isr_entry);
    #endif

    if(do_print_nvic_log) {
        printf("=== Interrupt Entry: from %d to %d ===\n", nvic.active_irq, ExceptionNumber);fflush(stdout);
    }
    if(interrupt_trace_path) {
        interrupt_trace_add_event(true, ExceptionNumber);
    }

    // Prepare new XPSR state
    uint32_t isr_xpsr = saved_regs.xpsr_retspr;
    // Reset ITSTATE bits
    isr_xpsr &= ~(xPSR_ICI_IT_2_Msk | xPSR_ICI_IT_1_Msk);
    // Set active interrupt
    isr_xpsr &= ~xPSR_ISR_Msk;
    isr_xpsr |= ExceptionNumber;
    uc_reg_write(uc, UC_ARM_REG_XPSR, &isr_xpsr);

    // Update nvic state with new active interrupt
    nvic.ExceptionActive[ExceptionNumber] = 1;
    nvic.ExceptionPending[ExceptionNumber] = 0;
    nvic.active_irq = ExceptionNumber;

    // We need to re-calculate the pending priority state
    recalc_prios();

    #ifdef DEBUG_NVIC
    puts("************ POST ExceptionEntry");
    print_state(uc);
    #endif
}

//#define NVIC_BLOCK_HOOK_SIMPLE
#ifndef NVIC_BLOCK_HOOK_SIMPLE
__attribute__ ((hot))
static void nvic_block_hook(uc_engine *uc, uint64_t address, uint32_t size, struct CortexmNVIC * arg_nvic) {
    /*
     * This implementation takes the more complex approach of trying to exit early in the common
     * case: If nothing changed on the enabling / base priority sides, just exit.
     */

    /*
     * CAUTION: This runs for every block - so we are on a performance-critical path
     *
     * We first need to check registers which can change without us seeing these changes:
     * 1. primask: Interrupts disabled (interrupts could have been re-enabled)
     * 2. basepri: The base active priority (base priority could have been lowered, such that another interrupt now takes precedence)
     *
     * We also consider whether previous updates are now pending a higher-prio interrupt
     **/

    // 1. Interrupts disabled?
    if (likely(GET_PRIMASK_NVIC(arg_nvic) == 0)) {
        // Interrupts are not disabled
        uint32_t basepri = GET_BASEPRI_NVIC(arg_nvic);

        // Interrupts have previously been entirely disabled
        if(unlikely(arg_nvic->prev_primask))
        {
            #ifdef DEBUG_NVIC
            printf("[NVIC] [tick %lu] Detected change in interrupt enable (new 0x%x vs old 0x%x), calling maybe_activate(uc);\n", get_global_ticker(), GET_PRIMASK(), arg_nvic->prev_primask);
            fflush(stdout);
            #endif

            // We went from interrupts masked to interrupts not masked
            arg_nvic->prev_primask = 0;
            // We need to check actual pending priorities
        } else if (likely(basepri == arg_nvic->prev_basepri) || (basepri != 0 && basepri < arg_nvic->prev_basepri)) {
            arg_nvic->prev_basepri = basepri;

            /*
             * This is the early exit which we expect to take most of the time
             * Not landing here would mean either
             * a) having newly enabled interupts again
             * b) or having lowered the base priority
             */
            return;
        } else {
            // Interrupts are still enabled, and we lowered basepri
            // We need to check actual pending priorities
        }

        #ifdef DEBUG_NVIC
        if(basepri > arg_nvic->prev_basepri) {
            printf("[NVIC] [tick %lu] Detected change in interrupt base priority (new 0x%x vs old 0x%x), calling maybe_activate(uc);\n", get_global_ticker(), basepri, arg_nvic->prev_basepri);
            fflush(stdout);
        }
        #endif
        arg_nvic->prev_basepri = basepri;

        // We know interrupts are still enabled here and we already queried the basepri value.
        // This means we don't need to update prev_primask, it stayed at 0
        // arg_nvic->prev_primask = 0;

        // We are inlining primask/basepri knowledge instead of calling the full maybe_activate
        // maybe_activate(uc, false);

        #ifdef DISABLE_NESTED_INTERRUPTS
        if( arg_nvic->active_irq == NVIC_NONE_ACTIVE) {
        #endif

            int active_group_prio = arg_nvic->active_group_prio;
            if(basepri != 0 && basepri < active_group_prio) {
                active_group_prio = basepri & arg_nvic->group_prio_mask;
            }

            if(arg_nvic->pending_prio < active_group_prio) {
                ExceptionEntry(uc, false, false);
            }

        #ifdef DISABLE_NESTED_INTERRUPTS
        }
        #endif
    } else {
        // primask is set / interrupts are disabled now
        arg_nvic->prev_primask = 1;
    }
}
#else
__attribute__ ((hot))
static void nvic_block_hook(uc_engine *uc, uint64_t address, uint32_t size, struct CortexmNVIC *arg_nvic) {
    /*
     * This implementation takes the simple approach of always re-calculating the current
     * active prio and checking it against the pending prio in case interrupts are enabled.
     */

    int32_t basepri;

    if (likely(GET_PRIMASK_NVIC(arg_nvic) == 0)) {
        #ifdef DISABLE_NESTED_INTERRUPTS
        if( likely(arg_nvic->active_irq == NVIC_NONE_ACTIVE)) {
        #endif

        basepri = GET_BASEPRI_NVIC(arg_nvic);

        int active_group_prio = arg_nvic->active_group_prio;
        if(basepri != 0 && basepri < active_group_prio) {
            active_group_prio = basepri & arg_nvic->group_prio_mask;
        }

        if(unlikely(arg_nvic->pending_prio < active_group_prio)) {
            ExceptionEntry(uc, false, false);
        }

        #ifdef DISABLE_NESTED_INTERRUPTS
        }
        #endif
    }
}
#endif

void *nvic_take_snapshot(uc_engine *uc) {
    size_t size = sizeof(nvic);

    // NVIC snapshot: save the sysreg mem page
    char *result = malloc(size + PAGE_SIZE);
    memcpy(result, &nvic, size);
    uc_mem_read(uc, SYSCTL_START, result + size, PAGE_SIZE);

    return result;
}

void nvic_restore_snapshot(uc_engine *uc, void *snapshot) {
    // Restore the nvic
    memcpy(&nvic, snapshot, sizeof(nvic));
    // Restore the sysreg mem page
    uc_mem_write(uc, SYSCTL_START, ((char *) snapshot) + sizeof(nvic), PAGE_SIZE);
}

void nvic_discard_snapshot(uc_engine *uc, void *snapshot) {
    free(snapshot);
}

uc_err set_interrupt_callbacks(interrupt_pending_allowed_cb_t pend_allowed_cb, interrupt_entry_cb_t entry_cb, interrupt_exit_cb_t exit_cb) {
    interrupt_pending_allowed_cb = pend_allowed_cb;
    interrupt_entry_cb = entry_cb;
    interrupt_exit_cb = exit_cb;

    return UC_ERR_OK;
}

uc_err init_nvic(uc_engine *uc, uint32_t vtor, uint32_t num_irq, uint32_t num_prio_bits, uint32_t p_interrupt_limit, uint32_t num_disabled_interrupts, uint32_t *disabled_interrupts, bool p_enable_hardfp) {
    #ifdef DEBUG_NVIC
    printf("[NVIC] init_nvic called with vtor: %x, num_irq: %d, num_prio_bits: %d\n", vtor, num_irq, num_prio_bits); fflush(stdout);
    #endif

    if(num_irq > EXCEPTION_NO_MAX) {
        num_irq = EXCEPTION_NO_MAX;
    }
    if(num_prio_bits > NUM_PRIO_BITS_MAX) {
        num_prio_bits = NUM_PRIO_BITS_MAX;
    }
    prio_mask = 0xff << (NUM_PRIO_BITS_MAX - num_prio_bits);
    #ifdef DEBUG_NVIC
    printf("[NVIC] set prio_mask: %x\n", prio_mask); fflush(stdout);
    #endif

    // Make sure SVC is enabled
    nvic.ExceptionEnabled[EXCEPTION_NO_SVC] = 1;
    nvic.ExceptionEnabled[EXCEPTION_NO_PENDSV] = 1;
    nvic.ExceptionEnabled[EXCEPTION_NO_SYSTICK] = 1;

    nvic.ExceptionPriority[EXCEPTION_NO_NMI] = -2;
    nvic.highest_ever_enabled_exception_no = EXCEPTION_NO_SYSTICK;

    nvic.active_irq = NVIC_NONE_ACTIVE;
    nvic.pending_irq = NVIC_NONE_ACTIVE;
    nvic.active_group_prio = NVIC_LOWEST_PRIO;
    nvic.pending_prio = NVIC_LOWEST_PRIO;
    set_prigroup(NVIC_RESET_VAL_PRIGROUP);

    // B1.5.5 Reset Behavior
    // Unicorn CPU reset will reset PRIMASK / FAULTMASK, SP, ...
    // Priorities default to 0, so nothing to be done

    nvic.interrupt_count = 0;
    interrupt_limit = p_interrupt_limit;

    num_config_disabled_interrupts = num_disabled_interrupts;
    config_disabled_interrupts = calloc(num_disabled_interrupts, sizeof(*disabled_interrupts));

    for(uint32_t i = 0; i < num_disabled_interrupts; ++i)
        config_disabled_interrupts[i] = EXCEPTION_NO_EXTERNAL_START + disabled_interrupts[i];

    enable_hardfp = p_enable_hardfp;

    // Get pointers to commonly used registers
    if(uc_reg_ptr(uc, UC_ARM_REG_PRIMASK, (void **) &nvic.reg_daif_ptr)) {
        puts("[init_nvic] ERROR: uc_reg_tr"); exit(-1);
    }
    if(uc_reg_ptr(uc, UC_ARM_REG_BASEPRI, (void **) &nvic.reg_basepri_ptr)) {
        puts("[init_nvic] ERROR: uc_reg_tr"); exit(-1);
    }
    if(uc_reg_ptr(uc, UC_ARM_REG_CURR_SP_MODE_IS_PSP, (void **) &reg_curr_sp_mode_is_psp_ptr)) {
        puts("[init_nvic] ERROR: uc_reg_tr"); exit(-1);
    }

    // Set the vtor. If it is uninitialized, read it from actual (restored) process memory
    if(vtor == NVIC_VTOR_NONE) {
        uc_mem_read(uc, SYSCTL_VTOR, &nvic.vtor, sizeof(nvic.vtor));
        printf("[NVIC] Recovered vtor base: %x\n", nvic.vtor); fflush(stdout);
    } else {
        // We have MMIO vtor read fall through, so put vtor value in emulated memory
        nvic.vtor = vtor;
        uc_mem_write(uc, SYSCTL_VTOR, &nvic.vtor, sizeof(nvic.vtor));
    }

    uc_hook_add(uc, &nvic_exception_return_hook_handle, UC_HOOK_BLOCK, nvic_exception_return_hook, NULL, EXCEPT_MAGIC_RET_MASK, EXCEPT_MAGIC_RET_MASK | 0xf);

    uc_hook_add(uc, &nvic_block_hook_handle, UC_HOOK_BLOCK_UNCONDITIONAL, nvic_block_hook, &nvic, 1, 0);

    // 3. nvic MMIO range read/write handler
    uc_hook_add(uc, &hook_mmio_write_handle, UC_HOOK_MEM_WRITE, hook_sysctl_mmio_write, NULL, SYSCTL_MMIO_BASE, SYSCTL_MMIO_END);
    uc_hook_add(uc, &hook_mmio_read_handle, UC_HOOK_MEM_READ, hook_sysctl_mmio_read, NULL, SYSCTL_MMIO_BASE, SYSCTL_MMIO_END);

    uc_hook_add(uc, &hook_svc_handle, UC_HOOK_INTR, handler_svc, NULL, 1, 0);

    subscribe_state_snapshotting(uc, nvic_take_snapshot, nvic_restore_snapshot, nvic_discard_snapshot);

    recalc_prios();

    return UC_ERR_OK;
}

uint16_t get_num_enabled() {
    return nvic.num_enabled;
}

uint8_t nth_enabled_irq_num(uint8_t n) {
    /*
     * Find an irq to pend based on fuzzing input byte.
     */
    return nvic.enabled_irqs[n % nvic.num_enabled];
}

void nvic_set_pending(uc_engine *uc, uint32_t num, int delay_activation) {
    pend_interrupt(uc, num);
    maybe_activate(uc, false);
}
