#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>
#include "dr_api.h"
#include "drsyms.h"

unsigned tabs = 0;

void *shadow[128];
unsigned top = 0;

#define indent() for (int i=0; i<tabs; ++i) dr_printf("\t")

static inline bool check_ret(void *a, void *b) {
    return b-a <= 8;
}

void on_call(void *call_ins, void *target_addr)
{
    shadow[top++] = call_ins;

    indent();
    dr_printf("%p: call %p\n", call_ins, target_addr);
    ++tabs;
}

void on_ret(void *ret_ins, void *target_addr)
{
    if (tabs > 0) --tabs;
    if (top != 0) {
        while (!check_ret(shadow[--top], target_addr)) {
            indent();
            dr_printf("skipping a frame (tried %p -> %p)\n", target_addr, shadow[top+1]);
            --tabs;
        }
    }
    indent();
    dr_printf("%p: ret to %p\n", ret_ins, target_addr);
}

static dr_emit_flags_t new_bb(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    if (!for_trace) {
        instr_t *tail = instrlist_last(bb);
        if (instr_is_call(tail)) {
            dr_insert_call_instrumentation(drcontext, bb, tail, on_call);
        } else if (instr_is_return(tail)) {
            dr_insert_mbr_instrumentation(drcontext, bb, tail, on_ret, SPILL_SLOT_2);
        }
    }

    return DR_EMIT_DEFAULT;
}

static void event_exit()
{
}

DR_EXPORT void dr_init(client_id_t id)
{
    disassemble_set_syntax(DR_DISASM_INTEL);

    dr_register_exit_event(event_exit);
    dr_register_bb_event(new_bb);

    drsym_init(0);
}

