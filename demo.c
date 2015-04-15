#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>
#include "dr_api.h"
#include "drsyms.h"
#include "kvec.h"


/*
char *get_sym(app_pc addr)
{
    module_data_t *data = dr_lookup_module(addr);
    if (data != NULL)
    {
        char *name = malloc(256);
        char file[MAXIMUM_PATH];
        drsym_info_t sym;
        sym.struct_size = sizeof(sym);
        sym.name = name;
        sym.name_size = 256;
        sym.file = file;
        sym.file_size = MAXIMUM_PATH;
        drsym_error_t res = drsym_lookup_address(data->full_path, addr - data->start, &sym, DRSYM_DEFAULT_FLAGS);
        if (res != DRSYM_SUCCESS && res != DRSYM_ERROR_LINE_NOT_AVAILABLE)
        {
            free(name);
            name = NULL;
        }
        dr_free_module_data(data);
        return name;
    }
    return NULL;
}
*/

void push(void *addr)
{
    kvec_t(void*) *stack = dr_get_tls_field(dr_get_current_drcontext());
    kv_push(void*, *stack, addr);
}

void *pop()
{
    kvec_t(void*) *stack = dr_get_tls_field(dr_get_current_drcontext());
    return kv_pop(*stack);
}

void on_call(void *call_ins, void *target_addr)
{
    push(call_ins);
}

void on_ret(void *ret_ins, void *target_addr)
{
    while (target_addr - pop() > 8)
        ;
}

dr_emit_flags_t new_bb(void *drcontext, void *tag, instrlist_t *bb, bool for_trace, bool translating)
{
    instr_t *tail = instrlist_last(bb);
    if (instr_is_call_direct(tail))
        dr_insert_call_instrumentation(drcontext, bb, tail, on_call);
    else if (instr_is_call_indirect(tail))
        dr_insert_mbr_instrumentation(drcontext, bb, tail, on_call, SPILL_SLOT_1);
    else if (instr_is_return(tail))
        dr_insert_mbr_instrumentation(drcontext, bb, tail, on_ret, SPILL_SLOT_1);

    return DR_EMIT_DEFAULT;
}

void on_thread(void *drcontext)
{
    kvec_t(void*) *stack = malloc(sizeof(kvec_t(void*)));
    kv_init(*stack);
    dr_set_tls_field(drcontext, stack);
}

void on_thread_exit(void *drcontext)
{
    kvec_t(void*) *stack = dr_get_tls_field(drcontext);
    kv_destroy(*stack);
    free(stack);
}

void event_exit()
{
    drsym_exit();
}

DR_EXPORT void dr_init(client_id_t id)
{
    dr_register_exit_event(&event_exit);
    dr_register_bb_event(&new_bb);
    dr_register_thread_init_event(&on_thread);
    dr_register_thread_exit_event(&on_thread_exit);

    drsym_init(0);
}

