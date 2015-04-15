#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>
#include <unwind.h>

#include "dr_api.h"
#include "drsyms.h"
#include "drmgr.h"
#include "drwrap.h"

#include "kvec.h"

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

int tls_key = -1;

void push(void *addr)
{
    kvec_t(void*) *stack = drmgr_get_tls_field(dr_get_current_drcontext(), tls_key);
    kv_push(void*, *stack, addr);
}

void *pop()
{
    kvec_t(void*) *stack = drmgr_get_tls_field(dr_get_current_drcontext(), tls_key);
    return kv_pop(*stack);
}

void *peek()
{
    kvec_t(void*) *stack = drmgr_get_tls_field(dr_get_current_drcontext(), tls_key);
    return kv_A(*stack, kv_size(*stack)-1);
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

dr_emit_flags_t new_bb(void *drcontext, void *tag, instrlist_t *bb, instr_t *inst, bool for_trace, bool translating, void *user_data)
{
    if (inst == instrlist_last(bb)) {
        if (instr_is_call_direct(inst))
            dr_insert_call_instrumentation(drcontext, bb, inst, on_call);
        else if (instr_is_call_indirect(inst))
            dr_insert_mbr_instrumentation(drcontext, bb, inst, on_call, SPILL_SLOT_1);
        else if (instr_is_return(inst))
            dr_insert_mbr_instrumentation(drcontext, bb, inst, on_ret, SPILL_SLOT_1);
    }

    return DR_EMIT_DEFAULT;
}

void on_thread(void *drcontext)
{
    kvec_t(void*) *stack = malloc(sizeof(kvec_t(void*)));
    kv_init(*stack);
    drmgr_set_tls_field(drcontext, tls_key, stack);
}

void on_thread_exit(void *drcontext)
{
    kvec_t(void*) *stack = drmgr_get_tls_field(drcontext, tls_key);
    kv_destroy(*stack);
    free(stack);
}

void on_call_phase2(void *wrapctx, OUT void **user_data)
{
    *user_data = drwrap_get_arg(wrapctx, 1);
}

void on_ret_phase2(void *wrapctx, void *user_data)
{
    struct _Unwind_Context *uw = user_data;

    void *catch_addr = (void*)_Unwind_GetIP(uw); // IP in catch, i.e. return address
/*    instr_t i;
    decode(drwrap_get_drcontext(wrapctx), catch_addr, &i);
    void *catch_func = ; // address of function containing catch

    while ( RTN_Address(RTN_FindByAddress(peek())) != catch_func )
            pop();
*/

    push(catch_addr);
}

void on_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
    void *addr;
    if ((addr = dr_get_proc_address(info->handle, "_Unwind_RaiseException_Phase2")) != NULL)
    {
        drwrap_wrap(addr, &on_call_phase2, &on_ret_phase2);
        drmgr_unregister_module_load_event(&on_module_load);
    }
}

void on_exit()
{
    drmgr_exit();
    drwrap_exit();
    drsym_exit();
}

DR_EXPORT void dr_init(client_id_t id)
{
    drmgr_init();
    drwrap_init();
    drsym_init(0);

    tls_key = drmgr_register_tls_field();

    dr_register_exit_event(&on_exit);
    drmgr_register_bb_instrumentation_event(NULL, &new_bb, NULL);
    drmgr_register_module_load_event(&on_module_load);
    drmgr_register_thread_init_event(&on_thread);
    drmgr_register_thread_exit_event(&on_thread_exit);
}

