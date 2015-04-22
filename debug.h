#pragma once

#define printf dr_printf
int tabs = 0;
#define indent (++tabs)
#define unindent ({ if (tabs > 0) --tabs; })
#define tdebug(...) ({ \
    for (int i = 0; i < tabs; ++i) dr_printf("\t"); \
    dr_printf(__VA_ARGS__); \
})
static char sym_name_buf[256];
static const char *get_sym(app_pc addr)
{
    module_data_t *data = dr_lookup_module(addr);
    if (data != NULL)
    {
        char file[MAXIMUM_PATH];
        drsym_info_t sym;
        sym.struct_size = sizeof(sym);
        sym.name = sym_name_buf;
        sym.name_size = 256;
        sym.file = file;
        sym.file_size = MAXIMUM_PATH;
        drsym_error_t res = drsym_lookup_address(data->full_path, addr - data->start, &sym, DRSYM_DEFAULT_FLAGS);

        dr_free_module_data(data);
        if (res == DRSYM_SUCCESS || res == DRSYM_ERROR_LINE_NOT_AVAILABLE)
            return sym_name_buf;
    }
    return NULL;
}
