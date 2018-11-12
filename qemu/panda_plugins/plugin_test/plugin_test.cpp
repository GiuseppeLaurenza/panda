

#define __STDC_FORMAT_MACROS

#include <algorithm>
#include <string>
#include <iostream>
#include <vector>

// #include "panda/plugin.h"
// #include "panda/plugin_plugin.h"


extern "C" {
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "../common/prog_point.h"
// #include "panda/rr/rr_log.h"
// #include "panda/plog.h"
#include "pandalog.h"
#include "rr_log.h"

// #include "../pri/pri_types.h"
// #include "../pri/pri_ext.h"
// #include "../pri/pri.h"

#include "../libfi/libfi.h"
#include "../libfi/libfi_ext.h"
// #include "../libfi/libfi_int.h"

#include "../procmon/procmon.h"



#include "cpu.h"

bool init_plugin(void *);
void uninit_plugin(void *);
}

void mycb (CPUState *env, target_ulong pc, uint8_t *args){
    printf("Someone called InterlockedCompareExchange\n");
    char * fnname = "InterlockedCompareExchange";
    char * libname = "kernel32.dll";
    // cb.callback=fn_start;
    // libfi_add_callback(libname, fnname, 0, 0, mycb);
    libfi_remove_callback(libname, fnname, 0, 0, mycb);
}
void proc_start(CPUState *env, unsigned int pid, char* proc_name){
    printf("Started process %u - %s\n", pid, proc_name);
}

void proc_remove(CPUState *env, unsigned int pid, char* proc_name){
    printf("Removed process %u - %s\n", pid, proc_name);
}

void module_start(CPUState *env, char* proc_name, unsigned int pid, char* mod_name, char* mod_filename, target_ulong size, target_ulong base){
    printf("Process %s loaded the module %s\n",proc_name, mod_name);
}

void module_remove(CPUState *env, char* proc_name, unsigned int pid, char* mod_name, char* mod_filename, target_ulong size, target_ulong base){
    printf("Process %s removed the module %s\n",proc_name, mod_name);
}

void main_module_start(CPUState *env, char* proc_name, unsigned int pid, char* mod_name, char* mod_filename, target_ulong size, target_ulong base){
    printf("MAIN MODULE: Process %s loaded the module %s\n",proc_name, mod_name);
}

void main_module_remove(CPUState *env, char* proc_name, unsigned int pid, char* mod_name, char* mod_filename, target_ulong size, target_ulong base){
    printf("MAIN MODULE: Process %s removed the module %s\n",proc_name, mod_name);
}


bool init_plugin(void *self) {
#if defined(TARGET_I386)  //&& !defined(TARGET_X86_64)
    printf("Initializing plugin plugin_test\n");
    panda_require("libfi");
    assert(init_libfi_api());
    // PPP_REG_CB("libfi", fn_start, fn_start);
    // PPP_REG_CB("libfi", fn_return, fn_start);
    char * fnname = "InterlockedCompareExchange";
    char * libname = "kernel32.dll";
    // cb.callback=fn_start;
    // libfi_add_callback(libname, fnname, 0, 0, mycb);
    // libfi_remove_callback(libname, fnname, 0, 0, mycb);
    // libfi_add_callback(libname, fnname, 1, 0, fn_start);
    // PPP_REG_CB("pri", fn_start, on_fn_start);
    // PPP_REG_CB("pri", on_fn_return, fn_return_new);
    panda_require("procmon");
    PPP_REG_CB("procmon", new_module_notify, module_start);
    PPP_REG_CB("procmon", removed_module_notify, module_remove);
    PPP_REG_CB("procmon", new_main_module_notify, main_module_start);
    PPP_REG_CB("procmon", removed_main_module_notify, main_module_remove);
    PPP_REG_CB("procmon", new_process_notify, proc_start);
    PPP_REG_CB("procmon", removed_process_notify, proc_remove);
    

#endif
    return true;
}

void uninit_plugin(void *self) {
    printf ("Uninitializing plugin libfi\n");
}

