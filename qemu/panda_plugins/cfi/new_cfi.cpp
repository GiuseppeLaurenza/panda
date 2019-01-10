/* PANDABEGINCOMMENT
 *
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 *
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS


#include <algorithm>
#include <sstream>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <stack>
#include <string>
#include <map>
#include <set>
#include <list>

extern "C" {
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "../common/prog_point.h"
// #include "panda/rr/rr_log.h"
// #include "panda/plog.h"
#include "pandalog.h"
#include "rr_log.h"
#include "cpu.h"
#include "disas.h"
#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
}

#include "../callstack_instr/callstack_instr.h"
#include "../callstack_instr/callstack_instr_ext.h"

#include "../procmon/procmon.h"
#include "../procmon/procmon_ext.h"
using namespace std;
panda_arg_list *args;
const char * stored_wl;
int debug;
static uint32_t capacity = 16;
map <string,set<target_ulong>> dll_address_map;
map <target_ulong,list<OsiModule>> process_dll_map;
set <target_ulong> kern_mod_set;

bool operator<(OsiModule const &a, OsiModule const &b) {
    string a_name(a.name);
    string a_concat = a_name + to_string(a.size) + "_" + to_string(a.base);
    string b_name(b.name);
    string b_concat = b_name + to_string(b.size) + "_" + to_string(b.base);
    bool result = a_concat < b_concat;
    return result;
}

bool get_library_name(CPUState *env, target_ulong pc, string appendix){
    //TODO REMOVE THIS FUNCTION AFTER DEBUG
    OsiProcs *ps = get_processes(env);
    if (ps == NULL) {
        return false;
    }
    int i;
    for (i = 0; i < ps->num; i++) {
        OsiProc *current = &(ps->proc[i]);
        OsiModules *ms = get_libraries(env, current);
        target_ulong pid = current->pid;

        if (ms != NULL) {
            for (int i = 0; i < ms->num; i++) {
                unsigned int base = ms->module[i].base;
                unsigned int size = ms->module[i].size;
                if (pc > base && pc < (base + size)) {
                    string dll_name = ms->module[i].name;
                    string file_name = ms->module[i].file;
                    target_ulong base_found = base;
                    cout << "[Caller:" << pid << " - Owner:"<< ps->proc[i].pid <<"]  " << appendix << " - Full Address " << std::hex << pc << "-" << std::dec << pc
                         << ", Virtual Address " << std::hex << pc - base_found << "-" << std::dec << pc - base_found
                         << " is in " << dll_name << " with full path as: " << file_name << endl;
//                    free_osimodules(ms);
//                    free_osiprocs(ps);
                    update_lists(env);
                    return true;
                }
//                free_osimodules(ms);
            }
        }
    }
//    free_osiprocs(ps);
    OsiModules *kms = get_modules(env);
    if(kms==NULL){
        return false;
    }
    for (i = 0; i < kms->num; i++) {
        unsigned int base = kms->module[i].base;
        unsigned int size = kms->module[i].size;
        if (pc > base && pc < (base + size)) {
            OsiProc *current = get_current_process(env);
            string dll_name = kms->module[i].name;
            string file_name = kms->module[i].file;
            target_ulong base_found = base;
            cout << "[Kernel Modules][" << current->pid << "] " << appendix << " - Full Address " << std::hex << pc << "-" << std::dec
                 << pc << ", Virtual Address " << std::hex << pc - base_found << "-" << std::dec << pc - base_found
                 << " is in " << dll_name << " with full path as: " << file_name << endl;
            update_lists(env);
            return true;
        }

    }
    return false;
}

void mod_kernel_load(CPUState *env, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    if(debug>1){
        printf("[KERNEL] Load module %s - %s\n",mod_name, mod_filename);
    }
    string current_module = string(mod_filename);
    std::transform(current_module.begin(), current_module.end(), current_module.begin(), ::tolower);
    current_module.erase(0, 3);
    replace(current_module.begin(), current_module.end(), '\\', '_');
    current_module += ".wl";
    current_module.insert(0, stored_wl);
    string to_replace = "stemroot";
    current_module.replace(current_module.find(to_replace), to_replace.length(), "windows");
    ifstream f(current_module.c_str());
    string line;
    while (getline(f, line)) {
        stringstream ss;
        target_ulong x;
        ss << line;
        ss >> x;
        kern_mod_set.insert(x + base);
    }
}

bool add_module_address(char* mod_filename){
    string current_module = string(mod_filename);
    if(dll_address_map.count(current_module)>0){
        return false;
    }
    string module_path = string(mod_filename);
    module_path.erase(0,3);
    replace( module_path.begin(), module_path.end(), '\\', '_');
    module_path += ".wl";
    module_path.insert(0, stored_wl);
    set<target_ulong> address_list;
    ifstream f (module_path);
    string line;
    while(getline(f, line)) {
        stringstream ss;
        target_ulong x;
        ss << line;
        ss >> x;
        address_list.insert(x);
    }
    dll_address_map[current_module]=address_list;
    return true;
}

bool add_module_pid(target_ulong pid, char* mod_name, char* mod_filename, target_ulong size, target_ulong base ){
    OsiModule* m = (OsiModule*) malloc(sizeof(OsiModule)*capacity);
    m->file = (char *)malloc(strlen(mod_filename)+1);
    strcpy(m->file, mod_filename);
    m->base = base;
    m->size = size;
    m->name = (char *)malloc(strlen(mod_name)+1);
    strcpy(m->name, mod_name);
    auto found_element = process_dll_map.find(pid);
    list<OsiModule> module_list;
    if(found_element!=process_dll_map.end()){
        module_list = found_element->second;
    }
    module_list.push_back(*m);
    process_dll_map[pid] = module_list;
    if(debug>0){
        printf("[%u] Mmodule_list %d - Process Map: %d\n", pid, module_list.size(), process_dll_map.size());
    }
    return true;
}

void new_module_load(CPUState *env, char *proc_name, unsigned int pid, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    if(debug>1){
        printf("[%u - %s] Load module %s\n",pid, proc_name, mod_name);
    }
    add_module_address(mod_filename);
    add_module_pid(pid, mod_name, mod_filename, size, base);
}



bool check_kernel_exec(CPUState *env, target_ulong pc) {
    OsiModules *kms = get_modules(env);
    if(kms==NULL){
        return false;
    }

    for (int i = 0; i < kms->num; i++) {
        unsigned int base = kms->module[i].base;
        unsigned int size = kms->module[i].size;
        if (pc > base && pc < (base + size)) {
            string dll_name = kms->module[i].name;
            if (dll_name.find("ntkrnlpa") != string::npos || dll_name.find("ntoskrnl") != string::npos) {
                free_osimodules(kms);
                return true;
            }
        }

    }
    free_osimodules(kms);
    return false;
}

bool check_destination_address(OsiProc* current, target_ulong pc) {
    char idle_name[] = "Idle";
    char system_name[] = "System";
    if (current->pid == 0) {
        return true;
    }

    if (strcmp(current->name, system_name) == 0 && current->ppid == 0) {
        return true;
    }
    auto process_dll_elem = process_dll_map.find(current->pid);
    if (process_dll_elem != process_dll_map.end()) {
        auto module_list = process_dll_elem->second;
        for (auto current_module_iterator = module_list.begin();
            current_module_iterator != module_list.end(); ++current_module_iterator) {
            OsiModule current_module = *current_module_iterator;
            unsigned int base = current_module.base;
            unsigned int size = current_module.size;
            if (pc > base && pc < (base + size)) {
                string module_name = string(current_module.file);
//                if(module_name.find(current->name) != string::npos){
                    return true;
//                }
                auto dll_element = dll_address_map.find(module_name);
                if (dll_element != dll_address_map.end()) {
                    auto address_set = dll_element->second;
                    if (address_set.count(pc - base)) {
                        return true;
                    }
                }
            }
        }
    }
    if (kern_mod_set.find(pc) != kern_mod_set.end()) {
        if (debug>1) {
//            printf("%lu found into whitelist for process %lu:%s\n", pc, current->pid, current->name);
        }
        return true;
    }
    return false;
}

void on_call(CPUState *env, target_ulong destination_address, target_ulong return_address){
    OsiProc* current = get_current_process(env);
    if(!check_destination_address(current, destination_address)){
        if(!check_kernel_exec(env, destination_address)){
            update_lists(env);
            if(!check_destination_address(current, destination_address)){
                get_library_name(env, destination_address, "On Call");
                printf("[%u] Violation calling %u, return address is %u\n", current->pid, destination_address, return_address);
                get_library_name(env, return_address, "Call violation start before");
            }
        }
    }
}


void uninit_plugin(void *self) {
    panda_disable_precise_pc();
    panda_free_args(args);
    printf("Unloading plugin cfi\n");
}

bool init_plugin(void *self) {
//#if defined(TARGET_I386)  || defined(TARGET_X86_64)
    printf("Initializing plugin cfi\n");
    args = panda_get_args("cfi");
    stored_wl = panda_parse_string(args,"stored_wl","/home/giuseppe/PassaggioDati/file_wl/");
    debug = panda_parse_uint32(args, "debug", 0);
    debug=0;
    panda_enable_precise_pc();
    panda_require("procmon");
    if (!init_procmon_api()) return false;
//    PPP_REG_CB("procmon", new_process_notify, new_process_create);
//    PPP_REG_CB("procmon", removed_process_notify, exit_process);
    PPP_REG_CB("procmon", new_module_notify, new_module_load);
//    PPP_REG_CB("procmon", removed_module_notify, module_unload);
//    PPP_REG_CB("procmon", new_main_module_notify, main_module_load);
//    PPP_REG_CB("procmon", removed_main_module_notify, main_module_unload);
    PPP_REG_CB("procmon", new_kernmod_notify, mod_kernel_load);
//    PPP_REG_CB("procmon", removed_kernmod_notify, mod_kernel_remove);
    panda_require("callstack_instr");
    if (!init_callstack_instr_api()) return false;
    if(!init_osi_api()) return false;
    PPP_REG_CB("callstack_instr", on_call_3, on_call);
//    PPP_REG_CB("callstack_instr", on_call_2, on_call_2);
//    PPP_REG_CB("callstack_instr", on_call, on_call);
//    PPP_REG_CB("callstack_instr", on_ret, on_ret);
    printf("CFI plugin loaded\nFolder with stored whitelists: %s\n", stored_wl);
    return true;
//#else
//    cout << "CFI plugin not supported on this architecture" << endl;
//    return false;
//#endif
}
