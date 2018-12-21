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
//#include <boost/algorithm/string/replace.hpp>

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

template
class std::map<int, int>;
map<target_ulong,stack<target_ulong>> user_stack;
map<target_ulong,stack<target_ulong>> kernel_stack;

//stack<target_ulong> kernel_stack;
// map<unsigned int, set<string> > wl_library_map;
map<unsigned int, set<unsigned int> > wl_library_map;
map<unsigned int, pair<unsigned int, unsigned int>> wl_mainmodule_map;
set<unsigned int> kern_mod_set;
set<unsigned int> swap_context_address_set;
unsigned int swap_context_relative_address[] = {517399, 810965, 489618, 489159, 517789, 491214};
bool DEBUG;
double POP_LEVEL;
panda_arg_list *args;

const char * stored_wl;
bool load=false;

string intToHexString(int intValue) {
    string hexStr;
    // integer value to hex-string
    stringstream sstream;
    sstream << "0x" << setfill('0') << setw(8) << hex << (int)intValue;
    hexStr= sstream.str();
    sstream.clear();    //clears out the stream-string
    return hexStr;
}

bool load_SwapContext_Address(CPUState *env) {
    OsiModules *kms = get_modules(env);
    unsigned int base;
    for (int i = 0; i < kms->num; i++) {
        string module_name = kms->module[i].name;
        if (!module_name.compare("ntoskrnl.exe")) {
            base = kms->module[i].base;
            break;
        }
    }
    for (int i = 0; i < (sizeof(swap_context_relative_address) / sizeof(swap_context_relative_address[0])); i++) {
        swap_context_address_set.insert((base + swap_context_relative_address[i]));
    }
    return true;
}

bool check_kernel_exec(CPUState *env, target_ulong pc) {
    OsiModules *kms = get_modules(env);
    for (int i = 0; i < kms->num; i++) {
        unsigned int base = kms->module[i].base;
        unsigned int size = kms->module[i].size;
        if (pc > base && pc < (base + size)) {
            string dll_name = kms->module[i].name;
            if (dll_name.find("ntkrnlpa") != string::npos) {
                return true;
            }
        }

    }
    return false;
}

bool get_library_name(CPUState *env, target_ulong pc, string appendix){
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
                    cout << pid << " - " << appendix << " - Full Address " << std::hex << pc << "-" << std::dec << pc
                         << ", Virtual Address " << std::hex << pc - base_found << "-" << std::dec << pc - base_found
                         << " is in " << dll_name << " with full path as: " << file_name << endl;
//                    free_osimodules(ms);
//                    free_osiprocs(ps);
                    return true;
                }
//                free_osimodules(ms);
            }
        }
    }
//    free_osiprocs(ps);
    OsiModules *kms = get_modules(env);
    for (i = 0; i < kms->num; i++) {
        unsigned int base = kms->module[i].base;
        unsigned int size = kms->module[i].size;
        if (pc > base && pc < (base + size)) {
            OsiProc *current = get_current_process(env);
            string dll_name = kms->module[i].name;
            string file_name = kms->module[i].file;
            target_ulong base_found = base;
            cout << "[" << current->pid << "] " << appendix << " - Full Address " << std::hex << pc << "-" << std::dec
                 << pc << ", Virtual Address " << std::hex << pc - base_found << "-" << std::dec << pc - base_found
                 << " is in " << dll_name << " with full path as: " << file_name << endl;
            return true;
        }

    }
    return false;
}

void mod_kernel_load(CPUState *env, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    if (DEBUG) {
        printf("New Kernel Module loaded:%s - %s \n", mod_name, mod_filename);
    }
    string current_module = string(mod_filename);
    std::transform(current_module.begin(), current_module.end(), current_module.begin(), ::tolower);
    current_module.erase(0, 3);
    replace(current_module.begin(), current_module.end(), '\\', '_');
    current_module += ".wl";
    current_module.insert(0, stored_wl);
//    string prova = regex_replace( current_module, regex("stemRoot"), "windows");
    string to_replace = "stemroot";
    current_module.replace(current_module.find(to_replace), to_replace.length(), "windows");
    ifstream f(current_module.c_str());
    string line;
    while (getline(f, line)) {
        stringstream ss;
        unsigned int x;
        ss << line;
        ss >> x;
        kern_mod_set.insert(x + base);
    }
}

void mod_kernel_remove(CPUState *env, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    if (DEBUG) {
        printf("Removed Kernel Module:%s - %s \n", mod_name, mod_filename);
    }
    //TODO ADD CODE FOR REMOVE KERNEL
}

void new_process_create(CPUState *env, unsigned int pid, char *proc_name) {
    if (DEBUG) {
        printf("[%lu] Create New Process:%s\n", pid, proc_name);
    }
}

void exit_process(CPUState *env, unsigned int pid, char *proc_name) {
    if (DEBUG) {
        printf("Process %s Exited\n", proc_name);
    }
    wl_library_map.erase(pid);
    wl_mainmodule_map.erase(pid);
}

void new_module_load(CPUState *env, char *proc_name, unsigned int pid, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    if (DEBUG) {
        printf("[%lu] New Module loaded:%s\n", pid,mod_filename);
    }

    string current_module = string(mod_filename);
    current_module.erase(0,3);
    replace( current_module.begin(), current_module.end(), '\\', '_');
    current_module += ".wl";
    current_module.insert(0, stored_wl);
    // std::transform(current_module.begin(), current_module.end(), current_module.begin(), ::tolower);
    ifstream f (current_module);
    string line;
    auto found_element = wl_library_map.find(pid);
    set<unsigned int> address_list;
    if(found_element!=wl_library_map.end()){
        address_list = found_element->second;
    }
    while(getline(f, line)) {
        stringstream ss;
        unsigned int x;
        ss << line;
        ss >> x;
        address_list.insert(x + base);
    }
    wl_library_map[pid] = address_list;
}

void module_unload(CPUState *env, char *proc_name, unsigned int pid, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    if (DEBUG) {
        printf("Unloaded Module %s\n", mod_name);
    }
//    string current_module = string(mod_filename);
//    current_module.erase(0,3);
//    replace( current_module.begin(), current_module.end(), '\\', '_');
//    current_module += ".wl";
//    current_module.insert(0, stored_wl);
//    std::transform(current_module.begin(), current_module.end(), current_module.begin(), ::tolower);
//
//    ifstream f (current_module);
//    string line;
//    auto found_element = wl_library_map.find(pid);
//    // set<string> address_list;
//    set<unsigned int> address_list;
//    if(found_element!=wl_library_map.end()){
//        address_list = found_element->second;
//        while(getline(f, line)) {
//            std::transform(line.begin(), line.end(), line.begin(), ::tolower);
//            stringstream ss;
//            ss << std::hex << line;
//            unsigned int x;
//            ss >> x;
//            address_list.erase(base + x);
//        }
//    }
//    wl_library_map[pid] = address_list;
}

void main_module_load(CPUState *env, char *proc_name, unsigned int pid, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    if (DEBUG) {
        printf("New Main Module loaded:%s\n", mod_name);
    }
    wl_mainmodule_map[pid] = make_pair(base,base+size);
}

void main_module_unload(CPUState *env, char *proc_name, unsigned int pid, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    if (DEBUG) {
        printf("Unloaded Main Module %s\n", mod_name);
    }
    //TODO ADD unloaded mode code
}


bool check_return_address(CPUState *env, OsiProc *current, target_ulong current_pc, bool kernel_state) {
//    char idle_name[] = "Idle";
//    char system_name[] = "System";
    map<target_ulong, stack<target_ulong>> current_map;
    target_ulong current_key;
    if (kernel_state) {
        if (swap_context_address_set.count(current_pc)) {
            return true;
        }
    }
    if (kernel_state) {
        current_map = kernel_stack;
        current_key = get_current_thread(env);
        current_key = current->pid;
    }else{
        current_map = user_stack;
        current_key = current->pid;
    }
    auto current_data = current_map.find(current_key);
    if (current_data != current_map.end()) {
        auto current_stack = current_data->second;
        while (!current_stack.empty()) {
            target_ulong temp = current_stack.top();
            current_stack.pop();
            if (temp == current_pc) {
#if !defined(TARGET_ARM)
                if (DEBUG) {
//                            printf("[%lu - %lu] - %u - ESP:%lu Legitimate return address\n", current->pid, current_key, current_pc, env->regs[R_ESP]);
                        printf("[%s] [%lu - %lu] Legitimate Return address: %lu - ESP: %lu\n", kernel_state ? "KERNEL" : "USER", current->pid, current_key, current_pc, env->regs[R_ESP]);
                }
//                    if(current_pc == 2188178711 || current_pc == 2188150471|| current_pc == 2188150930 || current_pc == 2188179101 || current_pc == 2188472277){
                if(current_pc== 2188152526){
                    printf("[%s] [%lu - %lu] Legitimate Return address: %lu - ESP: %lu\n", kernel_state ? "KERNEL" : "USER", current->pid, get_current_thread(env), current_pc, env->regs[R_ESP]);
                }
#endif
                return true;
            }
        }
    }
    return false;
}


bool check_destination_address(OsiProc *current, target_ulong pc) {
    char idle_name[] = "Idle";
    char system_name[] = "System";
    if (current->pid == 0) {
        return true;
    }

    if (strcmp(current->name, system_name) == 0 && current->ppid == 0) {
        return true;
    }

    auto wl_library = wl_library_map.find(current->pid);
    set<unsigned int> address_list;
    if (wl_library != wl_library_map.end()) {
        address_list = wl_library->second;
        auto check = address_list.find(pc);
        if (check != address_list.end()) {
            if (DEBUG) {
                printf("%lu found into whitelist for process %lu:%s\n", pc, current->pid, current->name);
            }
            return true;

        }
    }
    auto main_module_range_elem = wl_mainmodule_map.find(current->pid);
    if (main_module_range_elem != wl_mainmodule_map.end()) {
        auto range = main_module_range_elem->second;
        if (pc > range.first && pc > range.second) {
            if (DEBUG) {
//                printf("%lu found into whitelist for process %lu:%s\n", pc, current->pid, current->name);
            }
            return true;
        }
    }
    if (kern_mod_set.find(pc) != kern_mod_set.end()) {
        if (DEBUG) {
//            printf("%lu found into whitelist for process %lu:%s\n", pc, current->pid, current->name);
        }
        return true;
    }
    return false;
}


void on_call(CPUState *env, target_ulong pc) {
    // printf("CURRENT PC:%ul\n",pc);
//    get_library_name(env, pc, "On Call - Destination");
    OsiProc *current = get_current_process(env);
    // bool missing_dll=false;
    bool found = check_destination_address(current, pc);
    if(!found){
//        if(get_library_name(env, pc, "On Call - Destination")) {
        update_lists(env);
        found = check_destination_address(current, pc);
        if (!found) {
            if (check_kernel_exec(env, pc)) {
                get_library_name(env, pc, "On Call - Destination");
                    printf("VIOLATION - %lu doesn't found into whitelist for process %lu:%s\n\n\n", pc, current->pid, current->name);
                }
        }
//        }
        // }
    }
}

void on_call_2(CPUState *env, target_ulong pc) {
    bool kernel_state = panda_in_kernel(env);
//    char system_name[] = "System";
    OsiProc *current = get_current_process(env);
    target_ulong thread = get_current_thread(env);
#ifndef TARGET_ARM
    if (DEBUG) {
//        get_library_name(env, pc, "On Call - Source");
        printf("[%s] [%lu - %lu] Source %lu - ESP: %lu\n", kernel_state ? "KERNEL" : "USER", current->pid, thread, pc, env->regs[R_ESP]);
    }
//        if(pc == 2188178711 || pc == 2188150471|| pc == 2188150930 || pc == 2188179101 || pc == 2188472277){
//        if(pc== 2188152526){
//            get_library_name(env, pc, "SPECIAL RET:");
//            FILE *fp;
//            fp = fopen("/home/giuseppe/panda/memory_dump.raw","w+");
//            panda_memsavep(fp);
//            fp = fopen("/home/giuseppe/panda/test.txt", "w+");
//            fprintf(fp, "RET= 826C8ECE\n");
//            fprintf(fp, "tb->pc - size=34\n");
//            target_disas(fp,2188152492, 42, 2);
//            fprintf(fp, "\n\n cpu_get_tb_cpu_state");
//            target_disas(fp,2188152526, 1518, 2);
//            target_disas(fp, 2188152333, 1024, 2);
//            fclose(fp);
//            printf("[%s] [%lu - %lu] Source %lu - ESP: %lu\n", kernel_state ? "KERNEL" : "USER", current->pid, thread, pc, env->regs[R_ESP]);
//        }
#endif
    target_ulong pid = current->pid;
    ///// COMMENT THIS TO USE THREAD
    thread = pid;
    if (kernel_state) {
//        auto current_data = kernel_stack.find(pid);
        auto current_data = kernel_stack.find(thread);
        stack<target_ulong> current_stack;
        if(current_data!=kernel_stack.end()){
            current_stack=current_data->second;
        }       
        current_stack.push(pc);
        kernel_stack[thread] = current_stack;
    } else {
        auto current_data = user_stack.find(pid);
        stack<target_ulong> current_stack;
        if(current_data!=user_stack.end()){
            current_stack=current_data->second;
        }       
        current_stack.push(pc);
        user_stack[pid] = current_stack;
    }

}


void on_ret(CPUState *env, target_ulong pc) {
    if (swap_context_address_set.size() < 1) {
        load_SwapContext_Address(env);
    }
    OsiProc *current = get_current_process(env);
    target_ulong current_pc = panda_current_pc(env);
    bool kernel_state = panda_in_kernel(env);
    if (!check_return_address(env, current, current_pc, kernel_state)) {
//        if (!check_return_address(env, current, current_pc, !kernel_state)) {
            get_library_name(env, current_pc, "On Ret");
#ifndef TARGET_ARM
        printf("[%s] [%lu - %lu] %s - VIOLATION - Current address:%u - ESP:%lu\n", kernel_state ? "KERNEL" : "USER", current->pid, get_current_thread(env), current->name,
               current_pc, env->regs[R_ESP]);
#endif
//        }

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
    DEBUG = panda_parse_bool(args, "DEBUG");
    DEBUG = true;
//    POP_LEVEL = panda_parse_double(args, "pop", 100.0);
    // original_disk = panda_parse_string(args,"original_disk","/home/giuseppe/qcow_copy/");
    stored_wl = panda_parse_string(args,"stored_wl","/home/giuseppe/PassaggioDati/file_wl/");
    panda_enable_precise_pc();
    panda_require("procmon");
    if (!init_procmon_api()) return false;
    PPP_REG_CB("procmon", new_process_notify, new_process_create);
    PPP_REG_CB("procmon", removed_process_notify, exit_process);
    PPP_REG_CB("procmon", new_module_notify, new_module_load);
    PPP_REG_CB("procmon", removed_module_notify, module_unload);
    PPP_REG_CB("procmon", new_main_module_notify, main_module_load);
    PPP_REG_CB("procmon", removed_main_module_notify, main_module_unload);
    PPP_REG_CB("procmon", removed_kernmod_notify, mod_kernel_remove);
    PPP_REG_CB("procmon", new_kernmod_notify, mod_kernel_load);
    panda_require("callstack_instr");
    if (!init_callstack_instr_api()) return false;
    if(!init_osi_api()) return false;
//    PPP_REG_CB("callstack_instr", on_call_2, on_call_2);
    PPP_REG_CB("callstack_instr", on_call, on_call);
//    PPP_REG_CB("callstack_instr", on_ret, on_ret);
    // printf("CFI plugin loaded\nDEBUG mode %s\nLocal VM disk copy: %s\nFolder with stored whitelists: %s\nOn RET instruction, check stacks %lf levels\n", DEBUG ? "enabled" : "disabled", original_disk, stored_wl, POP_LEVEL);
    printf("CFI plugin loaded\nDEBUG mode %s\nFolder with stored whitelists: %s\nOn RET instruction, check stacks %lf levels\n", DEBUG ? "enabled" : "disabled", stored_wl, POP_LEVEL);
    return true;
//#else
//    cout << "CFI plugin not supported on this architecture" << endl;
//    return false;
//#endif
}

