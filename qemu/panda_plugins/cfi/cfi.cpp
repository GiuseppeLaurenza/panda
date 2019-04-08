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
//#include <boost/algorithm/string/replace.hpp>

extern "C"
{
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
//
//#include "../procmon/procmon.h"
//#include "../procmon/procmon_ext.h"
using namespace std;

template class std::map<int, int>;
map<target_ulong, stack<target_ulong>> user_stack;
map<target_ulong, stack<target_ulong>> kernel_stack;

//stack<target_ulong> kernel_stack;
// map<unsigned int, set<string> > wl_library_map;
// map<unsigned int, set<unsigned int> > wl_library_map;
// map<unsigned int, pair<unsigned int, unsigned int>> wl_mainmodule_map;

//static uint32_t capacity = 16;
map<string, set<target_ulong>> dll_address_map;
map<string, set<target_ulong>> kernel_module_address_map;
set<unsigned int> swap_context_address_set;

unsigned int swap_context_relative_address[] = {517399, 810965, 489618, 489159, 517789, 491214, 424294, 453397, 453007, 424594};
bool DEBUG = false;
double POP_LEVEL;
panda_arg_list *args;

const char *stored_wl;
bool load = false;

bool load_SwapContext_Address(CPUState *env)
{
    OsiModules *kms = get_modules(env);
    if (kms == NULL)
    {
        return false;
    }
    unsigned int base;
    for (int i = 0; i < kms->num; i++)
    {
        string module_name = kms->module[i].name;
        if (!module_name.compare("ntoskrnl.exe"))
        {
            base = kms->module[i].base;
            break;
        }
    }
    for (int i = 0; i < (sizeof(swap_context_relative_address) / sizeof(swap_context_relative_address[0])); i++)
    {
        swap_context_address_set.insert((base + swap_context_relative_address[i]));
    }
    return true;
}

bool get_library_name(CPUState *env, target_ulong pc, string appendix)
{
    OsiProcs *ps = get_processes(env);
    if (ps == NULL)
    {
        return false;
    }
    OsiProc *caller_process = get_current_process(env);

    int i;
    for (i = 0; i < ps->num; i++)
    {
        OsiProc *current = &(ps->proc[i]);
        if (caller_process->pid == current->pid)
        {
            OsiModules *ms = get_libraries(env, current);
            target_ulong pid = current->pid;

            if (ms != NULL)
            {
                for (int i = 0; i < ms->num; i++)
                {
                    unsigned int base = ms->module[i].base;
                    unsigned int size = ms->module[i].size;
                    if (pc > base && pc < (base + size))
                    {
                        //                        if (caller_process->pid == current->pid) {
                        //                            update_module(env, current->pid);
                        //                        }
                        string dll_name = ms->module[i].name;
                        string file_name = ms->module[i].file;
                        target_ulong base_found = base;
                        cout << "[Current: " << caller_process->pid << " - Owner: " << current->pid << "] " << appendix
                             << " - Full Address " << std::hex << pc << "-" << std::dec << pc
                             << ", Virtual Address " << std::hex << pc - base_found << "-" << std::dec
                             << pc - base_found
                             << " is in " << dll_name << " with full path as: " << file_name << endl;
                        //                    free_osimodules(ms);
                        //                    free_osiprocs(ps);
                        //                    return true;
                    }
                    //                free_osimodules(ms);
                }
            }
        }
    }
    //    free_osiprocs(ps);
    OsiModules *kms = get_modules(env);
    if (kms == NULL)
    {
        return false;
    }
    for (i = 0; i < kms->num; i++)
    {
        unsigned int base = kms->module[i].base;
        unsigned int size = kms->module[i].size;
        if (pc > base && pc < (base + size))
        {
            OsiProc *current = get_current_process(env);
            string dll_name = kms->module[i].name;
            string file_name = kms->module[i].file;
            target_ulong base_found = base;
            cout << "[KERNEL - " << current->pid << "] " << appendix << " - Full Address " << std::hex << pc << "-"
                 << std::dec
                 << pc << ", Virtual Address " << std::hex << pc - base_found << "-" << std::dec << pc - base_found
                 << " is in " << dll_name << " with full path as: " << file_name << endl;
            //            return true;
        }
    }
    return false;
}

set<target_ulong> add_module_address(char *mod_filename, bool kernel)
{
    string current_module = string(mod_filename);
    string module_path = string(mod_filename);
    map<string, set<target_ulong>> current_map;
    if (kernel)
    {
        current_map = kernel_module_address_map;
    }
    else
    {
        current_map = dll_address_map;
    }
    auto address_list_iterator = current_map.find(mod_filename);

    if (address_list_iterator != current_map.end())
    {
        return address_list_iterator->second;
    }

    module_path.erase(0, 3);
    string to_replace = "stemRoot";
    if (module_path.find(to_replace) != string::npos)
    {
        module_path.replace(module_path.find(to_replace), to_replace.length(), "windows");
    }
    std::transform(module_path.begin(), module_path.end(), module_path.begin(), ::tolower);
    replace(module_path.begin(), module_path.end(), '\\', '_');
    module_path += ".wl";

    module_path.insert(0, stored_wl);
    set<target_ulong> address_list;
    ifstream f(module_path);
    string line;
    while (getline(f, line))
    {
        stringstream ss;
        target_ulong x;
        ss << line;
        ss >> x;
        address_list.insert(x);
    }
    if (kernel)
    {
        kernel_module_address_map[current_module] = address_list;
    }
    else
    {
        dll_address_map[current_module] = address_list;
    }
    return address_list;
}

bool check_return_address(CPUState *env, OsiProc *current, target_ulong current_pc, bool kernel_state)
{
    char idle_name[] = "Idle";
    //    char system_name[] = "System";
    map<target_ulong, stack<target_ulong>> current_map;
    target_ulong current_key;
    if (kernel_state)
    {
        if (swap_context_address_set.count(current_pc))
        {
            return true;
        }
        if (strcmp(current->name, idle_name) == 0)
        {
            return true;
        }
    }
    if (kernel_state)
    {
        current_map = kernel_stack;
        current_key = get_current_thread(env);
        current_key = current->pid;
    }
    else
    {
        current_map = user_stack;
        current_key = current->pid;
    }
    auto current_data = current_map.find(current_key);
    if (current_data != current_map.end())
    {
        auto current_stack = current_data->second;
        while (!current_stack.empty())
        {
            target_ulong temp = current_stack.top();
            current_stack.pop();
            // printf("[%u] Stack size: %d\n",current_key, current_stack.size());
            if (temp == current_pc)
            {
#if !defined(TARGET_ARM)
                if (DEBUG)
                {
                    //                            printf("[%lu - %lu] - %u - ESP:%lu Legitimate return address\n", current->pid, current_key, current_pc, env->regs[R_ESP]);
                    printf("[%s] [%lu - %lu] Legitimate Return address: %lu - ESP: %lu\n", kernel_state ? "KERNEL" : "USER", current->pid, current_key, current_pc, env->regs[R_ESP]);
                }
//                    if(current_pc == 2188178711 || current_pc == 2188150471|| current_pc == 2188150930 || current_pc == 2188179101 || current_pc == 2188472277){
// if(current_pc== 2188152526){
//     printf("[%s] [%lu - %lu] Legitimate Return address: %lu - ESP: %lu\n", kernel_state ? "KERNEL" : "USER", current->pid, get_current_thread(env), current_pc, env->regs[R_ESP]);
// }
#endif
                return true;
            }
        }
    }
    return false;
}

bool check_destination_address(CPUState *env, OsiProc *current, target_ulong pc)
{
    char idle_name[] = "Idle";
    char system_name[] = "System";
    bool found = false;
    if (current->pid == 0)
    {
        found = true;
        return found;
    }

    if (strcmp(current->name, system_name) == 0 && current->ppid == 0)
    {
        found = true;
        return found;
    }

    OsiModules *ms = get_libraries(env, current);
    if (ms != NULL)
    {
        int i;
        for (i = 0; i < ms->num; i++)
        {
            unsigned int base = ms->module[i].base;
            unsigned int size = ms->module[i].size;
            if (pc > base && pc < (base + size))
            {
                string current_module = string(ms->module[i].file);
                set<target_ulong> address_set;
                auto dll_element = dll_address_map.find(current_module);
                if (dll_element != dll_address_map.end())
                {
                    address_set = dll_element->second;
                }
                else
                {
                    address_set = add_module_address(ms->module[i].file, false);
                }
                int count = address_set.count(pc - base);
                if (address_set.count(pc - base))
                {
                    //                    if(DEBUG){
                    //                        printf("[%u] Find address %u in module whitelist %s\n",current->pid,pc, module_name.c_str());
                    //                    }
                    found = true;
                }

                break;
            }
        }
        free_osimodules(ms);
    }
    OsiModules *kms = get_modules(env);
    if (kms != NULL)
    {
        int i;
        for (i = 0; i < kms->num; i++)
        {
            unsigned int base = kms->module[i].base;
            unsigned int size = kms->module[i].size;
            if (pc > base && pc < (base + size))
            {
                string current_module = string(kms->module[i].file);
                if (current_module.find("ntkrnlpa") != string::npos ||
                    current_module.find("ntoskrnl") != string::npos)
                {
                    found = true;
                    break;
                }
                set<target_ulong> address_set;
                auto dll_element = kernel_module_address_map.find(current_module);
                if (dll_element != kernel_module_address_map.end())
                {
                    address_set = dll_element->second;
                }
                else
                {
                    address_set = add_module_address(kms->module[i].file, true);
                }
                if (address_set.count(pc - base))
                {
                    found = true;
                }
                break;
            }
        }
        free_osimodules(kms);
    }
    return found;
}

void on_call(CPUState *env, target_ulong pc)
{
    // printf("CURRENT PC:%ul\n",pc);
    //    get_library_name(env, pc, "On Call - Destination");
    OsiProc *current = get_current_process(env);
    // bool missing_dll=false;
    bool found = check_destination_address(env, current, pc);
    if (!found)
    {
        //        if(get_library_name(env, pc, "On Call - Destination")) {
        //        update_lists(env);
        //        found = check_destination_address(current, pc);
        //        if (!found) {
        //            if (!check_kernel_exec(env, pc)) {
        get_library_name(env, pc, "On Call");
        bool kernel_state = panda_in_kernel(env);
        //                update_lists(env);
        //                if (!check_destination_address(current, pc)) {
        printf("VIOLATION - %lu doesn't found into whitelist for process %lu:%s\n", pc, current->pid, current->name);
        printf("[%s][%lu - %s] Violation on call %u\n", kernel_state ? "KERNEL" : "USER", current->pid, current->name,
               pc);

        //                }
        //            }
        //        }
        //        }
        // }
    }
    free_osiproc(current);
}

void on_call_2(CPUState *env, target_ulong pc)
{
    bool kernel_state = panda_in_kernel(env);
    //    char system_name[] = "System";
    OsiProc *current = get_current_process(env);
    target_ulong thread = get_current_thread(env);
#ifndef TARGET_ARM
    if (DEBUG)
    {
        //        get_library_name(env, pc, "On Call - Source");
        printf("[%s] [%lu - %lu] Source %lu - ESP: %lu\n", kernel_state ? "KERNEL" : "USER", current->pid, thread, pc, env->regs[R_ESP]);
    }
#endif
    target_ulong pid = current->pid;
    ///// COMMENT THIS TO USE THREAD
    thread = pid;
    if (kernel_state)
    {
        //        auto current_data = kernel_stack.find(pid);
        auto current_data = kernel_stack.find(thread);
        stack<target_ulong> current_stack;
        if (current_data != kernel_stack.end())
        {
            current_stack = current_data->second;
        }
        current_stack.push(pc);
        kernel_stack[thread] = current_stack;
    }
    else
    {
        auto current_data = user_stack.find(pid);
        stack<target_ulong> current_stack;
        if (current_data != user_stack.end())
        {
            current_stack = current_data->second;
        }
        current_stack.push(pc);
        user_stack[pid] = current_stack;
    }
}

void on_ret(CPUState *env, target_ulong pc)
{
    if (swap_context_address_set.size() < 1)
    {
        load_SwapContext_Address(env);
    }
    OsiProc *current = get_current_process(env);
    target_ulong current_pc = panda_current_pc(env);
    bool kernel_state = panda_in_kernel(env);
    if (!check_return_address(env, current, current_pc, kernel_state))
    {
        //        if (!check_return_address(env, current, current_pc, !kernel_state)) {
        //            get_library_name(env, current_pc, "On Ret");
        //#ifndef TARGET_ARM
        //        printf("[%s] [%lu - %lu] %s - VIOLATION - Current address:%u - ESP:%lu\n", kernel_state ? "KERNEL" : "USER", current->pid, get_current_thread(env), current->name,
        //               current_pc, env->regs[R_ESP]);
        //#endif
        get_library_name(env, pc, "On Return");
        printf("[%s][%lu - %s] Violation on return %u\n", kernel_state ? "KERNEL" : "USER", current->pid, current->name,
               pc);
        //        }
    }
}
void uninit_plugin(void *self)
{
    panda_disable_precise_pc();
    panda_free_args(args);
    printf("Unloading plugin cfi\n");
}

bool init_plugin(void *self)
{
    //#if defined(TARGET_I386)  || defined(TARGET_X86_64)
    printf("Initializing plugin cfi\n");
    args = panda_get_args("cfi");
    DEBUG = panda_parse_bool(args, "DEBUG");
    //     DEBUG = true;

    stored_wl = panda_parse_string(args, "stored_wl", "/home/giuseppe/PassaggioDati/file_wl/");
    panda_enable_precise_pc();

    panda_require("callstack_instr");
    if (!init_callstack_instr_api())
        return false;
    if (!init_osi_api())
        return false;
    PPP_REG_CB("callstack_instr", on_call_2, on_call_2);
    PPP_REG_CB("callstack_instr", on_call, on_call);
    PPP_REG_CB("callstack_instr", on_ret, on_ret);
    printf("CFI plugin loaded\nDEBUG mode %s\nFolder with stored whitelists: %s\n", DEBUG ? "enabled" : "disabled", stored_wl);
    return true;
    //#else
    //    cout << "CFI plugin not supported on this architecture" << endl;
    //    return false;
    //#endif
}
