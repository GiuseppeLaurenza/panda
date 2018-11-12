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


extern "C" {
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "../common/prog_point.h"
// #include "panda/rr/rr_log.h"
// #include "panda/plog.h"
#include "pandalog.h"
#include "rr_log.h"
#include "cpu.h"
#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);
}
#include "../callstack_instr/callstack_instr.h"
#include "../callstack_instr/callstack_instr_ext.h"

#include "../procmon/procmon.h"
using namespace std;

map<target_ulong,stack<target_ulong>> user_stack;
map<target_ulong,stack<target_ulong>> kernel_stack;
// map<unsigned int, set<string> > wl_library_map;
map<unsigned int, set<unsigned int> > wl_library_map;
map<unsigned int, pair<unsigned int, unsigned int>> wl_mainmodule_map;

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

bool get_library_name(CPUState *env, target_ulong pc){
    OsiProc *current = get_current_process(env);
    OsiModules *ms = get_libraries(env, current);
    bool found = false;
    string dll_name = "";
    string file_name = "";
    target_ulong base_found = 0;
    if (ms != NULL) {
        for (int i = 0; i < ms->num; i++){
            unsigned int base = ms->module[i].base;
            unsigned int size = ms->module[i].size;
            if(pc>base && pc<(base+size)){
                dll_name = ms->module[i].name;
                file_name = ms->module[i].file;
                base_found = base;
                found = true;
                break;
            }
        }
    }
    if(found){
        cout << "Address " << pc - base_found << " is in " << dll_name << " with full path as: "<< file_name <<endl;
        return true;
    }else{
        // cout << "Address " << pc << endl;
        return false;
    }
}


void new_process_create(CPUState *env, unsigned int pid, char *proc_name) {
    if (DEBUG) {
        printf("Create New Process:%s\n", proc_name);
    }
}

void exit_process(CPUState *env, unsigned int pid, char *proc_name) {
    // if (DEBUG) {
        printf("Process %s Exited\n", proc_name);
    // }
    wl_library_map.erase(pid);
    wl_mainmodule_map.erase(pid);
}

void new_module_load(CPUState *env, char *proc_name, unsigned int pid, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    if (DEBUG) {
        printf("New Module loaded:%s\n", mod_filename);
    }
    string current_module = string(mod_filename);
    current_module.erase(0,3);
    replace( current_module.begin(), current_module.end(), '\\', '_');
    current_module += ".wl";
    current_module.insert(0, stored_wl);
    // cout << current_module << endl;
    // std::transform(current_module.begin(), current_module.end(), current_module.begin(), ::tolower);
    ifstream f (current_module);
    string line;
    auto found_element = wl_library_map.find(pid);
    set<unsigned int> address_list;
    if(found_element!=wl_library_map.end()){
        address_list = found_element->second;
    }
    while(getline(f, line)) {
        // std::transform(line.begin(), line.end(), line.begin(), ::tolower);
        stringstream ss;
        // ss << std::hex << line;
        unsigned int x;
        ss << line;
        ss >> x;
        address_list.insert(x+base);
        // cout << address_list.size() << endl;
    }
    wl_library_map.insert(make_pair(pid, address_list));
}

void module_unload(CPUState *env, char *proc_name, unsigned int pid, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    if (DEBUG) {
        printf("Unloaded Module %s\n", mod_name);
    }
    string current_module = string(mod_filename);
    current_module.erase(0,3);
    replace( current_module.begin(), current_module.end(), '\\', '_');
    current_module += ".wl";
    current_module.insert(0, stored_wl);
    std::transform(current_module.begin(), current_module.end(), current_module.begin(), ::tolower);

    ifstream f (current_module);
    string line;
    auto found_element = wl_library_map.find(pid);
    // set<string> address_list;
    set<unsigned int> address_list;
    if(found_element!=wl_library_map.end()){
        address_list = found_element->second;
        while(getline(f, line)) {
            std::transform(line.begin(), line.end(), line.begin(), ::tolower);
            stringstream ss;
            ss << std::hex << line;
            unsigned int x;
            ss >> x;
            address_list.erase(base + x);
        }
    }
    wl_library_map.insert(make_pair(pid, address_list));
}

void main_module_load(CPUState *env, char *proc_name, unsigned int pid, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    if (DEBUG) {
        printf("New Main Module loaded:%s\n", mod_name);
    }
    wl_mainmodule_map.insert(make_pair(pid, make_pair(base,base+size)));
}

void main_module_unload(CPUState *env, char *proc_name, unsigned int pid, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    if (DEBUG) {
        printf("Unloaded Main Module %s\n", mod_name);
    }
}

// bool check_wl(CPUState *env, target_ulong pc) {
//     return true;
// }

void on_call(CPUState *env, target_ulong pc){
    // printf("CURRENT PC:%ul\n",pc);
    bool found=false;
    OsiProc *current = get_current_process(env);
    auto main_module_range_elem = wl_mainmodule_map.find(current->pid);
    if(main_module_range_elem!=wl_mainmodule_map.end()){
        auto range = main_module_range_elem->second;
        if(pc>range.first && pc>range.second){
            found=true;
            printf("%lu found into whitelist for process %s\n", pc, current->name);
        }
    }else{
        auto wl_library = wl_library_map.find(current->pid);
        set<unsigned int> address_list;
        if(wl_library!=wl_library_map.end()){
            address_list = wl_library->second;
            auto check = address_list.find(pc);
                if(check!=address_list.end()){
                    found=true;
                    printf("%lu found into whitelist for process %lu:%s\n", pc,current->pid, current->name);
                }
        }
    }
    if(!found){
            if(get_library_name(env, pc)){
                printf("VIOLATION - %lu doesn't found into whitelist for process %lu:%s\n", pc, current->pid, current->name);
            }
    }
}

void on_call_2(CPUState *env, target_ulong pc) {
    printf("On Call2: %lu\n", pc);
    get_library_name(env, pc);
    target_ulong thread = get_current_thread(env);
    if (panda_in_kernel(env)) {
        auto current_data = kernel_stack.find(thread);
        stack<target_ulong> current_stack;
        if(current_data!=kernel_stack.end()){
            current_stack=current_data->second;
        }       
        current_stack.push(pc);
        kernel_stack.insert(make_pair(thread,current_stack));
    } else {
        auto current_data = user_stack.find(thread);
        stack<target_ulong> current_stack;
        if(current_data!=user_stack.end()){
            current_stack=current_data->second;
        }       
        current_stack.push(pc);
        user_stack.insert(make_pair(thread,current_stack));
    }
}


void on_ret(CPUState *env, target_ulong pc) {
    int i;
    // printf("%s: On Ret from %lu to %lu\n", panda_in_kernel(env) ? "KERNEL" : "USER", pc, panda_current_pc(env));
    target_ulong thread = get_current_thread(env);
    target_ulong temp;
    for (i = 0; i < POP_LEVEL; i++) {
        if (panda_in_kernel(env)) {
            auto current_data = kernel_stack.find(thread);
            stack<target_ulong> current_stack;
            if(current_data!=kernel_stack.end()){
                current_stack=current_data->second;    
                temp = current_stack.top();
                current_stack.pop();
                // printf("%u - %u - %u,%u\n", temp, panda_current_pc(env), kernel_stack.size(), user_stack.size());
                if (temp == panda_current_pc(env)) {
                    printf("VALID ADDRESS\n");
                    return;
                }
            } 
        } else {
            auto current_data = kernel_stack.find(thread);
            stack<target_ulong> current_stack;
            if(current_data!=kernel_stack.end()){
                current_stack=current_data->second;    
                temp = current_stack.top();
                current_stack.pop();
                // printf("%u - %u - %u,%u\n", temp, panda_current_pc(env), kernel_stack.size(), user_stack.size());
                if (temp == panda_current_pc(env)) {
                    printf("VALID ADDRESS\n");
                    return;
                }
            }
        }

    }
    // printf("%s - VIOLATION - Current address:%u - %lu,%lu\n", panda_in_kernel(env) ? "KERNEL" : "USER",panda_current_pc(env), kernel_stack.size(), user_stack.size());
    // if(get_library_name(env, pc)){
    //     printf("%s - VIOLATION - Current address:%u - %lu,%lu\n", panda_in_kernel(env) ? "KERNEL" : "USER",panda_current_pc(env), kernel_stack.size(), user_stack.size());
    // }
}

void uninit_plugin(void *self) {
    panda_disable_precise_pc();
    panda_free_args(args);
    printf("Unloading plugin cfi\n");
}

bool init_plugin(void *self) {
#if defined(TARGET_I386)  //&& !defined(TARGET_X86_64)
    printf("Initializing plugin cfi\n");
    args = panda_get_args("cfi");
    DEBUG = panda_parse_bool(args, "DEBUG");
    POP_LEVEL = panda_parse_double(args, "pop", 100.0);
    // original_disk = panda_parse_string(args,"original_disk","/home/giuseppe/qcow_copy/");
    stored_wl = panda_parse_string(args,"stored_wl","/home/giuseppe/file_wl/");
    panda_enable_precise_pc();
    panda_require("procmon");
    PPP_REG_CB("procmon", new_process_notify, new_process_create);
    PPP_REG_CB("procmon", removed_process_notify, exit_process);
    PPP_REG_CB("procmon", new_module_notify, new_module_load);
    // PPP_REG_CB("procmon", removed_module_notify, module_unload);
    PPP_REG_CB("procmon", new_main_module_notify, main_module_load);
    // PPP_REG_CB("procmon", removed_main_module_notify, main_module_unload);
    panda_require("callstack_instr");
    if (!init_callstack_instr_api()) return false;
    if(!init_osi_api()) return false;
    PPP_REG_CB("callstack_instr", on_call, on_call);
    PPP_REG_CB("callstack_instr", on_call_2, on_call_2);
    PPP_REG_CB("callstack_instr", on_ret, on_ret);
    // printf("CFI plugin loaded\nDEBUG mode %s\nLocal VM disk copy: %s\nFolder with stored whitelists: %s\nOn RET instruction, check stacks %lf levels\n", DEBUG ? "enabled" : "disabled", original_disk, stored_wl, POP_LEVEL);
    printf("CFI plugin loaded\nDEBUG mode %s\nFolder with stored whitelists: %s\nOn RET instruction, check stacks %lf levels\n", DEBUG ? "enabled" : "disabled", stored_wl, POP_LEVEL);
    return true;
#else
    cout << "CFI plugin not supported on this architecture" << endl;
    return false;
#endif
}