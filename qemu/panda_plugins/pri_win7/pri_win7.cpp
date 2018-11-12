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

#include <sstream>
#include <fstream>
#include <algorithm>
#include <string>
#include <iostream>
#include <iomanip>
#include "panda/panda_addr.h"
extern "C" {

#include "config.h"
#include "rr_log.h"
#include "qemu-common.h"
#include "panda_common.h"
#include "cpu.h"

#include "pandalog.h"
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"

#include "../pri/pri_types.h"
#include "../pri/pri_ext.h"
#include "../pri/pri.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

#include "../loaded/loaded.h"

bool init_plugin(void *);
void uninit_plugin(void *);
void on_ret(CPUState *env, target_ulong pc);
void on_call(CPUState *env, target_ulong pc);

}

#include "../callstack_instr/callstack_instr.h"
#include "../common/prog_point.h"
#include "../callstack_instr/callstack_instr_ext.h"

const char *basedir = NULL;

using namespace std;

string intToHexString(int intValue) {
    string hexStr;
    // integer value to hex-string
    stringstream sstream;
    sstream << "0x" << setfill('0') << setw(8) << hex << (int)intValue;
    hexStr= sstream.str();
    sstream.clear();    //clears out the stream-string
    return hexStr;
}

void check_libraries_cpp(CPUState *env, target_ulong pc, int isCall){
    OsiProc *current = get_current_process(env);
    OsiModules *ms = get_libraries(env, current);
    if (ms != NULL) {
        for (int i = 0; i < ms->num; i++){
            unsigned int base = ms->module[i].base;
            unsigned int size = ms->module[i].size;
            if(pc>base && pc<(base+size)){
                string dll_name = ms->module[i].name;
                if (dll_name.find("(paged)") != string::npos){
                    continue;
                }
                replace(dll_name.begin(), dll_name.end(),'\\','_');
                string lowername;
                transform(dll_name.begin(), dll_name.end(), back_inserter(lowername), ::tolower);
                string path_file = string(basedir) + lowername;
                string funct_name;
                ifstream f (path_file);
                string line;
                while(getline(f, line)) {
                    string address= intToHexString(pc-base);
                    transform(address.begin(), address.end(), address.begin(), ::tolower);
                    if(line.find(address)!= string::npos){
                        istringstream ss(line);
                        std::getline(ss, funct_name, ',');
                    }
                }
                if(funct_name.empty()){
                    funct_name = dll_name+string("_func_0");
                }
                //TODO add into the text file the line number data
                if(isCall){
                    pri_runcb_on_fn_start(env, pc, dll_name.c_str(), funct_name.c_str(),0);
                }else{
                    pri_runcb_on_fn_return(env, pc, dll_name.c_str(), funct_name.c_str(),0);
                }
            }
        }
    }
    free_osiproc(current);
    free_osimodules(ms);  
}

void on_ret(CPUState *env, target_ulong pc){
    // check_libraries(env, pc, 0);
    check_libraries_cpp(env, pc, 0);
}

void on_call(CPUState *env, target_ulong pc){
    // check_libraries(env, pc, 1);
    check_libraries_cpp(env, pc, 1);
}

bool init_plugin(void *self){
#if defined(TARGET_I386)
    printf("Initializing plugin pri_win7\n");
    panda_arg_list *args = panda_get_args("pri_win7");
    basedir = panda_parse_string(args, "base", "/tmp");
    printf("Pri win7 using basedir=%s\n", basedir);
 
    panda_require("callstack_instr");
    if (!init_callstack_instr_api()) return false;
    panda_require("osi");
    if (!init_osi_api()) return false;
    panda_require("pri");
    if (!init_pri_api()) return false;

    PPP_REG_CB("callstack_instr", on_call, on_call);
    PPP_REG_CB("callstack_instr", on_ret, on_ret);
#endif
    return true;
}

void uninit_plugin(void *self) {
    printf("Unload pri_win7 plugin\n");
 }