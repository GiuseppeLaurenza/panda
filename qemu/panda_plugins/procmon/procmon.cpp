

#define __STDC_FORMAT_MACROS

// Choose a granularity for the OSI code to be invoked.
#define INVOKE_FREQ_PGD
//#define INVOKE_FREQ_BBL

#include <string>
#include <iostream>
#include <map>
#include <vector>
#include <list>



extern "C" {
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"

#include "pandalog.h"
#include "rr_log.h"

#include "cpu.h"
#include "procmon.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd);
int before_block_exec(CPUState *env, TranslationBlock *tb);

PPP_PROT_REG_CB(new_process_notify);
PPP_PROT_REG_CB(removed_process_notify);
PPP_PROT_REG_CB(new_module_notify);
PPP_PROT_REG_CB(removed_module_notify);
PPP_PROT_REG_CB(new_main_module_notify);
PPP_PROT_REG_CB(removed_main_module_notify);
}

PPP_CB_BOILERPLATE(new_process_notify);
PPP_CB_BOILERPLATE(removed_process_notify);
PPP_CB_BOILERPLATE(new_module_notify);
PPP_CB_BOILERPLATE(removed_module_notify);
PPP_CB_BOILERPLATE(new_main_module_notify);
PPP_CB_BOILERPLATE(removed_main_module_notify);

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

using namespace std;

// #if defined(TARGET_I386) && !defined(TARGET_X86_64)

map<pair<long unsigned int, string>, list<OsiModule>> library_map;


char * convert_string(string str){
    char * result = new char[str.size() + 1];
    memcpy(result, str.c_str(), str.size() + 1);
    return result;
}

void lower_case_copy(char* dest, char* src){
    int len = strlen(src);
    memset(dest, 0, len+1);
    int i;
    for(i=0;i<len;i++){
        dest[i]=tolower(src[i]);
    }
}

void compute_libraries_list(CPUState *env, OsiProc* process, list<OsiModule>& modules_list){
    OsiModules *ms = get_libraries(env, process);
    if (ms != NULL) {
        int j;
        for (j = 0; j < ms->num; j++){
            if(strcmp("(paged)",ms->module[j].name)!=0){
                static uint32_t capacity = 16;
                OsiModule* current_module = (OsiModule *)malloc(sizeof(OsiModule) * capacity);
                current_module->base=ms->module[j].base;
                current_module->size=ms->module[j].size;
                current_module->name = (char*) malloc(strlen(ms->module[j].name)+1);
                // lower_case_copy(current_module->name, ms->module[j].name);
                strcpy(current_module->name, ms->module[j].name);
                current_module->file = (char*) malloc(strlen(ms->module[j].file)+1);
                // lower_case_copy(current_module->file, ms->module[j].file);
                strcpy(current_module->file, ms->module[j].file);
                modules_list.push_back(*current_module);
            }
        }
        free_osimodules(ms);
    }
}


void notify_insertion_list(CPUState *env, OsiProc* process, list<OsiModule> modules_list){
    auto iterator = modules_list.begin();
    while(iterator != modules_list.end()){
        PPP_RUN_CB(new_module_notify, env, process->name, process->pid, iterator->name, iterator->file, iterator->size, iterator->base);
        iterator++;
    }
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {

    OsiProcs *ps = get_processes(env);
    if (ps == NULL) {
        printf("Process list not available.\n");
    }
    else {
        int i;
        auto iterator = library_map.begin();
        while(iterator!=library_map.end()){
            bool find=false;
            for (i = 0; i < ps->num; i++){
                OsiProc* current = &(ps->proc[i]);
                if(strcmp(current->name, iterator->first.second.c_str())){
                    find=true;
                }
            }
            if(!find){
                char * my_argument = const_cast<char*>(iterator->first.second.c_str());
                PPP_RUN_CB(removed_process_notify, env, iterator->first.first, my_argument);
            }
            iterator++;
        }


        for (i = 0; i < ps->num; i++){
            OsiProc* current = &(ps->proc[i]);
            list<OsiModule> modules_list;
            OsiModules *ms = get_libraries(env, current);
            bool paged = false;
            if (ms != NULL) {
                int j;
                for (j = 0; j < ms->num; j++){
                    if(strcmp("(paged)",ms->module[j].name)!=0){
                        static uint32_t capacity = 16;
                        OsiModule* current_module = (OsiModule *)malloc(sizeof(OsiModule) * capacity);
                        current_module->base=ms->module[j].base;
                        current_module->size=ms->module[j].size;
                        current_module->name = (char*) malloc(strlen(ms->module[j].name)+1);
                        lower_case_copy(current_module->name, ms->module[j].name);
                        current_module->file = (char*) malloc(strlen(ms->module[j].file)+1);
                        lower_case_copy(current_module->file, ms->module[j].file);
                        modules_list.push_back(*current_module);
                    }else{
                        paged=true;
                    }
                }
                free_osimodules(ms);
            }else{
                continue;
            }
            if(paged){
                continue;
            }
            string current_proc_name(current->name);
            auto process_from_map = library_map.find(make_pair(current->pid, current_proc_name));
            if(process_from_map!=library_map.end()){
                auto key = process_from_map->first;
                list<OsiModule> old_list = process_from_map->second;
                for (list<OsiModule>::iterator current_new_module = modules_list.begin(); current_new_module != modules_list.end(); ++current_new_module){
                    bool find = false;
                    for(list<OsiModule>::iterator current_old_module = old_list.begin(); current_old_module != old_list.end(); ++current_old_module){
                        // printf("%s - %s \n",current_old_module->name,current_new_module->name);
                        if(strcmp(current_old_module->name,current_new_module->name)==0 && current_old_module->base==current_new_module->base && current_old_module->size == current_new_module->size){
                            find = true;
                            // printf("FOUND\n");
                            break;
                        }
                    }
                    if(!find){
                        // printf("%s: Inserted module %s\n", current->name,current_new_module->name);
                        // printf("NOT FOUND\n");
                        if(strcmp(current->name, current_new_module->name)==0){
                            PPP_RUN_CB(new_main_module_notify, env, current->name, current->pid, current_new_module->name, current_new_module->file, current_new_module->size, current_new_module->base);
                        }
                        PPP_RUN_CB(new_module_notify, env, current->name, current->pid, current_new_module->name, current_new_module->file, current_new_module->size, current_new_module->base);
                    }
                }

                for (list<OsiModule>::iterator current_old_module = old_list.begin(); current_old_module != old_list.end(); ++current_old_module){
                    bool find = false;
                    for(list<OsiModule>::iterator current_new_module = modules_list.begin(); current_new_module != modules_list.end(); ++current_new_module){
                        if(strcmp(current_old_module->name,current_new_module->name)==0 && current_old_module->base==current_new_module->base && current_old_module->size == current_new_module->size){
                            find = true;
                            // printf("FOUND\n");
                            break;
                        }
                    }
                    if(!find){
                        // printf("%s: Removed module %s\n", current->name, current_old_module->name);
                        // printf("NOT FOUND\n");
                        if(strcmp(current->name, current_old_module->name)==0){
                            PPP_RUN_CB(removed_main_module_notify, env, current->name, current->pid, current_old_module->name, current_old_module->file, current_old_module->size, current_old_module->base);
                        }
                        PPP_RUN_CB(removed_module_notify, env, current->name, current->pid, current_old_module->name, current_old_module->file, current_old_module->size, current_old_module->base);
                    }
                }
                library_map[make_pair(current->pid, current_proc_name)] = modules_list;
                //########################TODO DISCOVER HOW TO FREE OSIMODULE LIST
                // list<OsiModule>::iterator current_old_module = old_list.begin();
                // while (current_old_module != old_list.end()){
                //     OsiModule* temp = (OsiModule*) &current_old_module;
                //     current_old_module++;
                //     // printf("Prima della free ");
                //     // cout<< current_proc_name << endl;
                //     // free(temp);
                //     // free_osimodules(temp);
                //     printf("%s\n",temp->name);
                //     free(temp->file);
                //     free(temp->name);
                //     // if (temp) free(temp);
                //     // printf("Dopo la free\n");
                // }

            }else{
                // printf("Inserted: %u - %s\n", current->pid,current->name);
                PPP_RUN_CB(new_process_notify, env, current->pid, current->name);
                library_map.insert(make_pair(make_pair(current->pid,current_proc_name), modules_list));
                notify_insertion_list(env, current, modules_list);
            }
        }
        
    }
    
    free_osiprocs(ps);
    return 0;
}

int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd) {
    // tb argument is not used by before_block_exec()
    return before_block_exec(env, NULL);
}



// #endif 

bool init_plugin(void *self) {
// #if defined(TARGET_I386) && !defined(TARGET_X86_64)
    printf ("Initialing plugin procmon\n");
#if defined(INVOKE_FREQ_PGD)
    // relatively short execution
    panda_cb pcb = { .after_PGD_write = vmi_pgd_changed };
    panda_register_callback(self, PANDA_CB_VMI_PGD_CHANGED, pcb);
#else
    // expect this to take forever to run
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
#endif
    if(!init_osi_api()) return false;
// #endif
    return true;
}

void uninit_plugin(void *self) {
    printf ("Unloading plugin procmon\n");
}

