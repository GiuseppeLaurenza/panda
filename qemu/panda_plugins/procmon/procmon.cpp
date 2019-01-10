

#define __STDC_FORMAT_MACROS

// Choose a granularity for the OSI code to be invoked.
#define INVOKE_FREQ_PGD
//#define INVOKE_FREQ_BBL

#include <string>
#include <iostream>
#include <algorithm>
#include <map>
#include <list>
#include <set>



extern "C" {
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"

#include "rr_log.h"

#include "procmon.h"

#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

bool init_plugin(void *);
void uninit_plugin(void *);

int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd);
int before_block_exec(CPUState *env, TranslationBlock *tb);
void update_lists(CPUState *env);

PPP_PROT_REG_CB(new_process_notify);
PPP_PROT_REG_CB(removed_process_notify);
PPP_PROT_REG_CB(new_module_notify);
PPP_PROT_REG_CB(removed_module_notify);
PPP_PROT_REG_CB(new_main_module_notify);
PPP_PROT_REG_CB(removed_main_module_notify);
PPP_PROT_REG_CB(new_kernmod_notify) ;
PPP_PROT_REG_CB(removed_kernmod_notify) ;
}

PPP_CB_BOILERPLATE(new_process_notify);
PPP_CB_BOILERPLATE(removed_process_notify);
PPP_CB_BOILERPLATE(new_module_notify);
PPP_CB_BOILERPLATE(removed_module_notify);
PPP_CB_BOILERPLATE(new_main_module_notify);
PPP_CB_BOILERPLATE(removed_main_module_notify);
PPP_CB_BOILERPLATE(removed_kernmod_notify);
PPP_CB_BOILERPLATE(new_kernmod_notify);

using namespace std;

//map< pair <long unsigned int, string>, list<OsiModule> > library_map;
map<OsiProc, set<OsiModule> > library_map;
set<OsiProc> proc_set;
set<OsiModule> kernel_module_set;


bool operator<(OsiModule const &a, OsiModule const &b) {
    string a_name(a.name);
    string a_concat = a_name + to_string(a.size) + "_" + to_string(a.base);
    string b_name(b.name);
    string b_concat = b_name + to_string(b.size) + "_" + to_string(b.base);
    bool result = a_concat < b_concat;
    return result;
}

bool operator<(OsiProc const &a, OsiProc const &b) {
    string a_name(a.name);
    string a_concat = a_name + to_string(a.pid);
    string b_name(b.name);
    string b_concat = b_name + to_string(b.pid);
    bool result = a_concat < b_concat;
    return result;
}

void remove_processes(CPUState *env, set<OsiProc> to_remove) {
    if (to_remove.size() == 0) {
        return;
    }
    set<OsiProc>::iterator it;
    for (it = to_remove.begin(); it != to_remove.end(); ++it) {
        OsiProc current = *it;
        proc_set.erase(current);
//        printf("REMOVED PROCESS: %lu - %s\n", it->pid, it->name);
        PPP_RUN_CB(removed_process_notify, env, current.pid, current.name);
    }
}

void remove_kernel_modules(CPUState *env, set<OsiModule> to_remove) {
    if (to_remove.size() == 0) {
        return;
    }
    set<OsiModule>::iterator it;
    for (it = to_remove.begin(); it != to_remove.end(); ++it) {
        kernel_module_set.erase(*it);
        PPP_RUN_CB(removed_kernmod_notify, env, it->name, it->file, it->size, it->base);
    }
}

void add_processes(CPUState *env, set<OsiProc> to_add) {
    if (to_add.size() == 0) {
        return;
    }
    set<OsiProc>::iterator it;
    for (it = to_add.begin(); it != to_add.end(); ++it) {
//        printf("Add Process:%lu - %s\n", it->pid, it->name);
        OsiProc current = *it;
        if (proc_set.insert(current).second) {
            PPP_RUN_CB(new_process_notify, env, it->pid, it->name);
            OsiModules *ms = get_libraries(env, &current);
            if (ms != NULL) {
                set<OsiModule> new_module_set;
                for (int j = 0; j < ms->num; j++) {
                    if (strcmp("(paged)", ms->module[j].name) != 0) {
                        new_module_set.insert(ms->module[j]);
                        if (strcmp(it->name, ms->module[j].name) == 0) {
                            //                        printf("Main Module: %s\n", ms->module[j].name);
                            PPP_RUN_CB(new_main_module_notify, env, it->name, it->pid, ms->module[j].name,
                                       ms->module[j].file, ms->module[j].size, ms->module[j].base);
                        }
                        //                    printf("Normal Module: %s\n", ms->module[j].name);
                        PPP_RUN_CB(new_module_notify, env, it->name, it->pid, ms->module[j].name, ms->module[j].file,
                                   ms->module[j].size, ms->module[j].base);
                    }
                }
                library_map[current] = new_module_set;
                //          printf("Library_map %d\n", library_map.size());
            }
        }
    }
}

void add_kernel_modules(CPUState *env, set<OsiModule> to_add) {
    if (to_add.size() == 0) {
        return;
    }
    set<OsiModule>::iterator it;
    for (it = to_add.begin(); it != to_add.end(); ++it) {
        if (kernel_module_set.insert(*it).second) {
            PPP_RUN_CB(new_kernmod_notify, env, it->name, it->file, it->size, it->base);
        }
    }
}

void update_modules(CPUState *env, set<OsiProc> proc_intersection_set) {
    set<OsiProc>::iterator it;
    for (it = proc_intersection_set.begin(); it != proc_intersection_set.end(); ++it) {
        OsiProc current = *it;
        OsiModules *ms = get_libraries(env, &current);
        if (ms != NULL) {
            bool paged = false;
            set<OsiModule> new_module_set;
            for (int j = 0; j < ms->num; j++) {
                if (strcmp("(paged)", ms->module[j].name) != 0) {
                    new_module_set.insert(ms->module[j]);
                } else {
                    paged = true;
                }
            }
            if(paged){
                continue;
            }
            auto process_from_map = library_map.find(current);
            if(process_from_map!=library_map.end()){
                set<OsiModule> old_set = process_from_map->second;
                set<OsiModule> to_add, to_remove, intersection_set;
                set_difference(old_set.begin(), old_set.end(), new_module_set.begin(), new_module_set.end(),
                               inserter(to_remove, to_remove.begin()));
                set_difference(new_module_set.begin(), new_module_set.end(), old_set.begin(), old_set.end(),
                               inserter(to_add, to_add.begin()));
                set<OsiModule>::iterator it2;
                for (it2 = to_add.begin(); it2 != to_add.end(); ++it2) {
                    if (strcmp(current.name, it2->name) == 0) {
//                        printf("Main Module: %s\n", ms->module[j].name);
                        PPP_RUN_CB(new_main_module_notify, env, current.name, current.pid, it2->name, it2->file,
                                   it2->size, it2->base);
                    }
//                    printf("Normal Module: %s\n", ms->module[j].name);
                    PPP_RUN_CB(new_module_notify, env, current.name, current.pid, it2->name, it2->file, it2->size,
                               it2->base);
                }
                for (it2 = to_remove.begin(); it2 != to_remove.end(); ++it2) {
                    if (strcmp(current.name, it2->name) == 0) {
//                        printf("Main Module: %s\n", ms->module[j].name);
                        PPP_RUN_CB(removed_main_module_notify, env, current.name, current.pid, it2->name, it2->file,
                                   it2->size, it2->base);
                    }
//                    printf("Normal Module: %s\n", ms->module[j].name);
                    PPP_RUN_CB(removed_module_notify, env, current.name, current.pid, it2->name, it2->file, it2->size,
                               it2->base);
                }
            }
        }
    }
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    OsiProcs *ps = get_processes(env);
    if (ps == NULL) {
        return 0;
    }
    set<OsiProc> new_proc_set;
    for (int i = 0; i < ps->num; i++) {
        new_proc_set.insert(ps->proc[i]);
    }
    set<OsiProc> to_add, to_remove, intersection_set;
    set_difference(proc_set.begin(), proc_set.end(), new_proc_set.begin(), new_proc_set.end(),
                   inserter(to_remove, to_remove.begin()));
    set_difference(new_proc_set.begin(), new_proc_set.end(), proc_set.begin(), proc_set.end(),
                   inserter(to_add, to_add.begin()));
    set_intersection(proc_set.begin(), proc_set.end(), new_proc_set.begin(), new_proc_set.end(),
                     inserter(intersection_set, intersection_set.begin()));
    remove_processes(env, to_remove);
    add_processes(env, to_add);
    update_modules(env, intersection_set);

    set<OsiModule> new_modkern_set;
    OsiModules *kms = get_modules(env);
    if(kms!=NULL){
        for (int i = 0; i < kms->num; i++) {
            new_modkern_set.insert(kms->module[i]);
        }
    }
    set<OsiModule> kern_to_add, kern_to_remove, kern_intersection;
    set_difference(kernel_module_set.begin(), kernel_module_set.end(), new_modkern_set.begin(), new_modkern_set.end(),
                   inserter(kern_to_remove, kern_to_remove.begin()));
    set_difference(new_modkern_set.begin(), new_modkern_set.end(), kernel_module_set.begin(), kernel_module_set.end(),
                   inserter(kern_to_add, kern_to_add.begin()));
    set_intersection(kernel_module_set.begin(), kernel_module_set.end(), new_modkern_set.begin(), new_modkern_set.end(),
                     inserter(kern_intersection, kern_intersection.begin()));
    add_kernel_modules(env, kern_to_add);
    remove_kernel_modules(env, kern_to_remove);

    return 0;
}

void update_lists(CPUState *env) {
//    printf("UPDATE LISTS\n");
    before_block_exec(env, NULL);
}

int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd) {
    // tb argument is not used by before_block_exec()
    return before_block_exec(env, NULL);
}

bool init_plugin(void *self) {
    printf ("Initialing plugin procmon\n");
#if defined(INVOKE_FREQ_PGD)
    // relatively short execution
    panda_cb pcb = {.after_PGD_write = vmi_pgd_changed};
    panda_register_callback(self, PANDA_CB_VMI_PGD_CHANGED, pcb);
#else
    // expect this to take forever to run
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
#endif
    if(!init_osi_api()) return false;
    return true;
}

void uninit_plugin(void *self) {
    printf ("Unloading plugin procmon\n");
}

