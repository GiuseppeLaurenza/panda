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

#include "config.h"
#include "cpu.h"
#include "panda/panda_addr.h"
#include "panda_common.h"
#include "qapi-types.h"
#include "qemu-common.h"
#include "qemu-timer.h"
#include "rr_log.h"

#include "data.h"

#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "pandalog.h"

// #include "../libfi/libfi_object.h"
#include "../libfi/libfi.h"
#include "../libfi/libfi_ext.h"


#include "../procmon/procmon.h"

#include "string.h"

#include "cfi.h"
#include "libdasm.h"
#include "recon.h"

bool init_plugin(void *);
void uninit_plugin(void *);
static void cfi_cleanup(void);

static plugin_interface_t wl_interface;
int enum_exp_table_reloc_table_to_wl(char *filename, uint32_t base, char *name, struct bin_file *file);

/* Hash table to hold the cr3 to process entry mapping */
GHashTable *cr3_pe_ht;

/* Hash table to hold the full file name to file entry */
GHashTable *filemap_ht;

/* Hash table to keep track of clashes. Shouldn't exist. :( */
GHashTable *vio_ht;

/* Some counters to keep track of hits/misses */
uint32_t hit_counter = 0;
uint32_t miss_counter = 0;
uint32_t stack_match = 0;
uint32_t miss_ret1 = 0, miss_ret2 = 0;
uint32_t dyn_hit_counter = 0;
uint32_t matched_call_ret = 0;
uint32_t stack_top = 0;
uint32_t stack_linear = 0;
uint32_t st_contains = 0;
struct proc_entry *sys_proc_cfi = NULL;
uint32_t system_loaded = 0;
unsigned long call_count = 0;
unsigned long ret_count = 0;

// extern uint32_t system_cr3=0;
uint32_t system_cr3 = 0;
// struct proc_entry *sys_proc_cfi = NULL;
static char wl_dir[256];

char C_DRIVE[256] = "\\home\\giuseppe\\qcow_copy";
char *FOLDER = "/home/giuseppe/qcow_copy_wl/";

bool DEBUG = true;

struct cr3_info {
    uint32_t value;
    GHashTable *vaddr_tbl;
    GHashTable *modules_tbl;
};

static mon_cmd_t wl_info_cmds[] = {
    {
        NULL,
        NULL,
    },
};

// static int wl_init(void* self);
// static void cfi_cleanup(void);
// extern void WL_cleanUp();
// extern void recon_init();

extern uint32_t *WL_Extract(char *file_name, uint32_t *entries, uint32_t *code_base, struct bin_file *file);

// struct hook_data {
// 	uintptr_t handle;
// };

//recon variables
QLIST_HEAD(loadedlist_head, service_entry)
loadedlist;
QLIST_HEAD(processlist_head, process_entry)
processlist;
QLIST_HEAD(threadlist_head, thread_entry)
threadlist;
QLIST_HEAD(filelist_head, file_entry)
filelist;
GHashTable *cr3_hashtable = NULL;
GHashTable *eproc_ht = NULL;

struct process_entry *system_proc = NULL;

uint32_t gkpcr;
uint32_t GuestOS_index;
// uintptr_t insn_handle = 0;
uintptr_t block_handle = 0;
// uint32_t system_cr3 = 0;
BYTE *recon_file_data_raw = 0;

static QEMUTimer *recon_timer = NULL;

unsigned long long insn_counter = 0;

#if defined(TARGET_I386)  //&& !defined(TARGET_X86_64)
// #if defined(TARGET_X86_64)

struct Data Stack_Pop_until(Stack *s, int index) {
    int i = 0;
    struct Data ret;
    ret.data = ret.esp = 0;

    if (index >= s->size) {
        monitor_printf(default_mon, "Invalid index. %d in stack 0x%08x\n", index, s);
        if (DEBUG) {
            printf("Invalid index. %d in stack 0x%08x\n", index, s);
        }
        vm_stop(0);
    }

    for (i = s->size - 1; i >= index; i--) {
        ret.data = s->data[i].data;
        ret.esp = s->data[i].esp;
        g_hash_table_remove(s->ht, ret.esp);
    }
    s->size = index;

    return ret;
}

static inline int get_insn_len(uint8_t *insn_bytes) {
    INSTRUCTION inst;
    int len;
    len = get_instruction(&inst, insn_bytes, MODE_32);
    return len;
}

uint32_t get_cr3_from_proc_base(uint32_t base) {
    CPUState *env;
    uint32_t cr3;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        if (env->cpu_index == 0) {
            break;
        }
    }
    cpu_memory_rw_debug(env, base + 0x18, (uint8_t *)&cr3, 4, 0);
    //vm_stop(0);

    return cr3;
}

// traverse handle table 1st level for win7
uint32_t w7_traverse_level1(uint32_t tableaddr, CPUState *env) {
    uint32_t count = 1;
    uint32_t object_body_addr, object_header_addr, info_mask;
    uint8_t object_type_index;
    W7TYPE_TABLE type = File;

    struct file_entry *fe;
    do {
        fe = (struct file_entry *)malloc(sizeof(struct file_entry));
        cpu_memory_rw_debug(env, tableaddr + count * 0x08, (uint8_t *)&object_header_addr, 4, 0);
        object_header_addr &= 0xffffffff8;

        if (object_header_addr == 0) {
            continue;
        }
        cpu_memory_rw_debug(env, object_header_addr + 0x0c, (uint8_t *)&object_type_index, 2, 0);
        cpu_memory_rw_debug(env, object_header_addr + 0xe, (uint8_t *)&info_mask, 4, 0);
        object_body_addr = object_header_addr + 0x18;

        if (object_type_index == type) {
            char file_type[32] = "File";
            fe->file_object_base = object_header_addr;
            strcpy(fe->type, file_type);
            readustr(object_body_addr + 0x30, fe->filename, env);
            QLIST_INSERT_HEAD(&filelist, fe, loadedlist_entry);
        }
    } while (++count <= 511);
    return 0;
}

uint32_t traverse_level1(uint32_t tableaddr, CPUState *env) {
    uint32_t count = 1;
    uint32_t object_body_addr, object_header_addr, object_type_addr, nameinfo_offset;
    uint32_t handle_table;

    char type[1024];
    char file[] = "File";
    //char proc[] = "Process";

    struct file_entry *fe;
    do {
        fe = (struct file_entry *)malloc(sizeof(struct file_entry));
        cpu_memory_rw_debug(env, tableaddr + count * 0x08, (uint8_t *)&object_header_addr, 4, 0);
        object_header_addr &= 0xffffffff8;
        if (object_header_addr == 0) {
            continue;
        }
        cpu_memory_rw_debug(env, object_header_addr + 0x08, (uint8_t *)&object_type_addr, 4, 0);
        cpu_memory_rw_debug(env, object_header_addr + 0x0c, (uint8_t *)&nameinfo_offset, 4, 0);
        object_body_addr = object_header_addr + 0x18;
        readustr(object_type_addr + 0x40, type, env);
        //monitor_printf(default_mon,"here we are%s\n", type);
        if (DEBUG) {
            printf("here we are%s\n", type);
        }
        if (strcmp(type, file) == 0) {
            fe->file_object_base = object_header_addr;
            strcpy(fe->type, type);
            readustr(object_body_addr + 0x30, fe->filename, env);
            QLIST_INSERT_HEAD(&filelist, fe, loadedlist_entry);
        }
    } while (++count <= 511);
    return 0;
}

uint32_t traverse_level2(uint32_t tableaddr, CPUState *env) {
    uint32_t level2_table_ptr;
    uint32_t level2_next_table_ptr;
    do {
        cpu_memory_rw_debug(env, tableaddr, (uint8_t *)&level2_table_ptr, 4, 0);
        if (GuestOS_index < 2) {
            traverse_level1(level2_table_ptr, env);
        } else {
            w7_traverse_level1(level2_table_ptr, env);
        }

        tableaddr += 0x04;
        cpu_memory_rw_debug(env, tableaddr, (uint8_t *)&level2_next_table_ptr, 4, 0);
    } while (level2_next_table_ptr != 0);
    return 0;
}

uint32_t traverse_level3(uint32_t tableaddr, CPUState *env) {
    uint32_t level3_table_ptr;
    uint32_t level3_next_table_ptr;
    do {
        cpu_memory_rw_debug(env, tableaddr, (uint8_t *)&level3_table_ptr, 4, 0);
        traverse_level2(level3_table_ptr, env);
        tableaddr += 0x04;
        cpu_memory_rw_debug(env, tableaddr, (uint8_t *)&level3_next_table_ptr, 4, 0);
    } while (level3_next_table_ptr != 0);
    return 0;
}

struct vp_hook_info {
    uint32_t addr;
    uint32_t size;
    uintptr_t handle;
};

int clear_list(int type) {
    struct process_entry *proc = NULL;
    struct service_entry *se = NULL;
    struct file_entry *fe = NULL;
    struct thread_entry *te = NULL;
    struct pe_entry *pef = NULL;
    struct api_entry *api = NULL;

    if (type == 0 && !QLIST_EMPTY(&loadedlist)) {
        QLIST_FOREACH(se, &loadedlist, loadedlist_entry) {
            QLIST_REMOVE(se, loadedlist_entry);
            free(se);
        }
        return 0;
    }

    if (type == 1 && !QLIST_EMPTY(&processlist)) {
        QLIST_FOREACH(proc, &processlist, loadedlist_entry) {
            if (!QLIST_EMPTY(&proc->modlist_head)) {
                QLIST_FOREACH(pef, &proc->modlist_head, loadedlist_entry) {
                    if (!QLIST_EMPTY(&pef->apilist_head)) {
                        QLIST_FOREACH(api, &pef->apilist_head, loadedlist_entry) {
                            QLIST_REMOVE(api, loadedlist_entry);
                            free(api);
                        }
                    }
                    QLIST_REMOVE(pef, loadedlist_entry);
                    free(pef);
                }
            }
            QLIST_REMOVE(proc, loadedlist_entry);
            free(proc);
        }
        return 0;
    }

    if (type == 2 && !QLIST_EMPTY(&threadlist)) {
        QLIST_FOREACH(te, &threadlist, loadedlist_entry) {
            QLIST_REMOVE(te, loadedlist_entry);
            free(te);
        }
        return 0;
    }
    if (type == 3 && !QLIST_EMPTY(&filelist)) {
        QLIST_FOREACH(fe, &filelist, loadedlist_entry) {
            QLIST_REMOVE(fe, loadedlist_entry);
            free(fe);
        }
        return 0;
    }
    return -1;
}

static void update_loaded_kernel_modulelist() {
    uint32_t kdvb, psLM, curr_mod, next_mod;
    CPUState *env;
    struct service_entry *se;
    uint32_t holder;

    if (gkpcr == 0)
        return;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        if (env->cpu_index == 0) {
            break;
        }
    }
    // clear list
    clear_list(MODULES);

    cpu_memory_rw_debug(env, gkpcr + KDVB_OFFSET, (uint8_t *)&kdvb, 4, 0);
    cpu_memory_rw_debug(env, kdvb + PSLM_OFFSET, (uint8_t *)&psLM, 4, 0);
    cpu_memory_rw_debug(env, psLM, (uint8_t *)&curr_mod, 4, 0);

    while (curr_mod != 0 && curr_mod != psLM) {
        se = (struct service_entry *)malloc(sizeof(struct service_entry));
        cpu_memory_rw_debug(env, curr_mod + handle_funds[GuestOS_index].offset->DLLBASE_OFFSET, (uint8_t *)&(se->base), 4, 0);  // dllbase  DLLBASE_OFFSET
        cpu_memory_rw_debug(env, curr_mod + handle_funds[GuestOS_index].offset->SIZE_OFFSET, (uint8_t *)&(se->size), 4, 0);     // dllsize  SIZE_OFFSET
        holder = readustr(curr_mod + handle_funds[GuestOS_index].offset->DLLNAME_OFFSET, se->name, env);

        QLIST_INSERT_HEAD(&loadedlist, se, loadedlist_entry);

        cpu_memory_rw_debug(env, curr_mod, (uint8_t *)&next_mod, 4, 0);
        cpu_memory_rw_debug(env, next_mod + 4, (uint8_t *)&holder, 4, 0);
        if (holder != curr_mod) {
            monitor_printf(default_mon,
                           "Something is wrong. Next->prev != curr. curr_mod = 0x%08x\n",
                           curr_mod);
            if (DEBUG) {
                printf("Something is wrong. Next->prev != curr. curr_mod = 0x%08x\n",
                       curr_mod);
            }
            //vm_stop(0);
        }
        curr_mod = next_mod;
    }
}

static void update_active_processlist() {
    uint32_t kdvb, psAPH, curr_proc, next_proc, handle_table;
    CPUState *env;
    struct process_entry *pe;

    if (gkpcr == 0)
        return;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        if (env->cpu_index == 0) {
            break;
        }
    }
    clear_list(PROC);
    cpu_memory_rw_debug(env, gkpcr + KDVB_OFFSET, (uint8_t *)&kdvb, 4, 0);
    cpu_memory_rw_debug(env, kdvb + PSAPH_OFFSET, (uint8_t *)&psAPH, 4, 0);
    cpu_memory_rw_debug(env, psAPH, (uint8_t *)&curr_proc, 4, 0);

    while (curr_proc != 0 && curr_proc != psAPH) {
        pe = (struct process_entry *)malloc(sizeof(struct process_entry));
        memset(pe, 0, sizeof(*pe));

        pe->EPROC_base_addr = curr_proc - handle_funds[GuestOS_index].offset->PSAPL_OFFSET;
        pe->cr3 = get_cr3_from_proc_base(pe->EPROC_base_addr);
        uint32_t curr_proc_base = pe->EPROC_base_addr;

        cpu_memory_rw_debug(env, curr_proc_base + handle_funds[GuestOS_index].offset->PSAPNAME_OFFSET, (uint8_t *)&(pe->name), NAMESIZE, 0);
        cpu_memory_rw_debug(env, curr_proc_base + handle_funds[GuestOS_index].offset->PSAPID_OFFSET, (uint8_t *)&(pe->process_id), 4, 0);
        cpu_memory_rw_debug(env, curr_proc_base + handle_funds[GuestOS_index].offset->PSAPPID_OFFSET, (uint8_t *)&(pe->ppid), 4, 0);
        cpu_memory_rw_debug(env, curr_proc_base + handle_funds[GuestOS_index].offset->PSAPTHREADS_OFFSET, (uint8_t *)&(pe->number_of_threads), 4, 0);
        cpu_memory_rw_debug(env, curr_proc_base + handle_funds[GuestOS_index].offset->PSAPHANDLES_OFFSET, (uint8_t *)&(handle_table), 4, 0);
        cpu_memory_rw_debug(env, handle_table, (uint8_t *)&(pe->table_code), 4, 0);
        cpu_memory_rw_debug(env, handle_table + handle_funds[GuestOS_index].offset->HANDLE_COUNT_OFFSET, (uint8_t *)&(pe->number_of_handles), 4, 0);

        QLIST_INSERT_HEAD(&processlist, pe, loadedlist_entry);

        cpu_memory_rw_debug(env, curr_proc, (uint8_t *)&next_proc, 4, 0);
        curr_proc = next_proc;
    }

    /* Update the process data structures in procmod */

    //	procmod_remove_all();
    //	QLIST_FOREACH(pe, &processlist, loadedlist_entry) {
    //		procmod_createproc(pe->process_id, pe->ppid,
    //			       get_cr3_from_proc_base(pe->EPROC_base_addr), pe->name);
    //	}
}

static void update_active_threadlist() {
    uint32_t kdvb, psAPH, thrdLH, curr_proc, next_proc;
    uint32_t curr_thrd, next_thrd, trapframe;
    CPUState *env;
    struct thread_entry *te = NULL;
    struct tcb *_tcb = NULL;

    if (gkpcr == 0)
        return;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        if (env->cpu_index == 0) {
            break;
        }
    }
    clear_list(THRD);
    cpu_memory_rw_debug(env, gkpcr + KDVB_OFFSET, (uint8_t *)&kdvb, 4, 0);
    cpu_memory_rw_debug(env, kdvb + PSAPH_OFFSET, (uint8_t *)&psAPH, 4, 0);
    cpu_memory_rw_debug(env, psAPH, (uint8_t *)&curr_proc, 4, 0);

    while (curr_proc != 0 && curr_proc != psAPH) {
        thrdLH = curr_proc - handle_funds[GuestOS_index].offset->PSAPL_OFFSET + handle_funds[GuestOS_index].offset->THREADLH_OFFSET;
        cpu_memory_rw_debug(env, thrdLH, (uint8_t *)&(curr_thrd), 4, 0);
        while (curr_thrd != 0 && curr_thrd != thrdLH) {
            te = (struct thread_entry *)malloc(sizeof(struct thread_entry));
            _tcb = (struct tcb *)malloc(sizeof(struct tcb));

            te->tcb = _tcb;
            te->ETHREAD_base_addr = curr_thrd - handle_funds[GuestOS_index].offset->THREADENTRY_OFFSET;
            cpu_memory_rw_debug(env, curr_thrd - handle_funds[GuestOS_index].offset->THREADENTRY_OFFSET + handle_funds[GuestOS_index].offset->TRAPFRAME_OFFSET, (uint8_t *)&(trapframe), 4, 0);
            cpu_memory_rw_debug(env, trapframe + 0x44, (uint8_t *)&(_tcb->_EAX), 4, 0);
            cpu_memory_rw_debug(env, trapframe + 0x5c, (uint8_t *)&(_tcb->_EBX), 4, 0);
            cpu_memory_rw_debug(env, trapframe + 0x40, (uint8_t *)&(_tcb->_ECX), 4, 0);
            cpu_memory_rw_debug(env, trapframe + 0x3c, (uint8_t *)&(_tcb->_EDX), 4, 0);
            cpu_memory_rw_debug(env, curr_thrd - handle_funds[GuestOS_index].offset->THREADENTRY_OFFSET + handle_funds[GuestOS_index].offset->THREADCID_OFFSET, (uint8_t *)&(te->owning_process_id), 4, 0);
            cpu_memory_rw_debug(env, curr_thrd - handle_funds[GuestOS_index].offset->THREADENTRY_OFFSET + handle_funds[GuestOS_index].offset->THREADCID_OFFSET + 0x04, (uint8_t *)&(te->thread_id), 4, 0);

            QLIST_INSERT_HEAD(&threadlist, te, loadedlist_entry);
            cpu_memory_rw_debug(env, curr_thrd, (uint8_t *)&next_thrd, 4, 0);
            curr_thrd = next_thrd;
        }

        cpu_memory_rw_debug(env, curr_proc, (uint8_t *)&next_proc, 4, 0);
        curr_proc = next_proc;
    }
}

static void update_opened_filelist() {
    uint32_t kdvb, psAPH, curr_proc, next_proc, num_handles, handle_table,
        table_code;
    CPUState *env;
    uint32_t tablecode;
    uint32_t level;

    if (gkpcr == 0)
        return;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        if (env->cpu_index == 0) {
            break;
        }
    }
    //TODO FIND WHAT IS FILE
    // clear_list(FILE);
    cpu_memory_rw_debug(env, gkpcr + KDVB_OFFSET, (uint8_t *)&kdvb, 4, 0);
    cpu_memory_rw_debug(env, kdvb + PSAPH_OFFSET, (uint8_t *)&psAPH, 4, 0);
    cpu_memory_rw_debug(env, psAPH, (uint8_t *)&curr_proc, 4, 0);

    while (curr_proc != 0 && curr_proc != psAPH) {
        cpu_memory_rw_debug(env, curr_proc - handle_funds[GuestOS_index].offset->PSAPL_OFFSET + handle_funds[GuestOS_index].offset->PSAPHANDLES_OFFSET, (uint8_t *)&(handle_table), 4, 0);
        cpu_memory_rw_debug(env, handle_table + handle_funds[GuestOS_index].offset->HANDLE_COUNT_OFFSET, (uint8_t *)&(num_handles), 4, 0);
        cpu_memory_rw_debug(env, handle_table, (uint8_t *)&(table_code), 4, 0);

        level = table_code & 3;
        tablecode = table_code & 0xfffffffc;
        //char* file = "File";
        switch (level) {
            case 0:
                // choose one func
                if (GuestOS_index < 2) {
                    traverse_level1(tablecode, env);
                } else {
                    w7_traverse_level1(tablecode, env);
                }
                break;
            case 1:
                traverse_level2(tablecode, env);
                break;
            case 2:
                traverse_level3(tablecode, env);
                break;
            default:
                break;
        }
        cpu_memory_rw_debug(env, curr_proc, (uint8_t *)&next_proc, 4, 0);
        curr_proc = next_proc;
    }
}

//from libfi_add_callback("ntdll.dll", "ZwLoadDriver", 1, 0, get_result);
void get_result(CPUState *env, target_ulong pc, uint8_t *args) {
    // CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
    monitor_printf(default_mon, "HIT!: 0x%08x\n", env->eip);
    if (DEBUG) {
        printf("HIT!: 0x%08x\n", env->eip);
    }
}

void hook_test() {
    //TODO Find if is useful to do this things
    // int pid = find_pid_by_name("smss.exe");
    // monitor_printf(default_mon,"pid: %d\n", pid);
    // uint32_t cr3 = find_cr3(pid);
    // monitor_printf(default_mon,"cr3: 0x%08x\n", cr3);

    // hookapi_hook_function_byname("ntdll.dll", "ZwLoadDriver",1, cr3 , get_result, NULL, 0);
    libfi_add_callback("ntdll.dll", "ZwLoadDriver", 1, 0, get_result);
}

void update_loaded_pefiles() {
    int temp;
    struct process_entry *proc = NULL;
    clear_list(PROC);
    update_active_processlist();

    QLIST_FOREACH(proc, &processlist, loadedlist_entry) {
        temp = update_loaded_user_mods(proc);
        if (DEBUG) {
            monitor_printf(default_mon, "%d entries loaded.\n", temp);
        }
        printf("%d entries loaded.\n", temp);
    }
}

static void update_symbolslist(Monitor *mon, const QDict *qdict) {
    update_loaded_pefiles();
    //TODO DISCOVER WHAT THIS FUNCTION DO
    // function_map_remove();
    struct process_entry *proc = NULL;
    struct pe_entry *pef = NULL;
    struct api_entry *api = NULL;
    QLIST_FOREACH(proc, &processlist, loadedlist_entry) {
        monitor_printf(default_mon, "----------Getting loaded modules for %s. PID: %d--------\n\n",
                       proc->name, proc->process_id);
        if (DEBUG) {
            printf("----------Getting loaded modules for %s. PID: %d--------\n\n",
                   proc->name, proc->process_id);
        }
        uint32_t cr3 = get_cr3_from_proc_base(proc->EPROC_base_addr);

        QLIST_FOREACH(pef, &proc->modlist_head, loadedlist_entry) {
            monitor_printf(default_mon, "----------Getting symbols for: 0x%08x, %s, %d, 0x%08x----------\n\n",
                           pef->base, pef->name, pef->size, pef->apilist_head);
            if (DEBUG) {
                printf("----------Getting symbols for: 0x%08x, %s, %d, 0x%08x----------\n\n",
                       pef->base, pef->name, pef->size, pef->apilist_head);
            }
            int i = 1;
            QLIST_FOREACH(api, &pef->apilist_head, loadedlist_entry) {
                monitor_printf(default_mon, "symbols %d: 0x%08x, %s \n", i++, api->base, api->name);
                if (DEBUG) {
                    printf("symbols %d: 0x%08x, %s \n", i++, api->base, api->name);
                }
                // function_map
                //TODO find what this function do
                // function_map_create(pef->name, api->name, cr3, api->base);
            }
        }
    }
    hook_test();
}

static inline void update_stack_layout(Stack *st, uint32_t esp) {
    st->end = (esp >> 3) << 3;
}

void convert_to_host_filename(char *fullname, char *host_name) {
    char fullname_lower[512] = {'\0'};
    char temp[1024] = {'\0'};
    int i;

    if (strstr(fullname, "\\") == 0) {
        strcpy(temp, "\\WINDOWS\\system32\\DRIVERS\\");
        strcat(temp, fullname);
        fullname = temp;
    }

    for (i = 0; i < strlen(fullname); i++)
        fullname_lower[i] = tolower(fullname[i]);

    strcpy(host_name, C_DRIVE);
    if (strstr(fullname, "\\Device\\HarddiskVolume2\\") != 0) {
        char *first = strstr(fullname, "\\");
        char *second = strstr((first + 1), "\\");
        char *third = strstr((second + 1), "\\");
        strcat(host_name, third);
    } else if (strstr(fullname, "\\Device\\HarddiskVolume1\\") != 0) {
        char *first = strstr(fullname, "\\");
        char *second = strstr((first + 1), "\\");
        char *third = strstr((second + 1), "\\");
        strcat(host_name, third);
    } else if (strstr(fullname, "\\SystemRoot\\") != 0) {
        char *first = strstr(fullname, "\\");
        char *second = strstr((first + 1), "\\");
        char *third = strstr((second + 1), "\\");
        strcat(host_name, "\\WINDOWS\\system32");
        strcat(host_name, third);
    } else if (strstr(fullname_lower, "\\") != 0) {
        char *start = strstr(fullname_lower, "\\");
        strcat(host_name, start);
    }
#if 0
	else if(strstr(fullname_upper, "C:\\WINDOWS\\SYSTEM32") != 0)
	{
		char *start = strstr(fullname_upper, "C:\\WINDOWS\\SYSTEM32");
		char *t = start + strlen("C:\\WINDOWS\\SYSTEM32");
		int offset = (int)(t - &fullname[0]);
		strcat(host_name, "\\WINDOWS\\system32");
		strcat(host_name, (char *)(fullname+offset));
		char *curr = host_name;
		while((t = strstr(curr, "\\")) != NULL)
			curr = t + 1;
		while(*curr != '\0') {
			*curr = tolower(*curr);
			curr++;
		}
	}
#endif
    else /*if(strstr(fullname,"\\WINDOWS\\")!=0)*/
    {
        strcat(host_name, fullname);
    }
    int x = 0;
    while (host_name[x] != 0) {
        if (((int)host_name[x]) == 92) {
            host_name[x] = '/';
        }

        x++;
    }

    for (i = 0; i < strlen(host_name); i++)
        host_name[i] = tolower(host_name[i]);
}

int enum_exp_table_reloc_table_to_wl(char *filename, uint32_t base, char *name, struct bin_file *file) {
    char wFileName[1024] = {'\0'};
    strcpy(wFileName, FOLDER);
    strcat(wFileName, name);
    strcat(wFileName, ".wl");
    FILE *dll_file;
    dll_file = fopen(wFileName, "w");

    uint32_t et_num, image_base;
    int ret = WL_Extract(filename, &et_num, &image_base, file);
    monitor_printf(default_mon, " Entries from export table = %d and entries from reloc table = %d\n", file->exp_tbl_count, file->reloc_tbl_count);
    if (DEBUG) {
        printf(" Entries from export table = %d and entries from reloc table = %d\n", file->exp_tbl_count, file->reloc_tbl_count);
    }
    return ret;
}

static Thread *alloc_thread(uint32_t tid) {
    Thread *thread = NULL;
    thread = (Thread *)malloc(sizeof(Thread));
    memset(thread, 0, sizeof(Thread));
    thread->ustack = (Stack *)malloc(sizeof(Stack));
    thread->kstack = (Stack *)malloc(sizeof(Stack));
    memset(thread->ustack, 0, sizeof(Stack));
    memset(thread->kstack, 0, sizeof(Stack));
    thread->ustack->tid = thread->kstack->tid = tid;
    thread->ustack->max_size = thread->kstack->max_size = 1000;
    thread->ustack->ht = g_hash_table_new(0, 0);
    thread->kstack->ht = g_hash_table_new(0, 0);
    thread->tid = tid;
    return thread;
}

static inline Stack *get_curr_stack(Thread *th) {
    if (!QEMU_is_in_kernel())
        return th->ustack;
    else
        return th->kstack;
}

static void insert_proc(uint32_t pid, uint32_t cr3, char *name) {
    struct proc_entry *e = g_hash_table_lookup(cr3_pe_ht, (gpointer)cr3);
    if (e) {
        monitor_printf(default_mon, "insert_proc(pid = %d, name = %s, cr3 = 0x%08x):Process already present... %d, %s, %08x..\n",
                       pid, name, cr3, e->pid, e->name, e->cr3);
        if (DEBUG) {
            printf("insert_proc(pid = %d, name = %s, cr3 = 0x%08x):Process already present... %d, %s, %08x..\n",
                   pid, name, cr3, e->pid, e->name, e->cr3);
        }
        if (e->pid != pid) {
            monitor_printf(default_mon, "PID mismatch(e->pid = %d. pid = %d). Shouldn't happen.\n", e->pid, pid);
            if (DEBUG) {
                printf("PID mismatch(e->pid = %d. pid = %d). Shouldn't happen.\n", e->pid, pid);
            }

            vm_stop(0);
        }
        if (e->name[0] == '\0')
            strcpy(e->name, name);

        goto done;
    }

    e = (struct proc_entry *)malloc(sizeof(*e));
    memset(e, 0, sizeof(*e));
    e->cr3 = cr3;
    strcpy(e->name, name);
    e->pid = pid;
    e->misc_whitelist = g_hash_table_new(0, 0);
    e->mod_hashtable = g_hash_table_new(0, 0);
    e->threads[e->curr_tid] = alloc_thread(e->curr_tid);

    g_hash_table_insert(cr3_pe_ht, (gpointer)cr3, (gpointer)e);
    if (name[0] != '\0')
        e->initialized |= 0x1;

    if (strcmp(name, "System") == 0)
        sys_proc_cfi = e;

done:
    return;
}

//From libfi_add_callback("kernel32.dll", "GetProcAddress", 0, 0, GetProcAddress_ret_hook);
static void GetProcAddress_ret_hook(CPUState *env, target_ulong pc, uint8_t *args) {
    printf("GetProcAddress_ret_hook");
    // struct hook_data *hook_handle = (struct hook_data *)opaque;
    // CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;

    struct proc_entry *p = g_hash_table_lookup(cr3_pe_ht, (gpointer)env->cr[3]);
    if (!p) {
        goto done;
    }

    if (env->eip != 0)
        g_hash_table_insert(p->misc_whitelist, (gpointer)env->eip, (gpointer)13);

done:
    // hookapi_remove_hook(hook_handle->handle);
    libfi_remove_callback("kernel32.dll", "GetProcAddress", 0, 0, GetProcAddress_ret_hook);
    // free(hook_handle);
}

// From libfi_add_callback("kernel32.dll", "GetProcAddress", 1, 0, GetProcAddress_hook);
// static void GetProcAddress_hook(void *opaque)
static void GetProcAddress_hook(CPUState *env, target_ulong pc, uint8_t *args) {
    printf("GetProcAddress_hook\n");
    // struct hook_data *hook_handle;
    uint32_t ret_addr;
    cpu_memory_rw_debug(env, env->regs[R_ESP], (uint8_t *)&ret_addr, 4, 0);
    // hook_handle = (struct hook_data *) malloc (sizeof(*hook_handle));
    // hook_handle->handle = hookapi_hook_return(ret_addr, GetProcAddress_ret_hook, (void *)hook_handle, sizeof(*hook_handle));
    libfi_add_callback("kernel32.dll", "GetProcAddress", 0, 0, GetProcAddress_ret_hook);
}

static unsigned int bin_file_write(FILE *fp, struct bin_file *file) {
    uint32_t *temp = NULL;
    int i = 0;
    unsigned int size = 0;
    unsigned int byte_count = 0;
    fwrite((void *)file->name, NAME_SIZE, 1, fp);
    byte_count += NAME_SIZE;

    fwrite((void *)&(file->image_base), sizeof(uint32_t), 1, fp);
    byte_count += sizeof(uint32_t);

    fwrite((void *)&(file->reloc_tbl_count), sizeof(unsigned int), 1, fp);
    byte_count += sizeof(unsigned int);

    fwrite((void *)&(file->exp_tbl_count), sizeof(unsigned int), 1, fp);
    byte_count += sizeof(unsigned int);

    size = g_hash_table_size(file->whitelist);
    fwrite((void *)&(size), sizeof(unsigned int), 1, fp);
    byte_count += sizeof(unsigned int);

    temp = (uint32_t *)malloc(sizeof(uint32_t) * size);

    GHashTableIter iter;
    gpointer key, value;

    g_hash_table_iter_init(&iter, file->whitelist);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        temp[i++] = (uint32_t)key;
    }

    assert(i == size);
    fwrite((void *)temp, i * sizeof(uint32_t), 1, fp);
    byte_count += i * sizeof(uint32_t);

    free(temp);
    monitor_printf(default_mon, "Written %s. Exp tbl: %d, reloc tbl: %d, Entries in ht: %d. Total bytes written = %d\n",
                   file->name, file->exp_tbl_count, file->reloc_tbl_count, g_hash_table_size(file->whitelist), byte_count);
    if (DEBUG) {
        printf("Written %s. Exp tbl: %d, reloc tbl: %d, Entries in ht: %d. Total bytes written = %d\n",
               file->name, file->exp_tbl_count, file->reloc_tbl_count, g_hash_table_size(file->whitelist), byte_count);
    }

    return byte_count;
}

static uint32_t wl_get_tid() {
    uint32_t tid = 0;
    uint32_t fs_base = 0, prcb = 0, ethr = 0;
    CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
    fs_base = env->segs[R_FS].base;
    if (!QEMU_is_in_kernel()) {
        cpu_memory_rw_debug(cpu_single_env, fs_base + 0x24, (uint8_t *)(&tid), 4, 0);
    } else {
        cpu_memory_rw_debug(cpu_single_env, fs_base + 0x20, (uint8_t *)(&prcb), 4, 0);
        cpu_memory_rw_debug(cpu_single_env, prcb + 0x4, (uint8_t *)(&ethr), 4, 0);
        cpu_memory_rw_debug(cpu_single_env, ethr + 0x22c + 0x4, (uint8_t *)(&tid), 4, 0);
    }
    return tid & 0xffff;
}

void do_set_wl_dir(Monitor *mon, const QDict *qdict) {
    const char *dir_name = qdict_get_str(qdict, "whitelist_directory");
    strncpy(wl_dir, dir_name, strlen(dir_name));
}

void do_set_guest_dir(Monitor *mon, const QDict *qdict) {
    const char *dir_name = qdict_get_str(qdict, "guest_directory");
    strncpy(C_DRIVE, dir_name, strlen(dir_name));
}

static char mon_proc[256];
void do_monitor_proc(Monitor *mon, const QDict *qdict) {
    const char *name;
    if (qdict_haskey(qdict, "proc_name")) {
        name = qdict_get_str(qdict, "proc_name");
        strncpy(mon_proc, name, strlen(name));
    }
    return;
}

void do_print_tid(Monitor *mon, const QDict *qdict) {
    monitor_printf(default_mon, "Current thread ID is tid: %x\n", wl_get_tid());
    if (DEBUG) {
        printf("Current thread ID is tid: %x\n", wl_get_tid());
    }
}

// void do_set_kernel_cfi(Monitor *mon, const QDict *qdict)
// {

// }

static void print_intint(gpointer key, gpointer val, gpointer ud) {
    monitor_printf(default_mon, "0x%08x, %d\n", key, val);
    if (DEBUG) {
        printf("0x%08x, %d\n", key, val);
    }
}

void do_dump_system_dyn_regions(Monitor *mon, const QDict *qdict) {
    int i;
    if (!system_cr3)
        goto done;

    struct proc_entry *p = g_hash_table_lookup(cr3_pe_ht, (gpointer)system_cr3);

    if (!p)
        goto done;

    for (i = 0; i < p->dr.mem_regions_count; i += 2) {
        monitor_printf(default_mon, "0x%08x 0x%08x\n", p->dr.mem_regions[i], p->dr.mem_regions[i + 1]);
        if (DEBUG) {
            printf("0x%08x 0x%08x\n", p->dr.mem_regions[i], p->dr.mem_regions[i + 1]);
        }
    }
    monitor_printf(default_mon, "Total number of entries = %d\n", (p->dr.mem_regions_count) / 2);
    if (DEBUG) {
        printf("Total number of entries = %d\n", (p->dr.mem_regions_count) / 2);
    }
    monitor_printf(default_mon, "Violation ht....\n");
    if (DEBUG) {
        printf("Violation ht....\n");
    }
    g_hash_table_foreach(vio_ht, print_intint, NULL);
    monitor_printf(default_mon, "Number of entries in violations ht: %d\n", g_hash_table_size(vio_ht));
    if (DEBUG) {
        printf("Number of entries in violations ht: %d\n", g_hash_table_size(vio_ht));
    }

done:
    return;
}

void do_dump_file_wl(Monitor *mon, const QDict *qdict) {
    GHashTableIter iter;
    gpointer key, value;
    struct bin_file *file;
    FILE *fp = fopen("file_whitelist.dump", "wb");
    uint32_t ht_size = 0;
    unsigned int byte_count = 0;

    ht_size = g_hash_table_size(filemap_ht);
    monitor_printf(default_mon, "Total files in ht = %d\n", ht_size);
    if (DEBUG) {
        printf("Total files in ht = %d\n", ht_size);
    }

    fwrite((void *)&ht_size, sizeof(ht_size), 1, fp);
    byte_count += sizeof(ht_size);

    g_hash_table_iter_init(&iter, filemap_ht);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        file = (struct bin_file *)value;
        byte_count += bin_file_write(fp, file);
    }

    monitor_printf(default_mon, "Total bytes written = %d\n", byte_count);
    if (DEBUG) {
        printf("Total bytes written = %d\n", byte_count);
    }

    fflush(fp);
    fclose(fp);
}

static void print_pskeyval(gpointer key, gpointer val, gpointer ud) {
    struct proc_entry *p = (struct proc_entry *)val;
    monitor_printf(default_mon, "%d\t %s\t 0x%08x\n", p->pid, p->name, p->cr3);
    if (DEBUG) {
        printf("%d\t %s\t 0x%08x\n", p->pid, p->name, p->cr3);
    }
}

void do_pslist_from_hashmap(Monitor *mon, const QDict *qdict) {
    g_hash_table_foreach(cr3_pe_ht, print_pskeyval, NULL);
}

static mon_cmd_t wl_term_cmds[] = {
#include "wl_cmds.h"
    {
        NULL,
        NULL,
    },
};

static uint32_t lookup_in_whitelist(struct proc_entry *p, uint32_t val) {
    uint32_t ret = 0;
    int index;
    struct bin_file *file = NULL;
    if (g_hash_table_lookup(p->misc_whitelist, val)) {
        ret = 1;
        goto done;
    }

    index = binsearch_mr(p->modules, val, p->module_count);
    if (index == 0 || index == -1 * (p->module_count)) {
        goto done;
    } else {
        index = (index > 0) ? index : -(index);
        if (!(index & 0x1))
            goto done;

        file = g_hash_table_lookup(p->mod_hashtable, p->modules[index - 1]);
        if (!file) {
            //FIXME: This needs to be handled. Possibly a race condition.
            //monitor_printf(default_mon, "Corresponding module file not present... next_eip: 0x%08x\n", val);
            //print_generic_table(p->mod_hashtable);
            //vm_stop();
        } else {
            if (g_hash_table_lookup(file->whitelist, val - p->modules[index - 1])) {
                ret = 1;
                goto done;
            }
        }
    }

done:
    return ret;
}

/*
 * Adds a particular memory region to the monitored regions.
 */
int add_monitored_region(struct proc_entry *p, uint32_t addr, uint32_t size) {
    int index;

    index = binsearch_mr(p->dr.mem_regions, addr, p->dr.mem_regions_count);

    if (index > 0 || ((-index) & 0x1) == 1)
        return -1;

    if (p->dr.mem_regions_count > (2 * MAX_REGIONS) - 2)
        return -1;

    index = -(index);

    memmove(&((p->dr.mem_regions)[index + 2]), &((p->dr.mem_regions)[index]), (p->dr.mem_regions_count - index) * sizeof(target_ulong));
    (p->dr.mem_regions)[index] = addr;
    (p->dr.mem_regions)[index + 1] = addr + size;
    p->dr.mem_regions_count += 2;

    return 0;
}

/*
 * Removes a particular memory region from the list of active allocations.
 */
int remove_monitored_region(struct proc_entry *p, uint32_t addr) {
    int index;
    index = binsearch_mr(p->dr.mem_regions, addr, p->dr.mem_regions_count);
    if ((index >= 0) && ((index & (0x1)) == 0)) {
        if ((p->dr.mem_regions)[index] == addr) {
            memmove(&((p->dr.mem_regions)[index]), &((p->dr.mem_regions)[index + 2]), (p->dr.mem_regions_count - index - 2) * sizeof(target_ulong));
            memset(&((p->dr.mem_regions)[p->dr.mem_regions_count - 2]), 0, 2 * sizeof(target_ulong));
            p->dr.mem_regions_count -= 2;
        }
    }
    return 0;
}

//From libfi_add_callback("ntdll.dll", "RtlAllocateHeap", 0, 0, RtlAllocateHeap_ret_hook);
static void RtlAllocateHeap_ret_hook(CPUState *env, target_ulong pc, uint8_t *args) {
    // struct vp_hook_info *hook = (struct vp_hook_info *)opaque;
    uint32_t addr;
    // CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;

    struct proc_entry *p = g_hash_table_lookup(cr3_pe_ht, (gpointer)env->cr[3]);
    if (!p) {
        monitor_printf(default_mon, "RtlAllocateHeap_ret_hook(eip = 0x%08x, cr3 = 0x%08x):Process not present... Stopping VM...\n",
                       env->eip, env->cr[3]);
        if (DEBUG) {
            printf("RtlAllocateHeap_ret_hook(eip = 0x%08x, cr3 = 0x%08x):Process not present... Stopping VM...\n",
                   env->eip, env->cr[3]);
        }
        vm_stop(0);
        goto done;
    }

    if (env->eip != 0)
        /// TODO FIND SUBSTITUTE FOR hook->size
        // add_monitored_region(p, env->eip, hook->size);
        printf("RtlAllocateHeap_ret_hook: Need size\n");

done:
    // hookapi_remove_hook(hook->handle);
    libfi_remove_callback("ntdll.dll", "RtlAllocateHeap", 0, 0, RtlAllocateHeap_ret_hook);
    // free(hook);
}

static void VirtualAlloc_ret_hook(CPUState *env, target_ulong pc, uint8_t *args) {
    // struct vp_hook_info *hook = (struct vp_hook_info *)opaque;
    uint32_t addr;
    // CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
    struct proc_entry *p = g_hash_table_lookup(cr3_pe_ht, (gpointer)env->cr[3]);
    if (!p) {
        monitor_printf(default_mon, "VirtualAlloc_ret_hook(eip = 0x%08x, cr3 = 0x%08x):Process not present... Stopping VM...\n",
                       env->eip, env->cr[3]);
        if (DEBUG) {
            printf("VirtualAlloc_ret_hook(eip = 0x%08x, cr3 = 0x%08x):Process not present... Stopping VM...\n",
                   env->eip, env->cr[3]);
        }
        vm_stop(0);
        goto done;
    }

    if (env->eip != 0) {
        // 	/// TODO FIND SUBSTITUTE FOR hook->size
        printf("VirtualAlloc_ret_hook: need size");
        // 	add_monitored_region(p, env->eip, hook->size);
        // monitor_printf(default_mon, "Found dyn code region: Base = 0x%08x, size = %d\n", env->eip, hook->size);
        // if(DEBUG){
        // 	printf("Found dyn code region: Base = 0x%08x, size = %d\n", env->eip, hook->size);
        // }
    }

done:
    // hookapi_remove_hook(hook->handle);
    libfi_remove_callback("kernel32.dll", "VirtualAlloc", 0, 0, VirtualAlloc_ret_hook);
    // free(hook);
}

// From libfi_add_callback("kernel32.dll", "VirtualAlloc", 1, 0, VirtualAlloc_hook);
static void VirtualAlloc_hook(CPUState *env, target_ulong pc, uint8_t *args) {
    printf("VirtualAlloc_hook\n");
    uint32_t prot, ret_addr, esp;
    struct vp_hook_info *hook_handle;

    uint32_t alloc_type, size, lpaddr;

    //Ret hook is same for both VirtualAlloc and RtlAllocateHeap
    //void (*VirtualAlloc_ret_hook)(void *opaque) = RtlAllocateHeap_ret_hook;

    esp = env->regs[R_ESP];

    cpu_memory_rw_debug(env, esp, (uint8_t *)&ret_addr, 4, 0);
    cpu_memory_rw_debug(env, esp + 16, (uint8_t *)&prot, 4, 0);
    cpu_memory_rw_debug(env, esp + 12, (uint8_t *)&alloc_type, 4, 0);
    cpu_memory_rw_debug(env, esp + 8, (uint8_t *)&size, 4, 0);
    cpu_memory_rw_debug(env, esp + 4, (uint8_t *)&lpaddr, 4, 0);

    monitor_printf(default_mon, "VirtualAlloc(0x%08x, %d, %x, %x)\n", lpaddr, size, alloc_type, prot);
    if (DEBUG) {
        printf("VirtualAlloc(0x%08x, %d, %x, %x)\n", lpaddr, size, alloc_type, prot);
    }
    if (prot & 0x000000F0) {  //Has execute permission. Hook return
        hook_handle = (struct vp_hook_info *)malloc(sizeof(*hook_handle));
        memset(hook_handle, 0, sizeof(*hook_handle));
        cpu_memory_rw_debug(env, esp + 8, (uint8_t *)&(hook_handle->size), 4, 0);
        // hook_handle->handle = hookapi_hook_return(ret_addr, VirtualAlloc_ret_hook, (void *)hook_handle, sizeof(*hook_handle));
        libfi_add_callback("kernel32.dll", "VirtualAlloc", 0, 0, VirtualAlloc_ret_hook);
    }
}

/*
 * If changing the protection was successful, add it to monitored regions.
 */
// From libfi_add_callback("kernel32.dll", "VirtualProtect", 0, 0, VirtualProtect_ret_hook);
static void VirtualProtect_ret_hook(CPUState *env, target_ulong pc, uint8_t *args) {
    // CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
    // struct vp_hook_info *hook_handle = (struct vp_hook_info *) opaque;
    int index;

    struct proc_entry *p = g_hash_table_lookup(cr3_pe_ht, (gpointer)env->cr[3]);
    if (!p) {
        monitor_printf(default_mon, "VirtualProtect_ret_hook(eip = 0x%08x, cr3 = 0x%08x):Process not present... Stopping VM...\n",
                       env->eip, env->cr[3]);
        if (DEBUG) {
            printf("VirtualProtect_ret_hook(eip = 0x%08x, cr3 = 0x%08x):Process not present... Stopping VM...\n",
                   env->eip, env->cr[3]);
        }
        vm_stop(0);
        goto done;
    }

    if (env->eip != 0)
        // 	/// TODO FIND SUBSTITUTE FOR hook->size
        printf("VirtualProtect_ret_hook: need size\n");
    // add_monitored_region(p, hook_handle->addr, hook_handle->size);

done:
    // hookapi_remove_hook(hook_handle->handle);
    libfi_remove_callback("kernel32.dll", "VirtualProtect", 0, 0, VirtualProtect_ret_hook);
    // free(hook_handle);
}

//From libfi_add_callback("kernel32.dll", "VirtualProtect", 1, 0, VirtualProtect_hook);
static void VirtualProtect_hook(CPUState *env, target_ulong pc, uint8_t *args) {
    printf("VirtualProtect_hook\n");
    struct vp_hook_info *hook_handle;
    uint32_t ret_addr;
    uint32_t prot;

    cpu_memory_rw_debug(env, env->regs[R_ESP], (uint8_t *)&ret_addr, 4, 0);
    cpu_memory_rw_debug(env, (env->regs[R_ESP]) + 12, (uint8_t *)&prot, 4, 0);

    if (!(prot & (0x10 | 0x20 | 0x40 | 0x80))) {  //Execute bit not set
        return;
    }

    hook_handle = (struct vp_hook_info *)malloc(sizeof(*hook_handle));

    cpu_memory_rw_debug(env, (env->regs[R_ESP]) + 8, (uint8_t *)&hook_handle->size, 4, 0);
    cpu_memory_rw_debug(env, (env->regs[R_ESP]) + 4, (uint8_t *)&hook_handle->addr, 4, 0);

    // hook_handle->handle = hookapi_hook_return(ret_addr, VirtualProtect_ret_hook, (void *)hook_handle, sizeof(*hook_handle));
    libfi_add_callback("kernel32.dll", "VirtualProtect", 0, 0, VirtualProtect_ret_hook);
}

//From libfi_add_callback("kernel32.dll", "VirtualFree", 1, 0, VirtualFree_hook);
static void VirtualFree_hook(CPUState *env, target_ulong pc, uint8_t *args) {
    printf("VirtualFree_hook\n");
    uint32_t addr;
    cpu_memory_rw_debug(env, env->regs[R_ESP] + 4, (uint8_t *)&addr, 4, 0);

    struct proc_entry *p = g_hash_table_lookup(cr3_pe_ht, (gpointer)env->cr[3]);
    if (!p) {
        monitor_printf(default_mon, "VirtualFree_hook(eip = 0x%08x, cr3 = 0x%08x):Process not present... Stopping VM...\n",
                       env->eip, env->cr[3]);
        if (DEBUG) {
            printf("VirtualFree_hook(eip = 0x%08x, cr3 = 0x%08x):Process not present... Stopping VM...\n",
                   env->eip, env->cr[3]);
        }
        goto done;
    }

    remove_monitored_region(p, addr);
done:
    return;
}

// From libfi_add_callback("ntdll.dll", "RtlAllocateHeap", 1, 0, RtlAllocateHeap_hook);
static void RtlAllocateHeap_hook(CPUState *env, target_ulong pc, uint8_t *args) {
    printf("RtlAllocateHeap_hook\n");
    struct vp_hook_info *hook_handle;
    uint32_t ret_addr;
    cpu_memory_rw_debug(env, env->regs[R_ESP], (uint8_t *)&ret_addr, 4, 0);
    hook_handle = (struct vp_hook_info *)malloc(sizeof(*hook_handle));
    //TODO CHECK SIZE
    cpu_memory_rw_debug(env, env->regs[R_ESP] + 12, (uint8_t *)&(hook_handle->size), 4, 0);

    // hook_handle->handle = hookapi_hook_return(ret_addr, RtlAllocateHeap_ret_hook, (void *)hook_handle, sizeof(*hook_handle));
    libfi_add_callback("ntdll.dll", "RtlAllocateHeap", 0, 0, RtlAllocateHeap_ret_hook);
}

// From libfi_add_callback("ntdll.dll", "RtlFreeHeap", 1, 0, RtlFreeHeap_hook);
static void RtlFreeHeap_hook(CPUState *env, target_ulong pc, uint8_t *args) {
    printf("RtlFreeHeap_hook\n");
    uint32_t addr;
    cpu_memory_rw_debug(env, env->regs[R_ESP] + 12, (uint8_t *)&addr, 4, 0);
    struct proc_entry *p = g_hash_table_lookup(cr3_pe_ht, (gpointer)env->cr[3]);
    if (!p) {
        monitor_printf(default_mon, "RtlFreeHeap_hook(eip = 0x%08x, cr3 = 0x%08x):Process not present... Stopping VM...\n",
                       env->eip, env->cr[3]);
        if (DEBUG) {
            printf("RtlFreeHeap_hook(eip = 0x%08x, cr3 = 0x%08x):Process not present... Stopping VM...\n",
                   env->eip, env->cr[3]);
        }
        vm_stop(0);
        goto done;
    }

    remove_monitored_region(p, addr);

done:
    return;
}

uint32_t insn_cbs_registered = 0;
// static void wl_loadmainmodule_notify(uint32_t pid, uint32_t cr3, char *name)
static void wl_loadmainmodule_notify(CPUState *env, char *proc_name, unsigned int pid, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    uint32_t cr3 = env->cr[3];
    monitor_printf(default_mon, "%s started. PID = %d, cr3 = 0x%08x\n", proc_name, pid, cr3);
    if (DEBUG) {
        printf("%s started. PID = %d, cr3 = 0x%08x\n", proc_name, pid, cr3);
    }
    insert_proc(pid, cr3, proc_name);
    /* Hook memory allocation/deallocation functions to monitor dynamic code */
    if (pid == 4) {  //system process
        // } else {
        // 	hookapi_hook_function_byname("kernel32.dll","GetProcAddress",1,cr3,GetProcAddress_hook,NULL,0);
        libfi_add_callback("kernel32.dll", "GetProcAddress", 1, 0, GetProcAddress_hook);
        // 	hookapi_hook_function_byname("ntdll.dll","RtlAllocateHeap",1,cr3,RtlAllocateHeap_hook,NULL,0);
        libfi_add_callback("ntdll.dll", "RtlAllocateHeap", 1, 0, RtlAllocateHeap_hook);
        // 	hookapi_hook_function_byname("ntdll.dll","RtlFreeHeap",1,cr3,RtlFreeHeap_hook,NULL,0);
        libfi_add_callback("ntdll.dll", "RtlFreeHeap", 1, 0, RtlFreeHeap_hook);
        // 	hookapi_hook_function_byname("kernel32.dll","VirtualAlloc",1,cr3,VirtualAlloc_hook,NULL,0);
        libfi_add_callback("kernel32.dll", "VirtualAlloc", 1, 0, VirtualAlloc_hook);
        // 	hookapi_hook_function_byname("kernel32.dll","VirtualFree",1,cr3,VirtualFree_hook,NULL,0);
        libfi_add_callback("kernel32.dll", "VirtualFree", 1, 0, VirtualFree_hook);
        // 	hookapi_hook_function_byname("kernel32.dll","VirtualProtect",1,cr3,VirtualProtect_hook,NULL,0);
        libfi_add_callback("kernel32.dll", "VirtualProtect", 1, 0, VirtualProtect_hook);
    }
}

static void insert_file_to_proc(struct proc_entry *p, struct bin_file *file, uint32_t load_addr) {
    int i;
    char wFileName[2048] = {'\0'};
    char temp_str[16] = {'\0'};
    uint32_t new_addr = 0;

    if (file->exp_tbl_count == 0 && file->reloc_tbl_count == 0)
        return;
    g_hash_table_insert(p->mod_hashtable, file->image_base, (gpointer)file);
}

int binsearch_mr(target_ulong *A, target_ulong value, int max_elements) {
    int low = 0;
    int mid = 0;
    int high = max_elements - 1;
    while (low <= high) {
        mid = (low + high) / 2;
        if (A[mid] > value)
            high = mid - 1;
        else if (A[mid] < value)
            low = mid + 1;
        else
            return mid;
    }
    return -(low);
}

int add_proc_module(struct proc_entry *p, uint32_t addr, uint32_t size) {
    int index;

    index = binsearch_mr(p->modules, addr, p->module_count);

    if (index > 0 || ((-index) & 0x1) == 1)
        return -1;

    if (p->module_count > (2 * MAX_REGIONS) - 2)
        return -1;

    index = -(index);

    memmove(&((p->modules)[index + 2]), &((p->modules)[index]), (p->module_count - index) * sizeof(target_ulong));
    (p->modules)[index] = addr;
    (p->modules)[index + 1] = addr + size;
    p->module_count += 2;

    return 0;
}

// static void wl_procexit(uint32_t pid, uint32_t cr3, char *name)
static void wl_procexit(CPUState *env, unsigned int pid, char *name) {
    int i;
    uint32_t cr3 = env->cr[3];
    monitor_printf(default_mon, "Process exiting: %s, pid: %d, cr3: %08x\n", name, pid, cr3);
    if (DEBUG) {
        printf("Process exiting: %s, pid: %d, cr3: %08x\n", name, pid, cr3);
    }
    struct proc_entry *p = (struct proc_entry *)g_hash_table_lookup(cr3_pe_ht, (gconstpointer)cr3);
    if (p == NULL) {
        monitor_printf(default_mon, "wl_procexit(pid = %d, cr3 = 0x%08x, name = %s):Process not present... Stopping VM...\n",
                       pid, cr3, name);
        if (DEBUG) {
            printf("wl_procexit(pid = %d, cr3 = 0x%08x, name = %s):Process not present... Stopping VM...\n",
                   pid, cr3, name);
        }
        vm_stop(0);
        goto done;
    }
    for (i = 0; i < MAX_THREADS; i++) {
        if (p->threads[i]) {
            if (p->threads[i]->kstack) {
                if (p->threads[i]->kstack->data) {
                    free(p->threads[i]->kstack->data);
                    p->threads[i]->kstack->data = NULL;
                }
                g_hash_table_destroy(p->threads[i]->kstack->ht);
                p->threads[i]->kstack->ht = NULL;
                free(p->threads[i]->kstack);
                p->threads[i]->kstack = NULL;
            }
            if (p->threads[i]->ustack) {
                if (p->threads[i]->ustack->data) {
                    free(p->threads[i]->ustack->data);
                    p->threads[i]->ustack->data = NULL;
                }
                g_hash_table_destroy(p->threads[i]->ustack->ht);
                p->threads[i]->ustack->ht = NULL;
                free(p->threads[i]->ustack);
                p->threads[i]->ustack = NULL;
            }
            free(p->threads[i]);
            p->threads[i] = NULL;
        }
    }
    if (p->mod_hashtable)
        g_hash_table_destroy(p->mod_hashtable);

    if (p->misc_whitelist)
        g_hash_table_destroy(p->misc_whitelist);

    g_hash_table_remove(cr3_pe_ht, cr3);

    free(p);
done:
    return;
}

// void wl_load_module_notify (
// 		uint32_t pid,
// 		uint32_t cr3,
// 		char *name,
// 		uint32_t base,
// 		uint32_t size,
// 		char *fullname)
void wl_load_module_notify(CPUState *env, char *proc_name, unsigned int pid, char *mod_name, char *mod_filename, target_ulong size, target_ulong base) {
    char host_filename[1024] = {'\0'};
    char temp[1024] = {'\0'};
    struct bin_file *file = NULL;
    char name_lower[256];
    int ret, i;
    uint32_t cr3 = env->cr[3];
    struct proc_entry *p = (struct proc_entry *)g_hash_table_lookup(cr3_pe_ht, (gconstpointer)cr3);
    if (p == NULL) {
        monitor_printf(default_mon, "Module loaded: name = %s, pid = %d, cr3 = 0x%08x, base = 0x%08x, fullname = %s. PROCESS NOT FOUND adding...\n",
                       mod_name, pid, cr3, base, mod_filename);
        if (DEBUG) {
            printf(default_mon, "Module loaded: name = %s, pid = %d, cr3 = 0x%08x, base = 0x%08x, fullname = %s. PROCESS NOT FOUND adding...\n",
                   mod_name, pid, cr3, base, mod_filename);
        }
        if (strstr(mod_name, ".exe") || strstr(mod_name, ".EXE"))
            insert_proc(pid, cr3, mod_name);
        else
            insert_proc(pid, cr3, "");
        p = (struct proc_entry *)g_hash_table_lookup(cr3_pe_ht, (gconstpointer)cr3);
    }

    for (i = 0; i < strlen(mod_name); i++) {
        if (!isascii(mod_filename[i]))
            continue;
        temp[i] = tolower(mod_filename[i]);
    }

    if (strstr(temp, "ntdll.dll"))
        p->initialized |= 0x2;

    file = (struct bin_file *)g_hash_table_lookup(filemap_ht, temp);
    if (!file) {  //First encounter
        file = (struct bin_file *)malloc(sizeof(*file));
        if (!file) {
            monitor_printf(default_mon, "malloc failed in wl_load_module_notify. :'(\n");
            if (DEBUG) {
                printf("malloc failed in wl_load_module_notify. :'(\n");
            }
            vm_stop(0);
        }
        memset(file, 0, sizeof(*file));
        strcpy(file->name, temp);
        convert_to_host_filename(mod_filename, host_filename);
        ret = enum_exp_table_reloc_table_to_wl(host_filename, base, mod_name, file);
        if (ret == -1) {  //Unable to open file or invalid pe header. Try defaults
            strcpy(name_lower, mod_name);
            strcpy(host_filename, C_DRIVE);
            strcat(host_filename, "\\Windows\\System32\\");

            for (i = 0; i < strlen(mod_name); i++)
                name_lower[i] = tolower(mod_name[i]);

            strcat(host_filename, name_lower);
            for (i = 0; i < strlen(host_filename); i++)
                if (host_filename[i] == '\\')
                    host_filename[i] = '/';

            ret = enum_exp_table_reloc_table_to_wl(host_filename, base, mod_name, file);
            if (ret == -1) {  //might be a driver??
                strcpy(name_lower, mod_name);
                strcpy(host_filename, C_DRIVE);
                strcat(host_filename, "\\Windows\\System32\\drivers\\");

                for (i = 0; i < strlen(mod_name); i++)
                    name_lower[i] = tolower(mod_name[i]);

                strcat(host_filename, name_lower);
                for (i = 0; i < strlen(host_filename); i++)
                    if (host_filename[i] == '\\')
                        host_filename[i] = '/';
                ret = enum_exp_table_reloc_table_to_wl(host_filename, base, mod_name, file);
            }
        }
        monitor_printf(default_mon, "%d entries loaded from %s. ", ret, mod_filename);
    }

    if (file->whitelist == 0) {  //Not initialized
        file->whitelist = g_hash_table_new(0, 0);
        for (i = 0; i < file->reloc_tbl_count; i++)
            g_hash_table_insert(file->whitelist, (file->reloc_tbl)[i], 1);
        for (i = 0; i < file->exp_tbl_count; i++)
            g_hash_table_insert(file->whitelist, (file->exp_tbl)[i], 2);

        monitor_printf(default_mon, "%d elements in ht.\n", g_hash_table_size(file->whitelist));
        if (DEBUG) {
            printf("%d elements in ht.\n", g_hash_table_size(file->whitelist));
        }
    }

    insert_file_to_proc(p, file, base);
    add_proc_module(p, base, size);

    //Free up the reloc table and the export table.
    if (file->exp_tbl) {
        free(file->exp_tbl);
        file->exp_tbl = 0;
    }

    if (file->reloc_tbl) {
        free(file->reloc_tbl);
        file->reloc_tbl = 0;
    }

    WL_cleanUp();

    if (!g_hash_table_lookup(filemap_ht, temp)) {
        if (file->reloc_tbl_count > 0 || file->exp_tbl_count > 0) {
            monitor_printf(default_mon, "Inserting to filemap temp: %s, fullname: %s\n", temp, mod_filename);
            if (DEBUG) {
                printf("Inserting to filemap temp: %s, fullname: %s\n", temp, mod_filename);
            }
            g_hash_table_insert(filemap_ht, temp, (gpointer)file);
        }
    }

done:
    return;
}

static int wl_init(void *self) {
    //##########TODO#########
    // procmod_init();
    // function_map_init();
    // init_hookapi();

    recon_init();
    cr3_pe_ht = g_hash_table_new(0, 0);
    filemap_ht = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    vio_ht = g_hash_table_new(0, 0);

    // load_file_wl("file_whitelist.dump");

    return 0;
}

// static void cfi_cleanup(void)
// {
// 	int i;
// 	//###### TODO CHECK CLEANUP
//     // cleanup_insn_cbs();
//    // if(hndl)
//    	// DECAF_unregister_callback(DECAF_BLOCK_BEGIN_CB, hndl);

//    // recon_cleanup();
// }

int Stack_Push_new(Stack *s, uint32_t esp, uint32_t addr) {
    int i = 0;
    if (s->data == NULL) {
        s->data = (struct Data *)malloc(sizeof(struct Data) * s->max_size);
    }
    if (s->size == s->max_size) {  //Maximum size reached. Reset stack.
        for (i = 0; i < s->max_size; i++) {
            g_hash_table_remove(s->ht, s->data[i].esp);
        }
        memset(s->data, 0, sizeof(struct Data) * s->max_size);
        s->size = 0;
    }
    s->data[s->size].data = addr;
    s->data[s->size].esp = esp;
    s->size++;

    return s->size - 1;
}

void call_target_handler(uint32_t eip, uint32_t next_eip, uint32_t op, uint32_t espval) {
    int insn_len = 0;
    CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
    uint8_t bytes[15] = {'\0'};
    Stack *st = NULL;
    uint32_t esp_page = 0;
    uint32_t ret_addr = 0;
    uint32_t fiber_id, tid;
    int index = 0;
    uint32_t esp = 0, not_curr_page = 0;

    struct proc_entry *p = g_hash_table_lookup(cr3_pe_ht, (gpointer)env->cr[3]);
    if (!p) {
        goto done;
    }

    if (p->initialized != 0x3)
        goto done;

    esp = env->regs[R_ESP];
    esp_page = (esp >> 3) << 3;
    ret_addr = eip + 5;
    if (esp_page != p->threads[p->curr_tid]->kernel_stack && esp_page != p->threads[p->curr_tid]->user_stack) {  //Still in the same thread. Push to stack and be done.
        p->curr_tid = wl_get_tid();
        if (!p->threads[p->curr_tid])
            p->threads[p->curr_tid] = alloc_thread(p->curr_tid);
        if (QEMU_is_in_kernel())
            p->threads[p->curr_tid]->kernel_stack = esp_page;
        else
            p->threads[p->curr_tid]->user_stack = esp_page;
        not_curr_page = 1;
    }
    st = get_curr_stack(p->threads[p->curr_tid]);
    index = Stack_Push_new(st, esp, ret_addr);
    g_hash_table_insert(st->ht, esp, ((index == 0) ? 0xabcdef : index));

    if (not_curr_page) {
        update_stack_layout(st, esp);
    }

    call_count++;

    //and whitelist the ret addr since some rets are incorporated using indirect jumps Eg: rpcrt4.dll::ObjectStubless()
    //FIXME: For now, inserting 1 as the value. Changing to the struct bin_file * could be costly.
    g_hash_table_insert(p->misc_whitelist, (gpointer)eip + insn_len, (gpointer)11);

done:
    return;
}

void callff_target_handler(uint32_t eip, uint32_t next_eip, uint32_t op, uint32_t espval) {
    uint32_t fiber_id;
    uint32_t tid;
    uint8_t bytes[15];
    uint32_t esp_page = 0, ret_addr = 0, not_curr_page = 0, esp = 0;
    int index = 0, insn_len = 0, i = 0;
    int in_stack = 1, in_wl = 1, in_dyn_mem = 1;
    tmodinfo_t *tp_src, *tp_dst;
    char name[256];
    CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;

    if (next_eip == 0)
        goto done;

    struct proc_entry *p = g_hash_table_lookup(cr3_pe_ht, (gpointer)env->cr[3]);
    if (!p) {
        goto done;
    }

    if (p->initialized != 0x3)
        goto done;

    int modrm = (op >> 8) & 0xff;
    Stack *fiber_stack;
    struct Data ret_pop;
    uint32_t prev_size, new_size;

    if (((modrm >> 3) & 7) == 2 || ((modrm >> 3) & 7) == 3        //indirect call insn
        || ((modrm >> 3) & 7) == 4 || ((modrm >> 3) & 7) == 5) {  //indirect jmp insn

        uint32_t ret = lookup_in_whitelist(p, next_eip);  //g_hash_table_lookup(p->hashtable, (gconstpointer) next_eip);
        if (!ret) {
            struct proc_entry *system_proc = g_hash_table_lookup(cr3_pe_ht, (gpointer)system_cr3);
            if (system_proc)
                ret = lookup_in_whitelist(system_proc, next_eip);  //g_hash_table_lookup(system_proc->hashtable, (gconstpointer) next_eip);

            if (!ret)
                in_wl = 0;
        }

        if (!in_wl) {  //Check if in dynamic memory
            index = binsearch_mr(p->dr.mem_regions, next_eip, p->dr.mem_regions_count);
            if (index == 0 || index == -1 * (p->dr.mem_regions_count)) {
                in_dyn_mem = 0;
            } else {
                index = (index > 0) ? index : -(index);
                if (!(index & 0x1)) {
                    in_dyn_mem = 0;
                }
            }
        }
    }

    Stack *st;
    if (((modrm >> 3) & 7) == 2 || ((modrm >> 3) & 7) == 3) {  //If it is a call insn, push ret addr to stack
        esp = env->regs[R_ESP];
        esp_page = (esp >> 3) << 3;
        cpu_memory_rw_debug(env, eip, &bytes[0], 15, 0);  //Read the instruction
        insn_len = get_insn_len(bytes);
        ret_addr = eip + insn_len;
        if (esp_page != p->threads[p->curr_tid]->kernel_stack && esp_page != p->threads[p->curr_tid]->user_stack) {  //Still in the same thread. Push to stack and be done.
            p->curr_tid = wl_get_tid();
            if (!p->threads[p->curr_tid])
                p->threads[p->curr_tid] = alloc_thread(p->curr_tid);
            if (QEMU_is_in_kernel())
                p->threads[p->curr_tid]->kernel_stack = esp_page;
            else
                p->threads[p->curr_tid]->user_stack = esp_page;
            not_curr_page = 1;
        }
        st = get_curr_stack(p->threads[p->curr_tid]);
        index = Stack_Push_new(st, esp, ret_addr);
        g_hash_table_insert(st->ht, esp, ((index == 0) ? 0xabcdef : index));

        if (not_curr_page) {
            update_stack_layout(st, esp);
        }

        call_count++;

        //and whitelist the ret addr since some rets are incorporated using indirect jumps Eg: rpcrt4.dll::ObjectStubless()
        g_hash_table_insert(p->misc_whitelist, (gpointer)eip + insn_len, (gpointer)12);
    }

done:
    return;
}

extern void vm_stop(RunState r);
void ret_target_handler(uint32_t eip, uint32_t next_eip, uint32_t op, uint32_t espval) {
    uint32_t prev_size, new_size, tid;
    tmodinfo_t *tp;
    uint32_t index, in_dyn_mem = 1;
    gboolean ispresent = 0;
    char name[256];
    uint32_t fiber_id;
    uint32_t tp_src = 0;
    struct Data ret_pop;
    if (next_eip == 0)
        goto done;

    CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;

    struct proc_entry *p = g_hash_table_lookup(cr3_pe_ht, (gpointer)env->cr[3]);
    if (!p) {
        goto done;
    }

    if (p->initialized != 0x3)
        goto done;

    ret_count++;
    uint32_t esp = 0, esp_page = 0, not_curr_page = 0;
    Stack *st = NULL;
    esp = espval;
    esp_page = (esp >> 3) << 3;
    if (esp_page != p->threads[p->curr_tid]->kernel_stack && esp_page != p->threads[p->curr_tid]->user_stack) {  //Still in the same thread. Push to stack and be done.
        p->curr_tid = wl_get_tid();
        if (!p->threads[p->curr_tid]) {
            p->threads[p->curr_tid] = alloc_thread(p->curr_tid);
            uint32_t ret = lookup_in_whitelist(p, next_eip);
            if (!ret) {
                miss_ret1++;
            } else {
                stack_match++;
            }
            goto done;
        }
        if (QEMU_is_in_kernel())
            p->threads[p->curr_tid]->kernel_stack = esp_page;
        else
            p->threads[p->curr_tid]->user_stack = esp_page;
        not_curr_page = 1;
    }
    st = get_curr_stack(p->threads[p->curr_tid]);
    index = g_hash_table_lookup(st->ht, esp);
    if (!index) {
        uint32_t ret = lookup_in_whitelist(p, next_eip);
        if (!ret) {
            miss_ret2++;
        } else {
            stack_match++;
        }
        goto done;
    }

    if (index == 0xabcdef)
        index = 0;

    if (index == st->size - 1)
        stack_top++;

    ret_pop = Stack_Pop_until(st, index);
    if (ret_pop.data != next_eip) {
        uint32_t ret = lookup_in_whitelist(p, next_eip);  //g_hash_table_lookup(p->hashtable, (gconstpointer) next_eip);
        if (!ret) {
            index = binsearch_mr(p->dr.mem_regions, next_eip, p->dr.mem_regions_count);
            if (index == 0 || index == -1 * (p->dr.mem_regions_count)) {
                in_dyn_mem = 0;
            } else {
                index = (index > 0) ? index : -(index);
                if (!(index & 0x1)) {
                    in_dyn_mem = 0;
                }
            }

            if (in_dyn_mem) {
                monitor_printf(default_mon, "In dynamic memory. EIP: 0x%08x, next_eip: 0x%08x\n", eip, next_eip);
                if (DEBUG) {
                    printf("In dynamic memory. EIP: 0x%08x, next_eip: 0x%08x\n", eip, next_eip);
                }
            } else {
                miss_counter++;
            }
        }
    } else {
        stack_match++;
    }

done:
    return;
}

void call_long_target_handler(uint32_t eip, uint32_t next_eip, uint32_t op, uint32_t espval) {
    monitor_printf(default_mon, "lcall: 0x9a @ EIP: 0x%08x Stopping VM... \n", eip);
    if (DEBUG) {
        printf("lcall: 0x9a @ EIP: 0x%08x Stopping VM... \n", eip);
    }
    vm_stop(0);
}

/* Handler for FLDZ instruction used to store eip */
void floating_point_handler(uint32_t eip, uint32_t next_eip, uint32_t op, uint32_t espval) {
    uint8_t bytes[15];
    CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;

    struct proc_entry *p = g_hash_table_lookup(cr3_pe_ht, (gpointer)env->cr[3]);
    if (!p) {
        goto done;
    }

    if (p->initialized != 0x3)
        goto done;

    cpu_memory_rw_debug(env, eip, &bytes[0], 15, 0);  //Read the instruction

    if (bytes[0] == 0xd9 && bytes[1] == 0xee)
        g_hash_table_insert(p->misc_whitelist, (gpointer)eip, (gpointer)2);  //2 == FLDZ insn

done:
    return;
}

void startup_registrations() {
    //	return;

    monitor_printf(default_mon, "Registering for callback handlers...\n");
    if (DEBUG) {
        printf("Registering for callback handlers...\n");
    }

    //TODO Discover what these function do
    // register_insn_cb_range(0xe8, 0xe8, call_target_handler);
    // register_insn_cb_range(0xff, 0xff, callff_target_handler);
    // register_insn_cb_range(0xc2, 0xc3, ret_target_handler);
    // register_insn_cb_range(0x9a, 0x9a, call_long_target_handler);

    // //Callback to handle floating point eip retrieval
    // register_insn_cb_range(0xd9, 0xd9, floating_point_handler);
}

//TODO CHANGE IMPLEMENTATION THROUGH panda functions

void remove_proc(struct process_entry *proc) {
    struct pe_entry *mod, *next;
    struct api_entry *api, *next_api;
    struct thread_entry *thr, *next_thr;
    QLIST_FOREACH_SAFE(mod, &proc->modlist_head, loadedlist_entry, next) {
        QLIST_FOREACH_SAFE(api, &mod->apilist_head, loadedlist_entry, next_api) {
            QLIST_REMOVE(api, loadedlist_entry);
            free(api);
        }
        QLIST_REMOVE(mod, loadedlist_entry);
        free(mod);
    }
    QLIST_FOREACH_SAFE(thr, &threadlist, loadedlist_entry, next_thr) {
        if (thr->owning_process_id == proc->process_id) {
            QLIST_REMOVE(thr, loadedlist_entry);
            free(thr);
        }
    }
}

// get all dlls of one process
int update_loaded_user_mods(struct process_entry *proc) {
    uint32_t proc_addr = proc->EPROC_base_addr;
    uint32_t curr_cr3, peb, ldr, memlist, first_dll, curr_dll;
    struct pe_entry *curr_entry = NULL;
    CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
    int ret = 0, flag = 0;
    QLIST_INIT(&proc->modlist_head);
    curr_cr3 = get_cr3_from_proc_base(proc_addr);
    cpu_memory_rw_debug(env, proc_addr + 0x1b0, (uint8_t *)&peb, 4, 0);

    if (peb == 0x00)
        goto done;

    TEMU_memory_rw_with_cr3(curr_cr3, peb + 0xc, (void *)&ldr, 4, 0);
    monitor_printf(default_mon, "peb is: 0x%08x\n", peb);
    if (DEBUG) {
        printf("peb is: 0x%08x\n", peb);
    }
    memlist = ldr + 0xc;
    TEMU_memory_rw_with_cr3(curr_cr3, memlist, (void *)&first_dll, 4, 0);

    if (first_dll == 0)
        goto done;

    curr_dll = first_dll;

    do {
        curr_entry = (struct pe_entry *)malloc(sizeof(*curr_entry));
        memset(curr_entry, 0, sizeof(*curr_entry));
        QLIST_INIT(&curr_entry->apilist_head);

        TEMU_memory_rw_with_cr3(curr_cr3, curr_dll + 0x18, (void *)&(curr_entry->base), 4, 0);
        if (curr_entry->base == 0x0 && flag == 0) {
            flag = 1;
            TEMU_memory_rw_with_cr3(curr_cr3, curr_dll, (void *)&curr_dll, 4, 0);
            continue;
        }
        TEMU_memory_rw_with_cr3(curr_cr3, curr_dll + 0x20, (void *)&(curr_entry->size), 4, 0);
        readustr_with_cr3(curr_dll + 0x2c, curr_cr3, curr_entry->name, env);
        readustr_with_cr3(curr_dll + 0x24, curr_cr3, curr_entry->fullname, env);

        if ((curr_entry->name)[0] == '\0')
            continue;

        update_api_with_pe(curr_cr3, curr_entry, 1);
        QLIST_INSERT_HEAD(&proc->modlist_head, curr_entry, loadedlist_entry);
        /* insert modules info, call function in procmod.h-- here need change */
        //		procmod_insert_modinfo(proc->process_id, curr_cr3, curr_entry->name, curr_entry->base, curr_entry->size);

        ret++;
        TEMU_memory_rw_with_cr3(curr_cr3, curr_dll, (void *)&curr_dll, 4, 0);
    } while (curr_dll != 0 && curr_dll != first_dll);

done:
    return ret;
}

struct process_entry *get_system_process() {
    struct process_entry *pe = NULL;
    handle_funds[GuestOS_index].update_processlist();
    QLIST_FOREACH(pe, &processlist, loadedlist_entry) {
        if (strcmp(pe->name, "System") == 0)
            break;
    }
    return pe;
}
struct process_entry *get_new_process() {
    struct process_entry *pe = NULL;
    handle_funds[GuestOS_index].update_processlist();
    monitor_printf(default_mon, "%d\tnew process...\n", GuestOS_index);
    if (DEBUG) {
        printf("%d\tnew process...\n", GuestOS_index);
    }
    QLIST_FOREACH(pe, &processlist, loadedlist_entry) {
        monitor_printf(default_mon, "0x%08x\t%d\t%s\t%d\t%d\t%d\t0x%08x\n",
                       pe->EPROC_base_addr, pe->ppid, pe->name, pe->process_id,
                       pe->number_of_threads, pe->number_of_handles, pe->cr3);
        if (DEBUG) {
            printf(default_mon, "0x%08x\t%d\t%s\t%d\t%d\t%d\t0x%08x\n",
                   pe->EPROC_base_addr, pe->ppid, pe->name, pe->process_id,
                   pe->number_of_threads, pe->number_of_handles, pe->cr3);
        }
    }
    pe = QLIST_FIRST(&processlist);
    return pe;
}

//TODO TEMU FUNCTIONS
target_ulong TEMU_get_phys_addr(target_ulong addr) {
    int mmu_idx, index;
    uint32_t phys_addr;
    CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;

    index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
    mmu_idx = cpu_mmu_index(env);
    if (__builtin_expect(env->tlb_table[mmu_idx][index].addr_read !=
                             (addr & TARGET_PAGE_MASK),
                         0)) {
        phys_addr = cpu_get_phys_page_debug(env, addr & TARGET_PAGE_MASK);
        if (phys_addr == -1)
            return -1;
        phys_addr += addr & (TARGET_PAGE_SIZE - 1);
        return phys_addr;
    }
    // #if 0 //not sure if we need it --Heng Yin
    //     pd = env->tlb_table[mmu_idx][index].addr_read & ~TARGET_PAGE_MASK;
    //     if (pd > IO_MEM_ROM && !(pd & IO_MEM_ROMD)) {
    //         cpu_abort(env, "Trying to execute code outside RAM or ROM at 0x" TARGET_FMT_lx "\n", addr);
    //     }
    // #endif
    // return addr + env->tlb_table[mmu_idx][index].addend - (unsigned long)phys_ram_base;
    return addr + env->tlb_table[mmu_idx][index].addend;
}

int TEMU_memory_rw(uint32_t addr, void *buf, int len, int is_write) {
    int l;
    target_ulong page, phys_addr;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        phys_addr = TEMU_get_phys_addr(page);
        if (phys_addr == -1)
            return -1;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        cpu_physical_memory_rw(phys_addr + (addr & ~TARGET_PAGE_MASK),
                               buf, l, is_write);
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}

uint32_t TEMU_get_physaddr_with_cr3(target_ulong cr3, target_ulong addr) {
    CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
    target_ulong saved_cr3 = env->cr[3];
    uint32_t phys_addr;

    env->cr[3] = cr3;
    phys_addr = cpu_get_phys_page_debug(env, addr & TARGET_PAGE_MASK);

    env->cr[3] = saved_cr3;
    return phys_addr;
}

int TEMU_memory_rw_with_cr3(target_ulong cr3, uint32_t addr, void *buf, int len, int is_write) {
    int l;
    target_ulong page, phys_addr;

    while (len > 0) {
        page = addr & TARGET_PAGE_MASK;
        phys_addr = TEMU_get_physaddr_with_cr3(cr3, page);
        if (phys_addr == -1)
            return -1;
        l = (page + TARGET_PAGE_SIZE) - addr;
        if (l > len)
            l = len;
        cpu_physical_memory_rw(phys_addr + (addr & ~TARGET_PAGE_MASK),
                               buf, l, is_write);
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}

int readustr_with_cr3(uint32_t addr, uint32_t cr3, void *buf, CPUState *env) {
    uint32_t unicode_data[2];
    int i, j, unicode_len = 0;
    uint8_t unicode_str[MAX_UNICODE_LENGTH] = {'\0'};
    char *store = (char *)buf;

    if (cr3 != 0) {
        if (TEMU_memory_rw_with_cr3(cr3, addr, (void *)&unicode_data, sizeof(unicode_data), 0) < 0) {
            //monitor_printf(default_mon,"TEMU_mem_rw_with_cr3(0x%08x, cr3=0x%08x, %d) returned non-zero.\n", addr, cr3, sizeof(unicode_data));
            store[0] = '\0';
            goto done;
        }
    } else {
        if (TEMU_memory_rw(addr, (void *)&unicode_data, sizeof(unicode_data), 0) < 0) {
            //monitor_printf(default_mon,"TEMU_mem_rw(0x%08x, %d) returned non-zero.\n", addr, sizeof(unicode_data));
            store[0] = '\0';
            goto done;
        }
    }

    unicode_len = (int)(unicode_data[0] & 0xFFFF);
    if (unicode_len > MAX_UNICODE_LENGTH)
        unicode_len = MAX_UNICODE_LENGTH;

    if (cr3 != 0) {
        if (TEMU_memory_rw_with_cr3(cr3, unicode_data[1], (void *)unicode_str, unicode_len, 0) < 0) {
            store[0] = '\0';
            goto done;
        }
    } else {
        if (TEMU_memory_rw(unicode_data[1], (void *)unicode_str, unicode_len, 0) < 0) {
            store[0] = '\0';
            goto done;
        }
    }

    for (i = 0, j = 0; i < unicode_len; i += 2, j++) {
        if (unicode_str[i] < 0x20 || unicode_str[i] > 0x7e)  //Non_printable character
            break;

        store[j] = unicode_str[i];
    }
    store[j] = '\0';

done:
    return strlen(store);
}

int readustr(uint32_t addr, void *buf, CPUState *env) {
    return readustr_with_cr3(addr, 0, buf, env);
}

//TODO FIND HOW TO IMPLEMENT FROM PROCMOD.CPP
void handle_guest_message(const char *message) {
}

/* COMMENTS FROM ORIGINAL CODE
 * This is stop gap arrangement to utilize the existing infrastructure.
 * TODO: The message has to be done away with.
 */
void message_p(struct process_entry *proc, int operation) {
    char proc_mod_msg[1024] = {'\0'};
    if (operation) {
        monitor_printf(default_mon, "P + %d %d %08x %s\n", proc->process_id, proc->ppid, proc->cr3, proc->name);
        if (DEBUG) {
            printf("P + %d %d %08x %s\n", proc->process_id, proc->ppid, proc->cr3, proc->name);
        }
        sprintf(proc_mod_msg, "P + %d %d %08x %s\n", proc->process_id, proc->ppid, proc->cr3, proc->name);
    } else {
        monitor_printf(default_mon, "P - %d %d %08x %s\n", proc->process_id, proc->ppid, proc->cr3, proc->name);
        if (DEBUG) {
            printf("P - %d %d %08x %s\n", proc->process_id, proc->ppid, proc->cr3, proc->name);
        }
        sprintf(proc_mod_msg, "P - %d %d %08x %s\n", proc->process_id, proc->ppid, proc->cr3, proc->name);
    }
    handle_guest_message(proc_mod_msg);
}

int getExportTable_with_pe(
    IMAGE_NT_HEADERS *PeHeader,
    DWORD *numOfExport,
    struct pe_entry *pef,
    uint32_t cr3,
    uint32_t spaceType) {
    DWORD edt_va, edt_raw_offset;
    DWORD image_base = pef->base;
    IMAGE_EXPORT_DIRECTORY tmp;
    CPUState *env;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        if (env->cpu_index == 0) {
            break;
        }
    }

    edt_va = PeHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if (!edt_va) {
        printf("this file does not have a export table\n");
        return -1;
    }

    edt_raw_offset = edt_va + image_base;
    if (!edt_raw_offset)
        return -1;
    int n;
    if (spaceType) {
        n = TEMU_memory_rw_with_cr3(cr3, edt_raw_offset, (void *)&tmp, sizeof(tmp), 0);
    } else {
        n = cpu_memory_rw_debug(env, edt_raw_offset, (uint8_t *)&tmp, sizeof(tmp), 0);
    }

    if (n == -1) {
        monitor_printf(default_mon, "error read temp memory\n");
        if (DEBUG) {
            printf("error read temp memory\n");
        }
        return -1;
    }

    get_export_section(&tmp, numOfExport, pef, spaceType, cr3, env);

    return 0;
}

//ORIGINAL COMMENT
///////////////////////////////////////////////////////
//get nt_header from image
//spaceType 1 for user space and 0 for kernal space
uint32_t NTHDR_from_image(uint32_t base, IMAGE_NT_HEADERS *PeHeader, uint32_t cr3, uint32_t spaceType) {
    IMAGE_DOS_HEADER DosHeader;
    CPUState *env;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        if (env->cpu_index == 0) {
            break;
        }
    }

    if (spaceType) {
        TEMU_memory_rw_with_cr3(cr3, base, (void *)&DosHeader, sizeof(DosHeader), 0);
    } else {
        cpu_memory_rw_debug(env, base, (uint8_t *)&DosHeader, sizeof(DosHeader), 0);
    }

    if (DosHeader.e_magic != (0x5a4d)) {  // get first dos signature
        fprintf(stderr, "e_magic Error -- Not a valid PE file!\n");
        return -1;
    }

    if (spaceType) {
        TEMU_memory_rw_with_cr3(cr3, base + DosHeader.e_lfanew, (void *)PeHeader, sizeof(*PeHeader), 0);
    } else {
        cpu_memory_rw_debug(env, base + DosHeader.e_lfanew, (uint8_t *)PeHeader, sizeof(*PeHeader), 0);
    }

    if (PeHeader->Signature != IMAGE_NT_SIGNATURE) {  //get nt signature
        fprintf(stderr, "nt_sig Error -- Not a valid PE file!\n");
        return -1;
    }

    return 1;
}
uint32_t recon_getImageBase(IMAGE_NT_HEADERS *PeHeader) {
    return PeHeader->OptionalHeader.ImageBase;
}

//ORIGINAL COMMENT
// pass pe_entry structure
int update_api_with_pe(uint32_t cr3, struct pe_entry *pef, uint32_t spaceType) {
    uint32_t numOfExport = 0;  //requested_base = 0;
    int i;
    IMAGE_NT_HEADERS PeHeader;

    i = NTHDR_from_image(pef->base, &PeHeader, cr3, spaceType);
    if (i == -1) {
        return 0;
    }
    recon_getImageBase(&PeHeader);
    getExportTable_with_pe(&PeHeader, &numOfExport, pef, cr3, spaceType);
    return numOfExport;
}

void message_m(uint32_t pid, uint32_t cr3, struct pe_entry *pe) {
    char proc_mod_msg[2048] = {'\0'};
    char api_msg[2048] = {'\0'};
    struct api_entry *api = NULL, *next = NULL;

    if (strlen(pe->name) == 0)
        return;

    monitor_printf(default_mon, "M %d %08x \"%s\" %08x %08x \"%s\"\n", pid, cr3, pe->name, pe->base, pe->size, pe->fullname);
    if (DEBUG) {
        printf("M %d %08x \"%s\" %08x %08x \"%s\"\n", pid, cr3, pe->name, pe->base, pe->size, pe->fullname);
    }
    sprintf(proc_mod_msg, "M %d %08x \"%s\" %08x %08x \"%s\"\n", pid, cr3, pe->name, pe->base, pe->size, pe->fullname);
    update_api_with_pe(cr3, pe, ((pid == 0 || pid == 4) ? 0 : 1));
    if (!QLIST_EMPTY(&pe->apilist_head)) {
        QLIST_FOREACH_SAFE(api, &pe->apilist_head, loadedlist_entry, next) {
            sprintf(api_msg, "F %s %s %08x\n", pe->name, api->name, api->base);
            handle_guest_message(api_msg);
            QLIST_REMOVE(api, loadedlist_entry);
            free(api);
        }
    }
    handle_guest_message(proc_mod_msg);
}

struct pe_entry *update_loaded_user_mods_with_peb(uint32_t cr3, uint32_t peb, target_ulong vaddr, uint32_t pid, struct cr3_info *cr3i) {
    uint32_t ldr, memlist, first_dll, curr_dll;
    struct pe_entry *curr_entry = NULL;

    CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
    int ret = 0, flag = 0;

    if (peb == 0x00)
        return NULL;

    TEMU_memory_rw_with_cr3(cr3, peb + 0xc, (void *)&ldr, 4, 0);
    memlist = ldr + 0xc;
    TEMU_memory_rw_with_cr3(cr3, memlist, (void *)&first_dll, 4, 0);

    if (first_dll == 0)
        return NULL;

    curr_dll = first_dll;

    do {
        curr_entry = (struct pe_entry *)malloc(sizeof(*curr_entry));
        memset(curr_entry, 0, sizeof(*curr_entry));

        TEMU_memory_rw_with_cr3(cr3, curr_dll + 0x18, (void *)&(curr_entry->base), 4, 0);
        if (curr_entry->base == 0x0 && flag == 0) {
            flag = 1;
            TEMU_memory_rw_with_cr3(cr3, curr_dll, (void *)&curr_dll, 4, 0);
            continue;
        }
        TEMU_memory_rw_with_cr3(cr3, curr_dll + 0x20, (void *)&(curr_entry->size), 4, 0);
        readustr_with_cr3(curr_dll + 0x24, cr3, curr_entry->fullname, env);
        readustr_with_cr3(curr_dll + 0x2c, cr3, curr_entry->name, env);
        uint32_t modules = curr_entry->base;

        if (modules > 0x00300000 && !g_hash_table_lookup(cr3i->modules_tbl, modules)) {
            message_m(pid, cr3, curr_entry);
            g_hash_table_insert(cr3i->modules_tbl, (gpointer)modules, (gpointer)1);
        }
        free(curr_entry);
        TEMU_memory_rw_with_cr3(cr3, curr_dll, (void *)&curr_dll, 4, 0);
    } while (curr_dll != 0 && curr_dll != first_dll);

done:
    return ret;
}

target_ulong get_new_modules(CPUState *env, uint32_t cr3, target_ulong vaddr, struct cr3_info *cr3i) {
    uint32_t base = 0, self = 0, pid = 0;
    if (cr3 == system_cr3) {
        //Need to load system module here.
        pid = 4;  //TODO: Fix this.
        update_kernel_modules(cr3, vaddr, pid, cr3i);
    } else {
        base = env->segs[R_FS].base;
        cpu_memory_rw_debug(env, base + 0x18, (uint8_t *)&self, 4, 0);

        if (base != 0 && base == self) {
            uint32_t pid_addr = base + 0x20;
            cpu_memory_rw_debug(env, pid_addr, (uint8_t *)&pid, 4, 0);
            uint32_t peb_addr = base + 0x30;
            uint32_t peb, ldr;
            cpu_memory_rw_debug(env, peb_addr, (uint8_t *)&peb, 4, 0);
            update_loaded_user_mods_with_peb(cr3, peb, vaddr, pid, cr3i);
        }
    }
    return 0;
}

uint32_t present_in_vtable = 0;
uint32_t adding_to_vtable = 0;
uint32_t getting_new_mods = 0;
void tlb_call_back(CPUState *env, target_ulong vaddr) {
    struct cr3_info *cr3i = NULL;
    struct process_entry *procptr = NULL;
    int flag = 0;
    int new = 0;
    char proc_mod_msg[1024] = {'\0'};
    target_ulong modules;
    uint32_t exit_page = 0;
    uint32_t cr3 = env->cr[3];

    cr3i = g_hash_table_lookup(cr3_hashtable, cr3);
    if (!QEMU_is_in_kernel()) {
        if (!cr3i) {  // new cr3'
            new = 1;
            if (system_proc == NULL) {  //get the system proc first. This should be automatic.
                cr3i = (struct cr3_info *)malloc(sizeof(*cr3i));
                cr3i->value = system_cr3;
                cr3i->vaddr_tbl = g_hash_table_new(0, 0);
                cr3i->modules_tbl = g_hash_table_new(0, 0);
                g_hash_table_insert(cr3_hashtable, (gpointer)cr3, (gpointer)cr3i);
                procptr = get_system_process();
                if (!procptr) {
                    monitor_printf(default_mon, "System proc is null. shouldn't be. Stopping vm...\n");
                    if (DEBUG) {
                        printf("System proc is null. shouldn't be. Stopping vm...\n");
                    }
                    vm_stop(0);
                }
                system_proc = procptr;
                message_p(procptr, 1);  // 1 for addition, 0 for remove
                update_kernel_modules(system_cr3, vaddr, procptr->process_id, cr3i);
                exit_page = (((procptr->EPROC_base_addr) + 0x78) >> 3) << 3;
                g_hash_table_insert(eproc_ht, (gpointer)(exit_page), (gpointer)1);
                QLIST_INIT(&procptr->modlist_head);
            }

            cr3i = (struct cr3_info *)malloc(sizeof(*cr3i));
            cr3i->value = cr3;
            cr3i->vaddr_tbl = g_hash_table_new(0, 0);
            cr3i->modules_tbl = g_hash_table_new(0, 0);
            g_hash_table_insert(cr3i->vaddr_tbl, (gpointer)vaddr, (gpointer)1);
            g_hash_table_insert(cr3_hashtable, (gpointer)cr3, (gpointer)cr3i);

            procptr = get_new_process();
            message_p(procptr, 1);  // 1 for addition, 0 for remove

            exit_page = (((procptr->EPROC_base_addr) + 0x78) >> 3) << 3;
            g_hash_table_insert(eproc_ht, (gpointer)(exit_page), (gpointer)1);
            QLIST_INIT(&procptr->modlist_head);

            if (g_hash_table_size(cr3_hashtable) == 2)
                startup_registrations();
        }
    } else if (!cr3i) {
        goto done;
    }

    if (!new) {  // not a new cr3
        if (g_hash_table_lookup(cr3i->vaddr_tbl, (gpointer)vaddr)) {
            present_in_vtable++;
            goto done;
        }
        g_hash_table_insert(cr3i->vaddr_tbl, (gpointer)vaddr, (gpointer)1);
        adding_to_vtable++;
    }

    getting_new_mods++;
    get_new_modules(env, cr3, vaddr, cr3i);

done:
    return;
}

void update_kernel_modules(uint32_t cr3, target_ulong vaddr, uint32_t pid, struct cr3_info *cr3i) {
    uint32_t kdvb, psLM, curr_mod, next_mod;
    uint32_t base, size, holder;
    //char name[512], fullname[2048];
    CPUState *env;
    struct pe_entry *curr_entry = NULL;
    if (gkpcr == 0 || cr3i == NULL)
        return;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        if (env->cpu_index == 0) {
            break;
        }
    }

    cpu_memory_rw_debug(env, gkpcr + KDVB_OFFSET, (uint8_t *)&kdvb, 4, 0);
    cpu_memory_rw_debug(env, kdvb + PSLM_OFFSET, (uint8_t *)&psLM, 4, 0);
    cpu_memory_rw_debug(env, psLM, (uint8_t *)&curr_mod, 4, 0);

    while (curr_mod != 0 && curr_mod != psLM) {
        curr_entry = (struct pe_entry *)malloc(sizeof(*curr_entry));

        memset(curr_entry, 0, sizeof(*curr_entry));
        QLIST_INIT(&curr_entry->apilist_head);

        cpu_memory_rw_debug(env, curr_mod + handle_funds[GuestOS_index].offset->DLLBASE_OFFSET, (uint8_t *)&(curr_entry->base), 4, 0);  // dllbase  DLLBASE_OFFSET
        cpu_memory_rw_debug(env, curr_mod + handle_funds[GuestOS_index].offset->SIZE_OFFSET, (uint8_t *)&(curr_entry->size), 4, 0);     // dllsize  SIZE_OFFSET
        holder = readustr(curr_mod + handle_funds[GuestOS_index].offset->DLLNAME_OFFSET, (curr_entry->name), env);
        readustr(curr_mod + 0x24, curr_entry->fullname, env);
        if (!g_hash_table_lookup(cr3i->modules_tbl, curr_entry->base)) {
            update_api_with_pe(cr3, curr_entry, 0);
            message_m(pid, cr3, curr_entry);
            g_hash_table_insert(cr3i->modules_tbl, (gpointer)(curr_entry->base), (gpointer)1);
        }
        free(curr_entry);
        cpu_memory_rw_debug(env, curr_mod, (uint8_t *)&next_mod, 4, 0);
        cpu_memory_rw_debug(env, next_mod + 4, (uint8_t *)&holder, 4, 0);
        if (holder != curr_mod) {
            monitor_printf(default_mon, "Something is wrong. Next->prev != curr. curr_mod = 0x%08x\n",
                           curr_mod);
            if (DEBUG) {
                printf("Something is wrong. Next->prev != curr. curr_mod = 0x%08x\n",
                       curr_mod);
            }
            break;
        }
        curr_mod = next_mod;
    }
}

int readcstr(target_ulong addr, void *buf, CPUState *env, uint32_t cr3, int spaceType) {
    //bytewise for now, perhaps block wise later.
    char *store = (char *)buf;
    int i = -1;
    int flag;
    do {
        if (++i == MAX_NAME_LENGTH)
            break;

        if (spaceType) {
            flag = TEMU_memory_rw_with_cr3(cr3, addr + i, (void *)&store[i], 1, 0);
        } else {
            flag = cpu_memory_rw_debug(env, addr + i, (uint8_t *)&store[i], 1, 0);
        }

        if (flag < 0) {
            store[i] = '\0';
            return i;
        }
    } while (store[i] != '\0');

    if (i == MAX_NAME_LENGTH) {
        store[i - 1] = '\0';
    }
    return i - 1;
}

int get_export_section(
    IMAGE_EXPORT_DIRECTORY *tmp,
    DWORD *numOfExport,
    struct pe_entry *pef,
    int spaceType,
    uint32_t cr3,
    CPUState *env) {
    DWORD *export_table, *ptr_to_table, *ptr_name_table;
    uint32_t image_base = pef->base;
    WORD *ptr_index_table;
    struct api_entry *api = NULL;

    ptr_to_table = (DWORD *)(tmp->AddressOfFunctions + image_base);
    ptr_name_table = (DWORD *)(tmp->AddressOfNames + image_base);
    ptr_index_table = (WORD *)(tmp->AddressOfNameOrdinals + image_base);

    uint32_t dllname = tmp->Name;
    char names[64];
    int m, i;
    if (spaceType) {
        m = TEMU_memory_rw_with_cr3(cr3, dllname + image_base, (void *)names, 16, 0);
    } else {
        m = cpu_memory_rw_debug(env, dllname + image_base, (uint8_t *)names, 16, 0);
    }
    if (m == -1) {
        // monitor_printf(default_mon,"error read name memory\n");
		if(DEBUG){
			printf("error read name memory\n");
		}
        return -1;
    }
    (*numOfExport) = tmp->NumberOfFunctions;
    DWORD num = tmp->NumberOfNames;
    WORD num1 = tmp->NumberOfNames;
    export_table = (DWORD *)malloc((*numOfExport) * sizeof(DWORD));
    DWORD *name_table = (DWORD *)malloc((num) * sizeof(DWORD));
    WORD *index_table = (WORD *)malloc((num1) * sizeof(WORD));
    if (spaceType) {
        TEMU_memory_rw_with_cr3(cr3, ptr_to_table, export_table, (*numOfExport) * sizeof(DWORD), 0);
        TEMU_memory_rw_with_cr3(cr3, ptr_name_table, name_table, (num) * sizeof(DWORD), 0);
        TEMU_memory_rw_with_cr3(cr3, ptr_index_table, index_table, (num1) * sizeof(WORD), 0);
    } else {
        cpu_memory_rw_debug(env, ptr_to_table, export_table, (*numOfExport) * sizeof(DWORD), 0);
        cpu_memory_rw_debug(env, ptr_name_table, name_table, (num) * sizeof(DWORD), 0);
        cpu_memory_rw_debug(env, ptr_index_table, index_table, (num1) * sizeof(WORD), 0);
    }

    for (i = 0; i < (num); i++) {
        api = (struct api_entry *)malloc(sizeof(*api));
        memset(api, 0, sizeof(*api));
        char apiname[64] = {0};
        readcstr(name_table[i] + image_base, &apiname[0], env, cr3, spaceType);
        WORD k = index_table[i];
        //export_table[k] += image_base;

        api->base = export_table[k];
        strncpy(api->name, apiname, 63);
        api->name[63] = '\0';
        QLIST_INSERT_HEAD(&(pef->apilist_head), api, loadedlist_entry);
        /* put in map*/
    }
    free(name_table);
    free(index_table);
    free(export_table);  //memleak
    return 0;
}

uint32_t get_kpcr() {
    uint32_t kpcr, selfpcr;
    CPUState *env;

    for (env = first_cpu; env != NULL; env = env->next_cpu) {
        if (env->cpu_index == 0) {
            break;
        }
    }

    kpcr = 0;
    cpu_memory_rw_debug(env, env->segs[R_FS].base + 0x1c, (uint8_t *)&selfpcr, 4, 0);

    if (selfpcr == env->segs[R_FS].base) {
        kpcr = selfpcr;
    }
    monitor_printf(default_mon, "KPCR at: 0x%08x\n", kpcr);
	if(DEBUG){
		printf("KPCR at: 0x%08x\n", kpcr);	
	}

    return kpcr;
}

//MODIFIED TO WORK ONLY WITH WIN7
void get_os_version() {
    // CPUState* env;
    // for (env = first_cpu; env != NULL; env = env->next_cpu) {
    // 	if (env->cpu_index == 0) {
    // 		break;
    // 	}
    // }
    // uint32_t kdvb, CmNtCSDVersion, num_package;

    // if (gkpcr == 0xffdff000) {
    // 	cpu_memory_rw_debug(env, gkpcr + 0x34, (uint8_t *) &kdvb, 4, 0);
    // 	cpu_memory_rw_debug(env, kdvb + 0x290, (uint8_t *) &CmNtCSDVersion, 4, 0); //CmNt version info
    // 	cpu_memory_rw_debug(env, CmNtCSDVersion, (uint8_t *) &num_package, 4, 0);
    // 	uint32_t num = num_package >> 8;
    // 	if (num == 0x02) {
    // 		GuestOS_index = 0; //winxpsp2
    // 	} else if (num == 0x03) {
    // 		GuestOS_index = 1; //winxpsp3
    // 	}
    // } else {
    GuestOS_index = 2;  //win7
                        // }
}

static uint32_t get_ntoskrnl_internal(uint32_t curr_page, CPUState *env) {
    IMAGE_DOS_HEADER *DosHeader = NULL;

    uint8_t page_data[4 * 1024] = {0};  //page_size
    uint16_t DOS_HDR = 0x5a4d;

    while (curr_page > 0x80000000) {
        if (cpu_memory_rw_debug(env, curr_page, (uint8_t *)page_data, 4 * 1024, 0) >= 0) {  //This is paged out. Just continue
            if (memcmp(&page_data, &DOS_HDR, 2) == 0) {
                DosHeader = (IMAGE_DOS_HEADER *)&(page_data);
                if (DosHeader->e_magic != 0x5a4d)
                    goto dec_continue;

                monitor_printf(default_mon, "DOS header matched at: 0x%08x\n", curr_page);
				if(DEBUG){
					printf("DOS header matched at: 0x%08x\n", curr_page);
				}
                if (*((uint32_t *)(&page_data[*((uint32_t *)&page_data[0x3c])])) != IMAGE_NT_SIGNATURE)
                    goto dec_continue;

                return curr_page;
            }
        }
    dec_continue:
        curr_page -= 1024 * 4;
    }
    return 0;
}

uint32_t get_ntoskrnl(CPUState *env) {
    uint32_t ntoskrnl_base = 0, exit_page = 0, cr3 = 0;
    struct cr3_info *cr3i = NULL;
    struct process_entry *procptr = NULL;
    monitor_printf(default_mon, "Trying by scanning back from sysenter_eip...\n");
	if(DEBUG){
		printf("Trying by scanning back from sysenter_eip...\n");
	}
    ntoskrnl_base = get_ntoskrnl_internal(env->sysenter_eip & 0xfffff000, env);
    if (ntoskrnl_base)
        goto found;
    monitor_printf(default_mon, "Trying by scanning back from eip that sets kpcr...\n");
	if(DEBUG){
		printf("Trying by scanning back from eip that sets kpcr...\n");
	}
    ntoskrnl_base = get_ntoskrnl_internal(env->eip & 0xfffff000, env);
    if (ntoskrnl_base)
        goto found;
    return 0;

found:
    cr3 = system_cr3 = env->cr[3];

    monitor_printf(default_mon, "OS base found at: 0x%08x\n", ntoskrnl_base);
	if(DEBUG){
		printf("OS base found at: 0x%08x\n", ntoskrnl_base);
	}

    return ntoskrnl_base;
}

void insn_end_cb(CPUState *env, TranslationBlock *tb) {
    struct cr3_info *cr3i = NULL;
    uint32_t cr3 = env->cr[3];
    uint32_t base;
    insn_counter++;

    if (env->eip > 0x80000000 && env->segs[R_FS].base > 0x80000000) {
        gkpcr = get_kpcr();
        if (gkpcr != 0) {
            //TODO
            // DECAF_unregister_callback(DECAF_INSN_END_CB, insn_handle);

            QLIST_INIT(&loadedlist);
            QLIST_INIT(&processlist);
            QLIST_INIT(&threadlist);
            QLIST_INIT(&filelist);
            cr3_hashtable = g_hash_table_new(0, 0);
            eproc_ht = g_hash_table_new(0, 0);

            get_os_version();
            base = get_ntoskrnl(env);
            if (!base) {
                monitor_printf(default_mon, "Unable to locate kernel base. Stopping VM...\n");
				if(DEBUG){
					printf("Unable to locate kernel base. Stopping VM...\n");
				}
                vm_stop(0);
                return;
            }

            //////////////////////////////block_handle = DECAF_register_callback(DECAF_BLOCK_BEGIN_CB, block_begin_cb, NULL);

            //TODO debug this function that generate segfault
            // qemu_mod_timer(recon_timer, qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 30);
            //TODO replace tlb callback
            // TEMU_register_tlb_callback(tlb_call_back);
        }
    }
}

uint32_t exit_block_end_eip = 0;
void check_procexit() {
    CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
    //	if(!TEMU_is_in_kernel())
    //		return;
    //
    //	if(exit_block_end_eip && env->eip != exit_block_end_eip)
    //		return;

    qemu_mod_timer(recon_timer, qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 30);

    monitor_printf(default_mon, "Checking for proc exits...\n");
	if(DEBUG){
		printf("Checking for proc exits...\n");
	}

    struct process_entry *proc = NULL, *next = NULL;
    uint32_t end_time[2];
    if (!QLIST_EMPTY(&processlist)) {
        QLIST_FOREACH_SAFE(proc, &processlist, loadedlist_entry, next) {
            if (proc->ppid == 0)
                continue;
            //0x78 for xp, 0x88 for win7
            cpu_memory_rw_debug(env, (proc->EPROC_base_addr) + handle_funds[GuestOS_index].offset->PEXIT_TIME, (uint8_t *)&end_time[0], 8, 0);
            if (end_time[0] | end_time[1]) {
                QLIST_REMOVE(proc, loadedlist_entry);
                remove_proc(proc);
                message_p(proc, 0);
                free(proc);
                exit_block_end_eip = env->eip;
                //return;
            }
        }
    }
}

bool translate_callback(CPUState *env, target_ulong pc) {
    //We are not interested in translation so we make a fake function
    return pc < 0x80000000;
}

void recon_init(void *self) {
    // insn_handle = DECAF_register_callback(DECAF_INSN_END_CB, insn_end_cb, NULL);
    panda_cb pcb;
    pcb.insn_translate = translate_callback;
    panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_after_exec = insn_end_cb;
    panda_register_callback(self, PANDA_CB_INSN_AFTER_EXEC, pcb);
    recon_timer = qemu_new_timer_ns(vm_clock, check_procexit, 0);
}

void uninit_plugin(void *self) {
    printf("Unloading plugin cfi\n");
}

int (*comparestring)(const char *, const char *);
bool init_plugin(void *self) {
#if defined(TARGET_I386)  //&& !defined(TARGET_X86_64)
    printf("Initializing plugin cfi\n");
    panda_require("libfi");
    panda_require("procmon");
    assert(init_libfi_api());
    comparestring = strcasecmp;
    wl_init(self);
    // wl_interface.plugin_cleanup = cfi_cleanup;
    wl_interface.mon_cmds = wl_term_cmds;
    wl_interface.info_cmds = wl_info_cmds;
    // loadmainmodule_notify = wl_loadmainmodule_notify;
    PPP_REG_CB("procmon", new_main_module_notify, wl_loadmainmodule_notify);
    // loadmodule_notify = wl_load_module_notify;
    PPP_REG_CB("procmon", new_module_notify, wl_load_module_notify);
    // removeproc_notify = wl_procexit;
    PPP_REG_CB("procmon", removed_process_notify, wl_procexit);
    // return &wl_interface;
    return true;
#else
    printf("CFI plugin not supported on this architecture\n");
    return false;
#endif
}

#endif