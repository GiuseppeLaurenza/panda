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

#include <iostream>
#include <string>
extern "C" {
#include "config.h"
#include "cpu.h"
#include "monitor.h"
#include "panda_common.h"
#include "panda_plugin.h"
#include "panda_plugin_plugin.h"
#include "qemu-queue.h"
bool init_plugin(void *);
void uninit_plugin(void *);
}
using namespace std;

#include "../libfi/libfi.h"
#include "../libfi/libfi_ext.h"
#include "../libfi/libfi_object.h"
#include "../procmon/procmon.h"
#include "recon_clean.h"

bool DEBUG;

//############TODO##########
//REPLACE ALL THE TIMER WORKFLOW

/* Hash table to hold the cr3 to process entry mapping */
GHashTable *cr3_pe_ht;
/* Hash table to hold the full file name to file entry */
GHashTable *filemap_ht;
/* Hash table to keep track of clashes. Shouldn't exist. :( */
GHashTable *vio_ht;

uint32_t gkpcr;
// extern uint32_t system_cr3=0;
uint32_t system_cr3 = 0;

struct cr3_info {
    uint32_t value;
    GHashTable *vaddr_tbl;
    GHashTable *modules_tbl;
};

//recon variables
QLIST_HEAD(loadedlist_head, service_entry)
loadedlist;
QLIST_HEAD(processlist_head, process_entry)
processlist;
QLIST_HEAD(threadlist_head, thread_entry)
threadlist;
QLIST_HEAD(filelist_head, file_entry)
filelist;

struct process_entry *system_proc = NULL;

GHashTable *cr3_hashtable = NULL;
GHashTable *eproc_ht = NULL;

unsigned long long insn_counter = 0;

void *my_self;

//TODO Clean all reference to uint32_t GuestOS_index;
uint32_t GuestOS_index = 0;

#if defined(TARGET_I386)
static inline int QEMU_is_in_kernel() {
    CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
    return ((env->hflags & HF_CPL_MASK) == 0);
}

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

//#########TODO#############
//DISCOVER HOW TO MAKE IT WORKS
void vm_stop(int i) {
    printf("CALLED vm_stop\n");
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


uint32_t present_in_vtable = 0;
uint32_t adding_to_vtable = 0;
uint32_t getting_new_mods = 0;

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

//TODO TEMU FUNCTIONS

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

        //TODO CHECK CONVERSION TO uint8_t
        cpu_physical_memory_rw(phys_addr + (addr & ~TARGET_PAGE_MASK),
                               (uint8_t *)buf, l, is_write);
        len -= l;
        buf += l;
        addr += l;
    }
    return 0;
}

uint32_t recon_getImageBase(IMAGE_NT_HEADERS *PeHeader) {
    return PeHeader->OptionalHeader.ImageBase;
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
        if (DEBUG) {
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
        TEMU_memory_rw_with_cr3(cr3, *ptr_to_table, export_table, (*numOfExport) * sizeof(DWORD), 0);
        TEMU_memory_rw_with_cr3(cr3, *ptr_name_table, name_table, (num) * sizeof(DWORD), 0);
        TEMU_memory_rw_with_cr3(cr3, *ptr_index_table, index_table, (num1) * sizeof(WORD), 0);
    } else {
        cpu_memory_rw_debug(env, *ptr_to_table, (uint8_t *)*(uint32_t *)export_table, (*numOfExport) * sizeof(DWORD), 0);
        cpu_memory_rw_debug(env, *ptr_name_table, (uint8_t *)*(uint32_t *)name_table, (num) * sizeof(DWORD), 0);
        cpu_memory_rw_debug(env, *ptr_index_table, (uint8_t *)*(uint32_t *)index_table, (num1) * sizeof(WORD), 0);
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

//TODO - update with panda function
/*Original comment */
//TODO FIND HOW TO IMPLEMENT FROM PROCMOD.CPP
void handle_guest_message(const char *message) {
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

//TODO DISCOVER The meaning of this functions (see recon.c for the entire flow)
int readustr(uint32_t addr, void *buf, CPUState *env) {
    return 1;
}

/* This is stop gap arrangement to utilize the existing infrastructure.
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
        if (!g_hash_table_lookup(cr3i->modules_tbl, (gpointer)curr_entry->base)) {
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

void update_processlist() {
    update_active_processlist();
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
            printf("0x%08x\t%d\t%s\t%d\t%d\t%d\t0x%08x\n",
                   pe->EPROC_base_addr, pe->ppid, pe->name, pe->process_id,
                   pe->number_of_threads, pe->number_of_handles, pe->cr3);
        }
    }
    pe = QLIST_FIRST(&processlist);
    return pe;
}

struct process_entry *get_system_process() {
    struct process_entry *pe = NULL;
    // handle_funds[GuestOS_index].update_processlist();
    update_processlist();
    QLIST_FOREACH(pe, &processlist, loadedlist_entry) {
        if (strcmp(pe->name, "System") == 0)
            break;
    }
    return pe;
}

// void tlb_call_back(CPUState* env, target_ulong vaddr)
int tlb_call_back(CPUState *env, target_ulong oldval, target_ulong newval) {
    if (DEBUG) {
        printf("TLB Callback, address changed from %lu to %lu", oldval, newval);
    }
    struct cr3_info *cr3i = NULL;
    struct process_entry *procptr = NULL;
    int flag = 0;
    int new_cb = 0;
    char proc_mod_msg[1024] = {'\0'};
    target_ulong modules;
    uint32_t exit_page = 0;
    uint32_t cr3 = env->cr[3];

    cr3i = (struct cr3_info *)(g_hash_table_lookup(cr3_hashtable, (gpointer)cr3));
    if (!QEMU_is_in_kernel()) {
        if (!cr3i) {
            new_cb = 1;
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
                // update_kernel_modules(system_cr3, vaddr, procptr->process_id, cr3i); CHANGED vaddr to newval
                update_kernel_modules(system_cr3, newval, procptr->process_id, cr3i);
                exit_page = (((procptr->EPROC_base_addr) + 0x78) >> 3) << 3;
                g_hash_table_insert(eproc_ht, (gpointer)(exit_page), (gpointer)1);
                QLIST_INIT(&procptr->modlist_head);
            }

            cr3i = (struct cr3_info *)malloc(sizeof(*cr3i));
            cr3i->value = cr3;
            cr3i->vaddr_tbl = g_hash_table_new(0, 0);
            cr3i->modules_tbl = g_hash_table_new(0, 0);
            g_hash_table_insert(cr3i->vaddr_tbl, (gpointer)newval, (gpointer)1);
            g_hash_table_insert(cr3_hashtable, (gpointer)cr3, (gpointer)cr3i);
            procptr = get_new_process();
            message_p(procptr, 1);  // 1 for addition, 0 for remove

            exit_page = (((procptr->EPROC_base_addr) + 0x78) >> 3) << 3;
            g_hash_table_insert(eproc_ht, (gpointer)(exit_page), (gpointer)1);
            QLIST_INIT(&procptr->modlist_head);

            if (g_hash_table_size(cr3_hashtable) == 2){
                startup_registrations();
            }
        }
    } else if (!cr3i) {
        goto done;
    }

    //         if(!new_cb) { // not a new cr3
    // 				if(g_hash_table_lookup(cr3i->vaddr_tbl, (gpointer)vaddr)) {
    // 						present_in_vtable++;
    // 						goto done;
    // 				}
    // 				g_hash_table_insert(cr3i->vaddr_tbl, (gpointer) vaddr, (gpointer)1);
    // 				adding_to_vtable++;
    // }

    //         getting_new_mods++;
    //         get_new_modules(env, cr3, vaddr, cr3i);

done:
    return 1;
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
                if (DEBUG) {
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
    if (DEBUG) {
        printf("Trying by scanning back from sysenter_eip...\n");
    }
    ntoskrnl_base = get_ntoskrnl_internal(env->sysenter_eip & 0xfffff000, env);
    if (ntoskrnl_base)
        goto found;
    monitor_printf(default_mon, "Trying by scanning back from eip that sets kpcr...\n");
    if (DEBUG) {
        printf("Trying by scanning back from eip that sets kpcr...\n");
    }
    ntoskrnl_base = get_ntoskrnl_internal(env->eip & 0xfffff000, env);
    if (ntoskrnl_base)
        goto found;
    return 0;

found:
    cr3 = system_cr3 = env->cr[3];

    monitor_printf(default_mon, "OS base found at: 0x%08x\n", ntoskrnl_base);
    if (DEBUG) {
        printf("OS base found at: 0x%08x\n", ntoskrnl_base);
    }

    return ntoskrnl_base;
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
    if (DEBUG) {
        printf("KPCR at: 0x%08x\n", kpcr);
    }

    return kpcr;
}

// void insn_end_cb(CPUState *env, TranslationBlock *tb) {
int insn_end_cb(CPUState *env, target_ulong pc) {
    // if (DEBUG) {
    //     printf("Callback by %d pointer\n",pc);
    // }
    struct cr3_info *cr3i = NULL;
    uint32_t cr3 = env->cr[3];
    uint32_t base;
    insn_counter++;
    if (DEBUG) {
        printf("%lu - %lu\n", env->eip, env->segs[R_FS].base);
    }
    //TODO ASK BRENDAN                                                    // 2147119104
    if (env->eip > 0x80000000 && env->segs[R_FS].base > 0x80000000) {
        if (DEBUG) {
            printf("INSN_END_CB: inside if\n");
        }
        gkpcr = get_kpcr();
        if (gkpcr != 0) {
            // DECAF_unregister_callback(DECAF_INSN_END_CB, insn_handle);
            panda_cb pcb;
            pcb.insn_after_exec = insn_end_cb;
            panda_disable_callback(my_self, PANDA_CB_INSN_AFTER_EXEC, pcb);

            QLIST_INIT(&loadedlist);
            QLIST_INIT(&processlist);
            QLIST_INIT(&threadlist);
            QLIST_INIT(&filelist);
            cr3_hashtable = g_hash_table_new(0, 0);
            eproc_ht = g_hash_table_new(0, 0);
            //         get_os_version();
            base = get_ntoskrnl(env);
            if (!base) {
                monitor_printf(default_mon, "Unable to locate kernel base. Stopping VM...\n");
                if (DEBUG) {
                    printf("Unable to locate kernel base. Stopping VM...\n");
                }
                vm_stop(0);
                return -1;
            }

            //TODO Replace TIMER
            // qemu_mod_timer(recon_timer, qemu_get_clock_ns(vm_clock) + get_ticks_per_sec() * 30);

            // TEMU_register_tlb_callback(tlb_call_back);
            pcb.after_PGD_write = tlb_call_back;
            panda_register_callback(my_self, PANDA_CB_VMI_PGD_CHANGED, pcb);
        }
    }
    return 1;
}

bool translate_callback(CPUState *env, target_ulong pc) {
    //We are not interested in translation so we make a fake function
    return pc < 0x80000000;
}

void recon_init() {
    if (DEBUG) {
        printf("RECON INIT\n");
    }
    // insn_handle = DECAF_register_callback(DECAF_INSN_END_CB, insn_end_cb, NULL);
    panda_cb pcb;
    pcb.insn_translate = translate_callback;
    panda_register_callback(my_self, PANDA_CB_INSN_TRANSLATE, pcb);
    pcb.insn_after_exec = insn_end_cb;
    panda_register_callback(my_self, PANDA_CB_INSN_AFTER_EXEC, pcb);
    //#########TODO#############
    // recon_timer = qemu_new_timer_ns(vm_clock, check_procexit, 0);
}

static int wl_init() {
    //##########TODO#########
    // procmod_init();
    // function_map_init();
    // init_hookapi();

    recon_init();
    cr3_pe_ht = g_hash_table_new(0, 0);
    filemap_ht = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
    vio_ht = g_hash_table_new(0, 0);

    //#########TODO#############
    // load_file_wl("file_whitelist.dump");

    return 0;
}

#endif
void uninit_plugin(void *self) {
    printf("Unloading plugin cfi\n");
}

bool init_plugin(void *self) {
#if defined(TARGET_I386)  //&& !defined(TARGET_X86_64)
    printf("Initializing plugin cfi\n");
    panda_arg_list *args = panda_get_args("cfi");
    DEBUG = panda_parse_bool(args, "DEBUG");
    printf("CFI plugin, DEBUG mode %s\n", DEBUG ? "enabled" : "disabled");
    my_self = self;
    panda_require("libfi");
    panda_require("procmon");
    assert(init_libfi_api());
    // comparestring = strcasecmp;
    // // wl_interface.plugin_cleanup = cfi_cleanup;
    // wl_interface.mon_cmds = wl_term_cmds;
    // wl_interface.info_cmds = wl_info_cmds;
    // // loadmainmodule_notify = wl_loadmainmodule_notify;
    // PPP_REG_CB("procmon", new_main_module_notify, wl_loadmainmodule_notify);
    // // loadmodule_notify = wl_load_module_notify;
    // PPP_REG_CB("procmon", new_module_notify, wl_load_module_notify);
    // // removeproc_notify = wl_procexit;
    // PPP_REG_CB("procmon", removed_process_notify, wl_procexit);
    // // return &wl_interface;
    wl_init();
    return true;
#else
    cout << "CFI plugin not supported on this architecture" << endl;
    return false;
#endif
}