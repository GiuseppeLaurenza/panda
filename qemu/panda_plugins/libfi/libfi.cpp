

#define __STDC_FORMAT_MACROS

#include <algorithm>
#include <iostream>
#include <string>
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

#include "../pri/pri_types.h"
#include "../pri/pri_ext.h"
#include "../pri/pri.h"


#include "cpu.h"
#include "libfi.h"
#include "libfi_int_fns.h"

bool init_plugin(void *);
void uninit_plugin(void *);

void libfi_add_callback(char *libname, char *fnname, int isenter, uint32_t numargs, libfi_cb_t cb);
void libfi_remove_callback(char *libname, char *fnname, int isenter, uint32_t numargs, libfi_cb_t cb);
// void libfi_add_cbe(struct LibFICbEntry *cbe);
// void libfi_remove_cbe(struct LibFICbEntry *cbe);
}

#include "../callstack_instr/callstack_instr.h"
#include "../callstack_instr/callstack_instr_ext.h"

using namespace std;

#if defined(TARGET_I386)  //&& !defined(TARGET_X86_64)

#include "libfi_object.h"
// struct LibFICbEntry {
//     string libname;
//     string fnname;
//     bool isenter;
//     uint32_t numargs;
//     libfi_cb_t callback;
//     uint32_t entry_size;
// };
std::vector<LibFICbEntry> libficbes;

// ok this is pretty perfunctory
enum CallingConv { CC_CDECL,
                   CC_DUNNO };
int calling_convention = CC_CDECL;

// #define ESP ((CPUX86State *)((CPUState *)env->env_ptr))->regs[R_ESP]
// #define EAX ((CPUArchState*)env->env_ptr)->regs[R_EAX]
#define MAX_ARGS 16
uint32_t word_size = 0;

// this will be used to hold onto program args
uint8_t *arg = NULL;

bool debug = false;

static inline void set_word_size() {
    if (word_size == 0) {
        word_size = (((CPUX86State *)first_cpu)->hflags & HF_LMA_MASK) ? 8 : 4;
        arg = (uint8_t *)malloc(word_size * MAX_ARGS);
    }
}

// Assumes target+host have same endianness.
static inline uint32_t get_word(CPUState *env, target_ulong addr) {
    target_ulong result = 0;
    panda_virtual_memory_rw(env, addr, (uint8_t *)&result, word_size, 0);
    return result;
}

static inline uint32_t get_stack(CPUState *env, int offset_number) {
    return get_word(env, ESP + word_size * offset_number);
}

inline bool endswith(const char *haystack, std::string suffix) {
    std::string s(haystack);
    return suffix.size() <= s.size() && (s.substr(s.size() - suffix.size()) == suffix);
}

void fn_start(CPUState *env, target_ulong pc, const char *file_name,
              const char *funct_name, unsigned long long lno) {
    // grab args for this fn if this guy has either enter or exit cb
    // printf("%s - %s\n", file_name, funct_name);
    for (LibFICbEntry &cbe : libficbes) {
        // CHANGED without !
        if (endswith(funct_name, cbe.fnname)) {
            set_word_size();
            if (calling_convention == CC_CDECL) {
                if (debug) printf("fn start %s pc=0x%x file_name %s\n", funct_name, pc, file_name);
                if (debug) printf("grabbing %d fn args\n", cbe.numargs);
                for (uint32_t i = 0; i < cbe.numargs; i++) {
                    if (word_size == 4) {
                        uint32_t a = get_stack(env, i + 1);
                        *((uint32_t *)(arg + i * word_size)) = a;
                        if (debug) printf("fn_start arg %d = 0x%x\n", i, a);
                    } else {
                        assert(1 == 0);
                    }
                }
            }
            break;
        }
    }
    for (LibFICbEntry &cbe : libficbes) {
        // CHANGED without !
        // if (cbe.isenter && endswith(funct_name, "!" + cbe.fnname)) {
        if (cbe.isenter && endswith(funct_name, cbe.fnname)) {
            if (debug) printf(" -- fn start callback\n");
            (*cbe.callback)(env, pc, (uint8_t *)arg);
        }
    }
}

void fn_return(CPUState *env, target_ulong pc, const char *file_name,
               const char *funct_name, unsigned long long lno) {
    if (!arg) {
        if (debug) {
            printf("*error* fn end %s .  Did not have argument array populated. EAX=%x\n",
                   funct_name, EAX);
        }
        return;
    }
    if (debug) printf("fn end %s EAX=%x\n", funct_name, EAX);
    for (LibFICbEntry &cbe : libficbes) {
        // funct_name comes from pri_dwarf and may be lib:!plt:fname
        // or lib:fname
        // if (!cbe.isenter && (endswith(funct_name, "!" + cbe.fnname))) {
        // CHANGED without !
        if (!cbe.isenter && (endswith(funct_name, cbe.fnname))) {
            if (debug) printf("fn end %s EAX=%x\n", funct_name, EAX);
            // args populated by fn_start i hope
            for (uint32_t i = 0; i < cbe.numargs; i++) {
                uint32_t a = *((uint32_t *)(arg + word_size * i));
                if (debug) printf("arg %d = %x\n", i, a);
            }
            if (debug) printf(" -- fn exit callback\n");
            (*cbe.callback)(env, pc, (uint8_t *)arg);
        }
    }
}

void libfi_add_callback(char *libname, char *fnname, int isenter, uint32_t numargs, libfi_cb_t cb) {
    LibFICbEntry cbe = {string(libname), string(fnname), (isenter == 1), numargs, cb, 0};
    cbe.entry_size = sizeof(cbe);
    libficbes.push_back(cbe);
    printf("adding callback %s %s %d \n", libname, fnname, isenter);
}

// void libfi_add_cbe(struct LibFICbEntry *cbe) {
//     libficbes.push_back(*cbe);
//     printf("adding callback %s %s %d \n", (cbe->libname).c_str(), (cbe->fnname).c_str(), cbe->isenter);
// }

void remove_element(string libname, string fnname, int isenter, uint32_t numargs, libfi_cb_t cb) {
    // printf("Prima %d\n",libficbes.size());
    auto iterator = libficbes.begin();
    while (iterator != libficbes.end()) {
        // cout << iterator->libname << " - " << libname << endl;
        if (!(iterator->libname.compare(libname)) && !(iterator->fnname.compare(fnname)) && iterator->isenter == isenter && iterator->numargs == numargs && iterator->callback == cb) {
            libficbes.erase(iterator);
            break;
        }
        iterator++;
    }
    // printf("Dopo %d\n",libficbes.size());
}

void libfi_remove_callback(char *libname, char *fnname, int isenter, uint32_t numargs, libfi_cb_t cb) {
    remove_element(string(libname), string(fnname), isenter, numargs, cb);
    printf("removing callback %s %s %d \n", libname, fnname, isenter);
}

// void libfi_remove_cbe(struct LibFICbEntry *cbe) {
//     remove_element(cbe->libname, cbe->fnname, cbe->isenter, cbe->numargs, cbe->callback);
//     printf("remove callback %s %s %d \n", (cbe->libname).c_str(), (cbe->fnname).c_str(), cbe->isenter);
// }

// void get_cbe(char *libname, char *fnname, int isenter, uint32_t numargs, libfi_cb_t cb, struct LibFICbEntry *cbe) {
//     // printf("%ul\n",libficbes.size());
//     // vector<LibFICbEntry>::iterator it = libficbes.begin();
//     auto it = libficbes.begin();
//     while (it != libficbes.end()) {
//         if (!(it->libname.compare(string(libname))) && !(it->fnname.compare(string(fnname))) && it->isenter == isenter && it->callback == cb){
//             cout << "Found " << it->libname << " - " << string(libname) << endl;
//             break;
//         }
//     }
// }


#endif

bool init_plugin(void *self) {
#if defined(TARGET_I386)  //&& !defined(TARGET_X86_64)
    panda_require("pri");
    // panda_require("callstack_instr");
    assert(init_callstack_instr_api());
    PPP_REG_CB("pri", on_fn_start, fn_start);
    PPP_REG_CB("pri", on_fn_return, fn_return);
#endif
    return true;
}

void uninit_plugin(void *self) {
    printf("Unloading plugin libfi\n");
}
