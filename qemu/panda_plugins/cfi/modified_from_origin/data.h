/// primary structure for DECAF plugin,
// callbacks have been removed due to the new interface
// including callbacks and states
// tainting has also been removed since we are going to
// have a new tainting interface that is dynamically
// controllable - which will be more like a util than
// something that is built directly into DECAF

#ifndef DATA_H_
#define DATA_H_

#include "monitor.h"
#include "qdict.h"
#include "cpu.h"
// #if defined(TARGET_I386) && !defined(TARGET_X86_64)
// typedef int (*hook_proc_t)(void *opaque);

//TODO Remove it
// typedef uintptr_t DECAF_Handle;

//TODO anonymize it
typedef enum {
        DECAF_BLOCK_BEGIN_CB = 0,
        DECAF_BLOCK_END_CB,
        DECAF_INSN_BEGIN_CB,
        DECAF_INSN_END_CB,
        DECAF_MEM_READ_CB,
        DECAF_MEM_WRITE_CB,
        DECAF_EIP_CHECK_CB,
        DECAF_KEYSTROKE_CB,//keystroke event
        DECAF_NIC_REC_CB,
        DECAF_NIC_SEND_CB,
        DECAF_OPCODE_RANGE_CB,
        DECAF_TLB_EXEC_CB,
        DECAF_READ_TAINTMEM_CB,
        DECAF_WRITE_TAINTMEM_CB,
#ifdef CONFIG_TCG_LLVM
	DECAF_BLOCK_TRANS_CB,
#endif /* CONFIG_TCG_LLVM */
        DECAF_LAST_CB, //place holder for the last position, no other uses.
} DECAF_callback_type_t;

typedef struct _tmodinfo
{
  char      name[512]; ///< module name
  uint32_t  base;  ///< module base address
  uint32_t  size;  ///< module size
}tmodinfo_t;

typedef struct mon_cmd_t {
    const char *name;
    const char *args_type;
    const char *params;
    const char *help;
    void (*user_print)(Monitor *mon, const QObject *data);
    union {
        void (*info)(Monitor *mon);
        void (*cmd)(Monitor *mon, const QDict *qdict);
        int  (*cmd_new)(Monitor *mon, const QDict *params, QObject **ret_data);
        int  (*cmd_async)(Monitor *mon, const QDict *params,
                          MonitorCompletion *cb, void *opaque);
    } mhandler;
    bool qapi;
    int flags;
} mon_cmd_t;

typedef struct _plugin_interface {
  /// array of monitor commands
  const mon_cmd_t *mon_cmds; // AWH - was term_cmd_t *term_cmds
  /// array of informational commands
  const mon_cmd_t *info_cmds; // AWH - was term_cmd_t
  /*!
   * \brief callback for cleaning up states in plugin.
   * TEMU plugin must release all allocated resources in this function
   */
  void (*plugin_cleanup)(void);

  //TODO: may need to remove it.
  //void (*send_keystroke) (int reg);

  //TODO: need to change it into using our generic callback interface
  // void (*after_loadvm) (const char *param); #######################

  /// \brief CR3 of a specified process to be monitored.
  /// 0 means system-wide monitoring, including all processes and kernel.
  union
  {
    uint32_t monitored_cr3;
    uint32_t monitored_pgd; //alias
  };
} plugin_interface_t;
// #endif
// #if defined(TARGET_I386) && !defined(TARGET_X86_64)
#ifndef TARGET_ARM

static inline int QEMU_is_in_kernel()
{
  CPUState *env = cpu_single_env ? cpu_single_env : first_cpu;
  return ((env->hflags & HF_CPL_MASK) == 0);
}
#endif

#endif