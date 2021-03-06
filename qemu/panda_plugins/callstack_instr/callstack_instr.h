#ifndef __CALLSTACK_INSTR_H
#define __CALLSTACK_INSTR_H

typedef void (* on_call_t)(CPUState *env, target_ulong func);
typedef void (* on_call_2_t)(CPUState *env, target_ulong func);
typedef void (* on_call_3_t)(CPUState *env, target_ulong destination_address, target_ulong return_address);
typedef void (* on_ret_t)(CPUState *env, target_ulong func);

#endif
