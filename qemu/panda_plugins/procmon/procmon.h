
#ifndef __PROCMON_H_
#define __PROCMON_H_



typedef void (* new_process_notify_t)(CPUState *env, unsigned int pid, char* proc_name);
typedef void (* removed_process_notify_t)(CPUState *env, unsigned int pid, char* proc_name);
typedef void (* new_module_notify_t)(CPUState *env, char* proc_name, unsigned int pid, char* mod_name, char* mod_filename, target_ulong size, target_ulong base);
typedef void (* removed_module_notify_t)(CPUState *env, char* proc_name, unsigned int pid, char* mod_name, char* mod_filename, target_ulong size, target_ulong base);
typedef void (* new_main_module_notify_t)(CPUState *env, char* proc_name, unsigned int pid, char* mod_name, char* mod_filename, target_ulong size, target_ulong base);
typedef void (* removed_main_module_notify_t)(CPUState *env, char* proc_name, unsigned int pid, char* mod_name, char* mod_filename, target_ulong size, target_ulong base);



#endif