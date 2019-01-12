//
// Created by giuseppe on 12/3/18.
//

#ifndef QEMU_PROCMON_INT_FNS_H
#define QEMU_PROCMON_INT_FNS_H

void update_lists(CPUState *env);

void update_module(CPUState *env, target_ulong pid);

#endif //QEMU_PROCMON_INT_FNS_H
