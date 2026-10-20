#ifndef _DARLING_EMULATION_HOST_BASIC_INFO_H_
#define _DARLING_EMULATION_HOST_BASIC_INFO_H_

#include <stdbool.h>
#include <mach/host_info.h>

// darlingserver's HOST_BASIC_INFO, the one source of the CPU counts and memory size that hw.* sysctls,
// pthread_qos_max_parallelism() and the workqueue read. Fills `out` and returns true; false if the query failed
// (`out` is then zeroed, and the next call asks again). The first answer is kept for the process's life.
bool host_basic_info_get(struct host_basic_info* out);

// XNU's sched_qos_max_parallelism (osfmk/kern/sched_prim.c), the scheduler's half of
// BSDTHREAD_CTL_QOS_MAX_PARALLELISM: the logical CPU count with _PTHREAD_QOS_PARALLELISM_COUNT_LOGICAL (0x1) in
// `flags`, else the physical one. Every QoS gets the same count, as without AMP. 0 if unknown.
int qos_max_parallelism(int qos, unsigned long flags);

#endif // _DARLING_EMULATION_HOST_BASIC_INFO_H_
