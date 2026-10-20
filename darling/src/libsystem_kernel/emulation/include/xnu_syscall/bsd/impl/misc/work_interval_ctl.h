#ifndef LINUX_WORK_INTERVAL_CTL_H
#define LINUX_WORK_INTERVAL_CTL_H

#include <stddef.h>
#include <stdint.h>

long sys_work_interval_ctl(uint32_t operation, uint64_t work_interval_id, void* arg, size_t len);

// in a fork child, before any signal handler: the child's one thread is in no work interval, and the child has not
// created a CA_CLIENT one (XNU's are the task's and the thread's, which a fork child gets new)
void work_interval_atfork_child(void);

#endif // LINUX_WORK_INTERVAL_CTL_H
