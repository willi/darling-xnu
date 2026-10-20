#ifndef LINUX_SETPRIORITY_H
#define LINUX_SETPRIORITY_H

#include <darling/emulation/conversion/process/priority.h>

long sys_setpriority(int which, int who, int prio);

#endif // LINUX_SETPRIORITY_H
