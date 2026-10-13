#ifndef WORKQ_KERNRETURN_H
#define WORKQ_KERNRETURN_H

#define PRIVATE 1
#include <sys/event.h>

struct timespec;

long sys_workq_kernreturn(int options, void* item, int affinity, int prio);

// kevent_qos(KEVENT_FLAG_WORKQ): changes to the process's kevent workqueue
long workq_kevent_register(const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents);
// the child of a fork has no kevent workqueue
void workq_kevent_atfork_child(void);

int sem_down(int* sem, int timeout);
void sem_up(int* sem);

#endif // WORKQ_KERNRETURN_H
