#ifndef WORKQ_KERNRETURN_H
#define WORKQ_KERNRETURN_H

#include <stdint.h>

#define PRIVATE 1
#include <sys/event.h>

// what XNU hands a kevent workqueue thread at most at once
#define WQ_KEVENT_LIST_LEN 16

struct timespec;

long sys_workq_kernreturn(int options, void* item, int affinity, int prio);

// kevent_qos(KEVENT_FLAG_WORKQ): changes to the process's kevent workqueue
long workq_kevent_register(const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents);
// the child of a fork has no kevent workqueue
void workq_kevent_atfork_child(void);

// For workloops (kevent_id.c): watch `fd` for readability on the kevent workqueue, reporting events with `udata`.
// `action` is EV_ADD, EV_ENABLE or EV_DELETE; additions are EV_DISPATCH.
int workq_kevent_watch_fd(int fd, uint64_t udata, uint16_t action);
// Starts a workqueue thread servicing a workloop with `events`, which must be preceded by the workloop's id.
void workq_workloop_thread_request(struct kevent_qos_s* events, int nevents, unsigned long priority);
// Re-enters the calling servicer thread with another batch of `events`.
void __attribute__((noreturn)) workq_workloop_thread_continue(struct kevent_qos_s* events, int nevents,
		unsigned long priority);
// Parks the calling servicer thread once it has no workloop to service.
void __attribute__((noreturn)) workq_workloop_thread_park(void);

int sem_down(int* sem, int timeout);
void sem_up(int* sem);

#endif // WORKQ_KERNRETURN_H
