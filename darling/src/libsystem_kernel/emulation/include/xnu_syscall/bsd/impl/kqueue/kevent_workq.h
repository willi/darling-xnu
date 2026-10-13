#ifndef LINUX_KEVENT_WORKQ_H
#define LINUX_KEVENT_WORKQ_H

#define PRIVATE 1
#include <sys/event.h>

// XNU's kevent workqueue: the kqueue behind kevent_qos(KEVENT_FLAG_WORKQ).

// kevent_qos(KEVENT_FLAG_WORKQ)
long workq_kevent_register(const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents);

// WQOPS_THREAD_KEVENT_RETURN, from the event manager thread
void __attribute__((noreturn)) workq_kevent_manager_return(const struct kevent_qos_s* changelist, int nchanges);

// The child of a fork has none of the parent's threads, nor its kqueues.
void workq_kevent_atfork_child(void);

#endif // LINUX_KEVENT_WORKQ_H
