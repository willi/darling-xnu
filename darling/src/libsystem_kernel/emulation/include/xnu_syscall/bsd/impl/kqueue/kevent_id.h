#ifndef LINUX_KEVENT_ID_H
#define LINUX_KEVENT_ID_H

#include <stdint.h>

#define PRIVATE 1
#include <sys/event.h>

long sys_kevent_id(uint64_t id, const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents,
		void* data_out, unsigned long* data_available, unsigned int flags);

long sys_kqueue_workloop_ctl(uint64_t cmd, uint64_t options, const void* addr, unsigned long sz);

// WQOPS_THREAD_WORKLOOP_RETURN, from the thread servicing a workloop
void __attribute__((noreturn)) workloop_servicer_return(const struct kevent_qos_s* changelist, int nchanges);

// The child of a fork has none of the parent's threads, nor its kqueues.
void workloop_atfork_child(void);

#endif // LINUX_KEVENT_ID_H
