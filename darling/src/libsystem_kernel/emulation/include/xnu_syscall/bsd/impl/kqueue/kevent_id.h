#ifndef LINUX_KEVENT_ID_H
#define LINUX_KEVENT_ID_H

#include <stdbool.h>
#include <stdint.h>

#define PRIVATE 1
#include <sys/event.h>

long sys_kevent_id(uint64_t id, const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents,
		void* data_out, unsigned long* data_available, unsigned int flags);

// Hooks for the workqueue threads that service workloops (workq_kernreturn.c).

// Whether an event from the kevent workqueue is the kqueue of a workloop becoming readable.
bool workloop_is_kq_event(int16_t filter, uint64_t udata);
void workloop_kq_fired(uint64_t udata);
// Runs on a servicer thread before it enters libdispatch with `events`.
void workloop_servicer_started(void* events, int thread_port);
// WQOPS_THREAD_WORKLOOP_RETURN
void __attribute__((noreturn)) workloop_servicer_return(const struct kevent_qos_s* changelist, int nchanges);
void workloop_atfork_child(void);

#endif // LINUX_KEVENT_ID_H
