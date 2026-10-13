#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/workq_kernreturn.h>

#include <sys/errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/fcntl.h>
#include <stddef.h>
#include <sys/queue.h>
#include <libsimple/lock.h>
#include <pthread/tsd_private.h>

#define __PTHREAD_EXPOSE_INTERNALS__ 1
#include <pthread/priority_private.h>

#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_register.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_create.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/ext/futex.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/machdep/impl/tls.h>
#include <darling/emulation/xnu_syscall/mach/impl/mach_traps.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/linux_premigration/signal/sigexc.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/fcntl.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kqueue.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent64.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_qos.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_id.h>

#include <elfcalls/threads.h>
#include <darlingserver/rpc.h>

// much easier to include than libpthread's `internal.h`
#include <darling/mldr/elfcalls/dthreads.h>

#define WQ_MAX_THREADS	64

#define WQOPS_QUEUE_ADD 1
#define WQOPS_QUEUE_REMOVE 2
#define WQOPS_THREAD_RETURN 4
#define WQOPS_THREAD_SETCONC  8
#define WQOPS_THREAD_KEVENT_RETURN 0x40
#define WQOPS_THREAD_WORKLOOP_RETURN 0x100
#define WQOPS_QUEUE_NEWSPISUPP  0x10
#define WQOPS_QUEUE_REQTHREADS  0x20
#define WQOPS_QUEUE_REQTHREADS2    0x30
#define WQOPS_SET_EVENT_MANAGER_PRIORITY 0x80
#define WQOPS_SETUP_DISPATCH 0x400

// Flags for the newly spawned thread:
// WQ_FLAG_THREAD_NEWSPI
// WQ_FLAG_THREAD_REUSE (0 if thread is newly spawned)
// item is unused in "new SPI"

#define WQ_FLAG_THREAD_PRIO_SCHED    0x00008000
#define WQ_FLAG_THREAD_PRIO_QOS      0x00004000
#define WQ_FLAG_THREAD_PRIO_MASK     0x00000fff

#define WQ_FLAG_THREAD_OVERCOMMIT    0x00010000
#define WQ_FLAG_THREAD_REUSE         0x00020000
#define WQ_FLAG_THREAD_NEWSPI        0x00040000
#define WQ_FLAG_THREAD_KEVENT        0x00080000
#define WQ_FLAG_THREAD_EVENT_MANAGER 0x00100000
#define WQ_FLAG_THREAD_TSD_BASE_SET  0x00200000
#define WQ_FLAG_THREAD_WORKLOOP      0x00400000
#define WQ_FLAG_THREAD_OUTSIDEQOS    0x00800000

#define WORKQ_EXIT_THREAD_NKEVENT (-1)

static int workq_sem = WQ_MAX_THREADS; // max 64 threads in use
static libsimple_lock_t workq_parked_lock = LIBSIMPLE_LOCK_INITIALIZER;
// static int workq_parked_threads = 0; // num spawned, but unused threads
static int workq_parked[WQ_MAX_THREADS];
static int workq_parked_prio[WQ_MAX_THREADS];

TAILQ_HEAD(tailhead, parked_thread) workq_parked_head = TAILQ_HEAD_INITIALIZER(workq_parked_head);

struct parked_thread
{
	int sem, flags;
	// what to wake up with; events are only for workloop servicers
	void* events;
	int nevents;
	TAILQ_ENTRY(parked_thread) entries;
};

static void list_add(struct parked_thread* head, struct parked_thread* item);
static void list_remove(struct parked_thread* head, struct parked_thread* item);

//void* __attribute__((weak)) __attribute__((visibility("default"))) pthread_getspecific(unsigned long key) { return NULL; }
//int __attribute__((weak)) __attribute__((visibility("default"))) pthread_setspecific(unsigned long key, const void* value) { return 1; }

static int priority_to_class(int prio);

static void rpc_guard(int fd) {
	guard_entry_options_t options;
	options.close = __dserver_close_socket;
	guard_table_add(fd, guard_flag_prevent_close | guard_flag_close_on_fork, &options);
};

static void rpc_unguard(int fd) {
	guard_table_remove(fd);
};

static const struct darling_thread_create_callbacks callbacks = {
	.thread_self_trap = &thread_self_trap_impl,
	.thread_set_tsd_base = &sys_thread_set_tsd_base,
	.rpc_guard = rpc_guard,
	.rpc_unguard = rpc_unguard,
};

static int extract_wq_flags(int priority) {
	int flags = 0;
	int qos = _pthread_priority_thread_qos(priority);

	flags = WQ_FLAG_THREAD_NEWSPI | qos | WQ_FLAG_THREAD_PRIO_QOS;

	if (priority & _PTHREAD_PRIORITY_OVERCOMMIT_FLAG) {
		flags |= WQ_FLAG_THREAD_OVERCOMMIT;
	}

	return flags;
};

#ifndef VARIANT_DYLD
// XNU's kevent workqueue (WORKQ_FEATURE_KEVENT), which Apple's libdispatch requires: knotes registered with
// kevent_qos(KEVENT_FLAG_WORKQ) live on a kqueue of their own, and the events they fire are handed to
// workqueue threads instead of being returned to whoever registered them. Here, a single event manager thread
// waits on that kqueue, passes each batch to libdispatch's kevent callback and applies the changes the callback
// returns before it waits again, so no event is delivered twice while libdispatch handles it.
static libsimple_lock_t workq_kevent_lock = LIBSIMPLE_LOCK_INITIALIZER;
static int workq_kevent_kq = -1;
static bool workq_kevent_manager_started = false;
static struct kevent_qos_s workq_kevent_events[WQ_KEVENT_LIST_LEN];

static int workq_kevent_get_kq(void)
{
	libsimple_lock_lock(&workq_kevent_lock);
	if (workq_kevent_kq < 0)
	{
		workq_kevent_kq = sys_kqueue();
		if (workq_kevent_kq >= 0)
			sys_fcntl(workq_kevent_kq, F_SETFD, FD_CLOEXEC);
	}
	libsimple_lock_unlock(&workq_kevent_lock);
	return workq_kevent_kq;
}

// Applies `changelist` to the kevent workqueue. Like XNU, only failed changes (and those with EV_RECEIPT) are
// reported in `eventlist`; if it has no room, the first failure fails the call.
static int workq_kevent_apply(const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents)
{
	struct kevent64_s* changelist64 = NULL;
	struct kevent64_s* eventlist64 = NULL;
	int kq, rv, i;

	kq = workq_kevent_get_kq();
	if (kq < 0)
		return kq;

	if (nchanges > 0)
	{
		changelist64 = (struct kevent64_s*) __builtin_alloca(nchanges * sizeof(struct kevent64_s));
		for (i = 0; i < nchanges; i++)
			kevent_qos_to_64(&changelist[i], &changelist64[i]);
	}
	if (nevents > 0)
		eventlist64 = (struct kevent64_s*) __builtin_alloca(nevents * sizeof(struct kevent64_s));

	rv = sys_kevent64(kq, changelist64, nchanges, eventlist64, nevents, KEVENT_FLAG_ERROR_EVENTS, NULL);

	for (i = 0; i < rv; i++)
		kevent_64_to_qos(&eventlist64[i], &eventlist[i]);
	return rv;
}

// Waits for the next batch of kevents and runs the event manager thread with it.
static void __attribute__((noreturn)) workq_kevent_manager_wait(dthread_t self, int thread_port,
		void* stacklowaddr, int flags)
{
	struct kevent64_s events64[WQ_KEVENT_LIST_LEN];
	int i, n, nevents = 0;

	while (nevents == 0)
	{
		n = sys_kevent64(workq_kevent_kq, NULL, 0, events64, WQ_KEVENT_LIST_LEN, 0, NULL);
		if (n == -EINTR)
			continue;
		if (n < 0)
		{
			__simple_printf("workq: waiting for kevents failed: %d\n", n);
			__simple_abort();
		}

		for (i = 0; i < n; i++)
		{
			// workloops' kqueues fire for their servicers, not for libdispatch's event manager
			if (workloop_is_kq_event(events64[i].filter, events64[i].udata))
				workloop_kq_fired(events64[i].udata);
			else
				kevent_64_to_qos(&events64[i], &workq_kevent_events[nevents++]);
		}
	}

	wqueue_entry_point_asm_jump(self, thread_port, stacklowaddr, workq_kevent_events, flags, nevents);
}

static void workq_kevent_manager_start(void* self, int thread_port, void* stacklowaddr,
		void* item, int flags, int nevents)
{
	sigexc_thread_setup();
	workq_kevent_manager_wait(self, thread_port, stacklowaddr, flags);
}

// WQOPS_THREAD_KEVENT_RETURN: libdispatch has handled a batch and hands back the changes it made while doing so.
static void __attribute__((noreturn)) workq_kevent_manager_return(const struct kevent_qos_s* changelist,
		int nchanges)
{
	dthread_t self = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_PTHREAD_SELF);
	int thread_port = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_MACH_THREAD_SELF);

	if (nchanges > 0)
	{
		// XNU drops errors from these changes as well; the output list only makes sure all of them are applied
		struct kevent_qos_s* errors = (struct kevent_qos_s*) __builtin_alloca(nchanges * sizeof(struct kevent_qos_s));
		workq_kevent_apply(changelist, nchanges, errors, nchanges);
	}

	workq_kevent_manager_wait(self, thread_port, self->stackbottom,
		WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_KEVENT | WQ_FLAG_THREAD_EVENT_MANAGER
		| WQ_FLAG_THREAD_TSD_BASE_SET | WQ_FLAG_THREAD_REUSE);
}

static void workq_kevent_start_manager(void)
{
	bool start_manager;

	libsimple_lock_lock(&workq_kevent_lock);
	start_manager = !workq_kevent_manager_started;
	workq_kevent_manager_started = true;
	libsimple_lock_unlock(&workq_kevent_lock);

	if (start_manager)
	{
		__darling_thread_create(512*1024, pthread_obj_size, workq_kevent_manager_start, 0, NULL,
				WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_KEVENT | WQ_FLAG_THREAD_EVENT_MANAGER, 0,
				&callbacks, NULL);
	}
}

long workq_kevent_register(const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents)
{
	int rv = workq_kevent_apply(changelist, nchanges, eventlist, nevents);

	if (rv < 0)
		return rv;

	workq_kevent_start_manager();
	return rv;
}

int workq_kevent_watch_fd(int fd, uint64_t udata, uint16_t action)
{
	struct kevent_qos_s change = {
		.ident = fd,
		.filter = EVFILT_READ,
		.flags = (action & EV_ADD) ? (EV_ADD | EV_ENABLE | EV_DISPATCH) : action,
		.udata = udata,
	};
	struct kevent_qos_s error;
	int rv = workq_kevent_apply(&change, 1, &error, 1);

	if (rv < 0)
		return rv;
	if (rv > 0 && (error.flags & EV_ERROR) && error.data != 0)
		return -error.data;

	if (action & EV_ADD)
		workq_kevent_start_manager();
	return 0;
}

static int workq_workloop_thread_flags(unsigned long priority)
{
	return extract_wq_flags(priority) | WQ_FLAG_THREAD_KEVENT | WQ_FLAG_THREAD_WORKLOOP;
}

static void workq_workloop_thread_start(void* self, int thread_port, void* stackaddr,
		void* events, int flags, int nevents)
{
	workloop_servicer_started(events, thread_port);
	wqueue_entry_point_wrapper(self, thread_port, stackaddr, events, flags, nevents);
}

void workq_workloop_thread_request(struct kevent_qos_s* events, int nevents, unsigned long priority)
{
	int flags = workq_workloop_thread_flags(priority);
	struct parked_thread* thread;

	// Workloop servicers are not counted against WQ_MAX_THREADS: requesting one must not block.
	libsimple_lock_lock(&workq_parked_lock);

	thread = workq_parked_head.tqh_first;
	if (thread != NULL)
	{
		TAILQ_REMOVE(&workq_parked_head, thread, entries);
		thread->flags = flags;
		thread->events = events;
		thread->nevents = nevents;
		sem_up(&thread->sem);
		libsimple_lock_unlock(&workq_parked_lock);
		return;
	}

	libsimple_lock_unlock(&workq_parked_lock);

	__darling_thread_create(512*1024, pthread_obj_size, workq_workloop_thread_start, 0,
			(uintptr_t) events, flags, nevents, &callbacks, NULL);
}

void workq_workloop_thread_continue(struct kevent_qos_s* events, int nevents, unsigned long priority)
{
	dthread_t self = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_PTHREAD_SELF);
	int thread_port = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_MACH_THREAD_SELF);

	wqueue_entry_point_asm_jump(self, thread_port, self->stackbottom, events,
		workq_workloop_thread_flags(priority) | WQ_FLAG_THREAD_TSD_BASE_SET | WQ_FLAG_THREAD_REUSE, nevents);
}

void workq_kevent_atfork_child(void)
{
	// kqueues and threads do not survive a fork
	workq_kevent_lock = (libsimple_lock_t) LIBSIMPLE_LOCK_INITIALIZER;
	workq_kevent_kq = -1;
	workq_kevent_manager_started = false;
	workloop_atfork_child();
}
#else
long workq_kevent_register(const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents)
{
	return -ENOSYS;
}

void workq_kevent_atfork_child(void)
{
}
#endif

#ifndef VARIANT_DYLD
// Parks the calling workqueue thread until a thread request (or a workloop) needs it, or terminates it if none
// does for a while. `counted` threads were started by WQOPS_QUEUE_REQTHREADS and count against WQ_MAX_THREADS.
static void __attribute__((noreturn)) workq_thread_park(bool counted)
{
	int thread_self, prio;
	struct parked_thread me;
	dthread_t dthread;
	bool terminating = false;

	libsimple_lock_lock(&workq_parked_lock);

	// Semaphore locked state (wait for wakeup)
	me.sem = 0;
	me.events = NULL;
	me.nevents = 0;

	// extract initial flags
	// (in case we only get created and used once and then terminate; `_pthread_wqthread` requires a valid `flags` argument)
	dthread = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_PTHREAD_SELF);
	prio = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_PTHREAD_QOS_CLASS);
	// doesn't extract `WQ_FLAG_THREAD_KEVENT` if we had it set, but that shouldn't matter
	// like i said before, the only case where we actually need these flags to be set here is when the thread is going to die immediately after creation
	me.flags = extract_wq_flags(prio);

	// Enqueue for future WQOPS_QUEUE_REQTHREADS
	TAILQ_INSERT_HEAD(&workq_parked_head, &me, entries);

	// Decrease the amount of running threads
	if (counted)
		sem_up(&workq_sem);

	libsimple_lock_unlock(&workq_parked_lock);

	// Wait until someone calls WQOPS_QUEUE_REQTHREADS
	// and wakes us up
	if (!sem_down(&me.sem, 15))
	{
		// Make sure we haven't just been woken up before locking the queue
		// and remove us from the queue if not.
		libsimple_lock_lock(&workq_parked_lock);
	
		if (me.sem > 0)
		{
			libsimple_lock_unlock(&workq_parked_lock);
			goto wakeup;
		}

		TAILQ_REMOVE(&workq_parked_head, &me, entries);

		libsimple_lock_unlock(&workq_parked_lock);

		terminating = true;

		// resume the thread; it'll call `_pthread_wqthread_exit` and kill itself
		goto resume_thread;
	}

wakeup: // we actually want to go back into the thread to do work
	// __simple_printf("Thread %d woken up, prio=%d\n", thread_self, me.flags & WQ_FLAG_THREAD_PRIOMASK);

resume_thread: // we want the thread to resume, but it might be just to die
	// reset stack and call entry point again with WQ_FLAG_THREAD_REUSE
	thread_self = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_MACH_THREAD_SELF);
	dthread = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_PTHREAD_SELF);

	if (!terminating && (me.flags & WQ_FLAG_THREAD_WORKLOOP))
		workloop_servicer_started(me.events, thread_self);

	wqueue_entry_point_asm_jump(dthread, thread_self, dthread->stackbottom, me.events,
		me.flags | WQ_FLAG_THREAD_REUSE,
		terminating ? WORKQ_EXIT_THREAD_NKEVENT : me.nevents
	);

	__builtin_unreachable();
}

void workq_workloop_thread_park(void)
{
	workq_thread_park(false);
}
#endif

long sys_workq_kernreturn(int options, void* item, int affinity, int prio)
{
#ifndef VARIANT_DYLD
	// __simple_printf("workq_kernreturn: 0x%x, %p, 0x%x, 0x%x\n", options, item, affinity, prio);

	// item is only used with WQOPS_QUEUE_ADD
	switch (options)
	{
		case WQOPS_THREAD_KEVENT_RETURN:
			// only the event manager thread services kevents
			workq_kevent_manager_return(item, affinity);
		case WQOPS_THREAD_WORKLOOP_RETURN:
			workloop_servicer_return(item, affinity);
		case WQOPS_THREAD_RETURN:
			// Signalizes that the thread has completed its job
			// and can be either recycled or terminated
			workq_thread_park(true);
		case WQOPS_SET_EVENT_MANAGER_PRIORITY:
		case WQOPS_QUEUE_NEWSPISUPP:
			return 0;
		case WQOPS_QUEUE_REQTHREADS2: // with prop bucket
		case WQOPS_QUEUE_REQTHREADS:
		{
			// affinity contains thread count

			int i, flags = extract_wq_flags(prio);

			// __simple_printf("Thread requested with prio %d\n", prio & WQ_FLAG_THREAD_PRIOMASK);

			for (i = 0; i < affinity; i++)
			{
				// Increase the amount of running threads
				sem_down(&workq_sem, -1);

				libsimple_lock_lock(&workq_parked_lock);

				if (workq_parked_head.tqh_first != NULL)
				{
					struct parked_thread* thread;

					thread = workq_parked_head.tqh_first;

					// Resume an existing thread
					// __simple_printf("Resuming thread %d\n", id);

					thread->flags = flags;
					thread->events = NULL;
					thread->nevents = 0;

					// Dequeue
					TAILQ_REMOVE(&workq_parked_head, thread, entries);

					// Resume the thread
					sem_up(&thread->sem);
					libsimple_lock_unlock(&workq_parked_lock);

					continue;
				}

				libsimple_lock_unlock(&workq_parked_lock);

				// __simple_printf("Spawning a new thread\n");
				__darling_thread_create(512*1024, pthread_obj_size, wqueue_entry_point_wrapper, 0,
						NULL, flags, 0, &callbacks, NULL);

				/*if (ret < 0)
				{
					__simple_printf("Failed to spawn a new thread, err %d\n", -ret);
					return ret;
				}*/
			}
			return 0;
		}
		case WQOPS_SETUP_DISPATCH: {
			// TODO: actually do something with the info passed in
			// XNU just tacks it onto the process its called for and uses it later when someone asks for it

			/*
			struct workq_dispatch_config cfg = {0};

			// `affinity` contains the size of the config structure passed in
			memcpy(&cfg, item, (affinity < sizeof(struct workq_dispatch_config)) ? affinity : sizeof(struct workq_dispatch_config));
			*/

			return 0;
		} break;
		default:
			return -ENOTSUP;
	}
#else
	return -ENOSYS;
#endif
}

int sem_down(int* sem, int timeout)
{
	int result;
	struct timespec ts = { timeout, 0 };

try_again:
	result = __sync_add_and_fetch(sem, -1);
	if (result < 0)
	{
		*sem = -1;
		result = __linux_futex(sem, FUTEX_WAIT, -1, (timeout != -1) ? &ts : NULL, 0, 0);

		if (result == -1)
			return 0;

		goto try_again;
	}

	return 1;
}

void sem_up(int* sem)
{
	int result;
	result = __sync_add_and_fetch(sem, 1);
	if (result == 0)
	{
		*sem = 1;
		__linux_futex(sem, FUTEX_WAKE, 1, NULL, 0, 0);
	}
}

#define __PTHREAD_PRIORITY_CBIT_USER_INTERACTIVE 0x20
#define __PTHREAD_PRIORITY_CBIT_USER_INITIATED 0x10
#define __PTHREAD_PRIORITY_CBIT_DEFAULT 0x8
#define __PTHREAD_PRIORITY_CBIT_UTILITY 0x4
#define __PTHREAD_PRIORITY_CBIT_BACKGROUND 0x2
#define __PTHREAD_PRIORITY_CBIT_MAINTENANCE 0x1
#define __PTHREAD_PRIORITY_CBIT_UNSPECIFIED 0x0

#define QOS_CLASS_USER_INTERACTIVE 0x21
#define QOS_CLASS_USER_INITIATED 0x19
#define QOS_CLASS_DEFAULT 0x15
#define QOS_CLASS_UTILITY 0x11
#define QOS_CLASS_BACKGROUND 0x09
#define QOS_CLASS_MAINTENANCE 0x05
#define QOS_CLASS_UNSPECIFIED 0x0

static int priority_to_class(int prio)
{
	int dec_prio = (prio & 0xff00) >> 8;
	switch (dec_prio)
	{
		case __PTHREAD_PRIORITY_CBIT_USER_INTERACTIVE:
			return __PTHREAD_PRIORITY_CBIT_MAINTENANCE;
		case __PTHREAD_PRIORITY_CBIT_USER_INITIATED:
			return QOS_CLASS_USER_INITIATED;
		case __PTHREAD_PRIORITY_CBIT_DEFAULT:
			return QOS_CLASS_DEFAULT;
		case __PTHREAD_PRIORITY_CBIT_UTILITY:
			return QOS_CLASS_UTILITY;
		case __PTHREAD_PRIORITY_CBIT_BACKGROUND:
			return QOS_CLASS_BACKGROUND;
		case __PTHREAD_PRIORITY_CBIT_MAINTENANCE:
			return QOS_CLASS_MAINTENANCE;
		default:
			return QOS_CLASS_UNSPECIFIED;
	}
}
