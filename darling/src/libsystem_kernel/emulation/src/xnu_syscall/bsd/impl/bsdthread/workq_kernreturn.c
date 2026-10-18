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
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/ext/futex.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/machdep/impl/tls.h>
#include <darling/emulation/xnu_syscall/mach/impl/mach_traps.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/linux_premigration/signal/sigexc.h>

#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_workq.h>
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

#ifndef WQ_FLAG_THREAD_COOPERATIVE
#define WQ_FLAG_THREAD_COOPERATIVE 0x01000000 /* thread is part of cooperative thread pool */
#endif

static int workq_sem = WQ_MAX_THREADS; // max 64 threads in use
static libsimple_lock_t workq_parked_lock = LIBSIMPLE_LOCK_INITIALIZER;
// static int workq_parked_threads = 0; // num spawned, but unused threads
static int workq_parked[WQ_MAX_THREADS];
static int workq_parked_prio[WQ_MAX_THREADS];

TAILQ_HEAD(tailhead, parked_thread) workq_parked_head = TAILQ_HEAD_INITIALIZER(workq_parked_head);

struct parked_thread
{
	int sem;
	// what the thread is woken up for: a WQOPS_QUEUE_REQTHREADS request with `flags`,
	// or a workq_thread_request() if `prepare` is set
	int flags;
	workq_prepare_f prepare;
	void* context;
	TAILQ_ENTRY(parked_thread) entries;
};

// a workq_thread_request() answered by a new thread
struct workq_request
{
	workq_prepare_f prepare;
	void* context;
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
	.signal_stack_setup = sigexc_thread_setup,
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
extern void* calloc(__SIZE_TYPE__ count, __SIZE_TYPE__ size);
extern void free(void* ptr);

int workq_thread_flags(unsigned long priority)
{
	return extract_wq_flags(priority);
}

void workq_thread_enter(const struct workq_batch* batch)
{
	dthread_t self = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_PTHREAD_SELF);
	int thread_port = _pthread_getspecific_direct(_PTHREAD_TSD_SLOT_MACH_THREAD_SELF);

	wqueue_entry_point_asm_jump(self, thread_port, self->stackbottom, batch->events,
		batch->flags | WQ_FLAG_THREAD_REUSE | WQ_FLAG_THREAD_TSD_BASE_SET, batch->nevents);
}

static void workq_requested_thread_start(void* self, int thread_port, void* stacklowaddr,
		void* item, int flags, int nevents)
{
	struct workq_request request = *(struct workq_request*) item;
	struct workq_batch batch;

	free(item);

	// with nothing to do, the thread enters _start_wqthread just to terminate
	if (!request.prepare(request.context, &batch))
		batch = (struct workq_batch) { .events = NULL, .nevents = WORKQ_EXIT_THREAD_NKEVENT, .flags = flags };

	// the thread's TSD base is already set, as `flags` says
	wqueue_entry_point_asm_jump(self, thread_port, stacklowaddr, batch.events,
		batch.flags | (flags & WQ_FLAG_THREAD_TSD_BASE_SET), batch.nevents);
}

void workq_thread_request(workq_prepare_f prepare, void* context)
{
	struct parked_thread* thread;
	struct workq_request* request;

	libsimple_lock_lock(&workq_parked_lock);

	thread = workq_parked_head.tqh_first;
	if (thread != NULL)
	{
		TAILQ_REMOVE(&workq_parked_head, thread, entries);
		thread->prepare = prepare;
		thread->context = context;
		sem_up(&thread->sem);
		libsimple_lock_unlock(&workq_parked_lock);
		return;
	}

	libsimple_lock_unlock(&workq_parked_lock);

	request = calloc(1, sizeof(*request));
	if (request == NULL)
	{
		__simple_printf("workq: out of memory for a thread request\n");
		__simple_abort();
	}
	request->prepare = prepare;
	request->context = context;

	if (__darling_thread_create(512*1024, pthread_obj_size, workq_requested_thread_start, 0, (uintptr_t) request,
			extract_wq_flags(_pthread_priority_make_from_thread_qos(THREAD_QOS_DEFAULT, 0, 0)), 0, &callbacks, NULL) == NULL)
	{
		// lost, as a REQTHREADS request below is
		__simple_printf("workq: couldn't start a thread for a request\n");
		free(request);
	}
}

// Parks the calling workqueue thread until a request needs it, or terminates it if none does for a while.
// `counted` threads came from WQOPS_QUEUE_REQTHREADS and count against WQ_MAX_THREADS until they park.
static void __attribute__((noreturn)) workq_thread_park(bool counted)
{
	struct parked_thread me;
	struct workq_batch batch;

park:
	libsimple_lock_lock(&workq_parked_lock);

	// Semaphore locked state (wait for wakeup)
	me.sem = 0;
	me.prepare = NULL;
	me.context = NULL;

	// `_start_wqthread` requires valid flags even when the thread is only resumed to terminate
	me.flags = extract_wq_flags(_pthread_getspecific_direct(_PTHREAD_TSD_SLOT_PTHREAD_QOS_CLASS));

	// Enqueue for future requests
	TAILQ_INSERT_HEAD(&workq_parked_head, &me, entries);

	// Decrease the amount of running threads
	if (counted)
		sem_up(&workq_sem);
	counted = false;

	libsimple_lock_unlock(&workq_parked_lock);

	// Wait until a request wakes us up
	if (!sem_down(&me.sem, 15))
	{
		// Make sure we haven't just been woken up before locking the queue
		// and remove us from the queue if not.
		libsimple_lock_lock(&workq_parked_lock);

		if (me.sem > 0)
		{
			libsimple_lock_unlock(&workq_parked_lock);
			goto woken;
		}

		TAILQ_REMOVE(&workq_parked_head, &me, entries);

		libsimple_lock_unlock(&workq_parked_lock);

		// resume the thread; it'll call `_pthread_wqthread_exit` and kill itself
		batch = (struct workq_batch) { .events = NULL, .nevents = WORKQ_EXIT_THREAD_NKEVENT, .flags = me.flags };
		workq_thread_enter(&batch);
	}

woken:
	// Whoever woke us up has unlinked `me` and is done with it, so the stack it lives on may be reused.
	if (me.prepare == NULL)
		batch = (struct workq_batch) { .events = NULL, .nevents = 0, .flags = me.flags };
	else if (!me.prepare(me.context, &batch))
		goto park;

	workq_thread_enter(&batch);
}

void workq_thread_return(void)
{
	workq_thread_park(false);
}

void workq_atfork_child(void)
{
	// none of the parent's threads exist in the child
	workq_parked_lock = (libsimple_lock_t) LIBSIMPLE_LOCK_INITIALIZER;
	TAILQ_INIT(&workq_parked_head);
	workq_sem = WQ_MAX_THREADS;
}
#else
void workq_atfork_child(void)
{
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
			// only the event manager thread services the kevent workqueue
			workq_kevent_manager_return(item, affinity);
		case WQOPS_THREAD_WORKLOOP_RETURN:
			// the workloop is the one the thread is bound to, whatever `item` points to
			workloop_servicer_return(item, affinity);
		case WQOPS_THREAD_RETURN:
			// Signalizes that the thread has completed its job
			// and can be either recycled or terminated
			workq_thread_park(true);
		case WQOPS_SET_EVENT_MANAGER_PRIORITY:
		case WQOPS_QUEUE_NEWSPISUPP:
			return 0;
		case WQOPS_QUEUE_REQTHREADS2: // for the cooperative pool
		case WQOPS_QUEUE_REQTHREADS:
		{
			// affinity contains thread count

			int i, flags = extract_wq_flags(prio);

			// as XNU's workq_reqthreads(): REQTHREADS2 asks for threads of libdispatch's cooperative pool (Swift
			// concurrency's executor), which libpthread tells libdispatch so it drains that pool's root queue
			if (options == WQOPS_QUEUE_REQTHREADS2)
				flags = (flags & ~WQ_FLAG_THREAD_OVERCOMMIT) | WQ_FLAG_THREAD_COOPERATIVE;

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
					thread->prepare = NULL;
					thread->context = NULL;

					// Dequeue
					TAILQ_REMOVE(&workq_parked_head, thread, entries);

					// Resume the thread
					sem_up(&thread->sem);
					libsimple_lock_unlock(&workq_parked_lock);

					continue;
				}

				libsimple_lock_unlock(&workq_parked_lock);

				// __simple_printf("Spawning a new thread\n");
				if (__darling_thread_create(512*1024, pthread_obj_size, wqueue_entry_point_wrapper, 0,
						NULL, flags, 0, &callbacks, NULL) == NULL)
				{
					// XNU keeps such a request queued and retries (workq_schedule_delayed_thread_creation() in
					// bsd/pthread/pthread_workqueue.c); here it's lost, but its running-thread slot comes back
					__simple_printf("workq: couldn't start a thread\n");
					sem_up(&workq_sem);
				}
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

// A counting semaphore on a futex: `*sem` is the count, never below 0. Takes one, waiting up to `timeout` seconds for it
// (-1: for ever); answers 0 when it timed out.
//
// It was the count gone negative for waiters, and the waiter stored -1 over it before its futex wait: a sem_up() between
// the decrement and that store was lost, so a parked thread woken for a request timed out instead, removed itself from
// the parked list a second time (its waker had already) and left the list pointing into its stack; when the thread was
// gone, the next park wrote into the dead stack (runningboardd segfaulted in workq_thread_park), and the request it was
// woken for was dropped. Any futex error also counted as a timeout, a signal or a changed value among them.
int sem_down(int* sem, int timeout)
{
	struct timespec ts = { timeout, 0 };

	for (;;)
	{
		int count = __atomic_load_n(sem, __ATOMIC_ACQUIRE);
		if (count > 0)
		{
			if (__atomic_compare_exchange_n(sem, &count, count - 1, false, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
				return 1;
			continue;
		}

		// a signal or a sem_up() before the wait (the count is not 0 any more) ends it early: look again
		int result = LINUX_SYSCALL(__NR_futex, sem, FUTEX_WAIT, 0, (timeout != -1) ? &ts : NULL, NULL, 0);
		if (result == -LINUX_ETIMEDOUT)
			return 0;
	}
}

void sem_up(int* sem)
{
	__atomic_add_fetch(sem, 1, __ATOMIC_RELEASE);
	LINUX_SYSCALL(__NR_futex, sem, FUTEX_WAKE, 1, NULL, NULL, 0);
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
