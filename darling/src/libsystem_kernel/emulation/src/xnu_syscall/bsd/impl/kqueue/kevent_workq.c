#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_workq.h>

#include <stdbool.h>
#include <stdint.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/poll.h>
#include <libsimple/lock.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/workq_kernreturn.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/fcntl.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_deferdelete.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kqueue.h>
#include <darling/emulation/xnu_syscall/bsd/impl/select/poll.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>

#ifndef VARIANT_DYLD
// XNU's kevent workqueue (WORKQ_FEATURE_KEVENT), which Apple's libdispatch requires: knotes registered with
// kevent_qos(KEVENT_FLAG_WORKQ) live on a kqueue of their own, and the events they fire are handed to workqueue
// threads instead of being returned to whoever registered them. Here, a single event manager thread waits on that
// kqueue, passes each batch to libdispatch's kevent callback and applies the changes the callback returns before
// it waits again, so no event is delivered twice while libdispatch handles it.
//
// Changes are applied and events collected under one lock, which deferred deletes require (kevent_deferdelete.h).
// So the manager waits for the kqueue to become readable without holding the lock, then collects without blocking.

#define LINUX_EFD_NONBLOCK 04000
#define LINUX_EFD_CLOEXEC 02000000

#define MANAGER_FLAGS (WQ_FLAG_THREAD_NEWSPI | WQ_FLAG_THREAD_KEVENT | WQ_FLAG_THREAD_EVENT_MANAGER)

static libsimple_lock_t kqworkq_lock = LIBSIMPLE_LOCK_INITIALIZER;
static int kqworkq_kq = -1;
static struct kevent_deferdelete kqworkq_dd;
// an eventfd that wakes the manager up when the next batch has events the kqueue doesn't report
static int kqworkq_wakefd = -1;
static bool kqworkq_manager_started = false;

// the batch the event manager thread is handed
static struct kevent_qos_s manager_events[WQ_KEVENT_LIST_LEN];

static int kqworkq_setup(void)
{
	int kq, wakefd;

	if (kqworkq_kq >= 0)
		return 0;

	kq = sys_kqueue();
	if (kq < 0)
		return kq;
	sys_fcntl(kq, F_SETFD, FD_CLOEXEC);

	wakefd = LINUX_SYSCALL(__NR_eventfd2, 0, LINUX_EFD_NONBLOCK | LINUX_EFD_CLOEXEC);
	if (wakefd < 0)
	{
		sys_close(kq);
		return errno_linux_to_bsd(wakefd);
	}

	kqworkq_kq = kq;
	kqworkq_wakefd = wakefd;
	return 0;
}

static void kqworkq_wake_manager(void)
{
	uint64_t one = 1;

	LINUX_SYSCALL3(__NR_write, kqworkq_wakefd, &one, sizeof(one));
}

// Applies `changelist` like XNU's kevent_register() loop: failed changes, and those with EV_RECEIPT, are reported
// in `errors`. Once `errors` is full, a failure ends the call with that error if `strict`; otherwise the remaining
// changes are applied and their errors dropped. `errors` may be `changelist`.
static int kqworkq_apply(const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* errors, int nerrors, bool strict)
{
	int i, n = 0;

	for (i = 0; i < nchanges; i++)
	{
		struct kevent_qos_s kev = changelist[i];
		int error = kevent_dd_register(&kqworkq_dd, kqworkq_kq, &kev);

		if (error == 0 && !(kev.flags & EV_RECEIPT))
			continue;

		kev.flags |= EV_ERROR;
		kev.data = error;
		if (n < nerrors)
			errors[n++] = kev;
		else if (error != 0 && strict)
		{
			n = -error;
			break;
		}
	}

	// a re-enabled deferred delete has an event for the manager
	if (kevent_dd_pending(&kqworkq_dd))
		kqworkq_wake_manager();

	return n;
}

// Blocks the event manager thread until the kevent workqueue has events, and makes them its next batch.
static void kqworkq_manager_wait(struct workq_batch* batch)
{
	struct pollfd fds[2];
	uint64_t count;
	int n, rv;

	for (;;)
	{
		libsimple_lock_lock(&kqworkq_lock);
		n = kevent_dd_collect(&kqworkq_dd, kqworkq_kq, manager_events, WQ_KEVENT_LIST_LEN);
		libsimple_lock_unlock(&kqworkq_lock);

		if (n > 0)
			break;
		if (n < 0 && n != -EINTR)
		{
			__simple_printf("workq: collecting kevents failed: %d\n", n);
			__simple_abort();
		}

		fds[0] = (struct pollfd) { .fd = kqworkq_kq, .events = POLLIN };
		fds[1] = (struct pollfd) { .fd = kqworkq_wakefd, .events = POLLIN };
		rv = sys_poll_nocancel(fds, 2, -1);
		if (rv < 0 && rv != -EINTR)
		{
			__simple_printf("workq: waiting for kevents failed: %d\n", rv);
			__simple_abort();
		}
		if (rv > 0 && (fds[1].revents & POLLIN))
			LINUX_SYSCALL3(__NR_read, kqworkq_wakefd, &count, sizeof(count));
	}

	*batch = (struct workq_batch) { .events = manager_events, .nevents = n, .flags = MANAGER_FLAGS };
}

// the manager answers its thread request with the first batch, however long that takes
static bool kqworkq_manager_prepare(void* context, struct workq_batch* batch)
{
	kqworkq_manager_wait(batch);
	return true;
}

long workq_kevent_register(const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents)
{
	bool start_manager = false;
	int rv;

	if (nchanges < 0 || nevents < 0)
		return -EINVAL;

	libsimple_lock_lock(&kqworkq_lock);

	rv = kqworkq_setup();
	if (rv == 0)
	{
		rv = kqworkq_apply(changelist, nchanges, eventlist, (eventlist != NULL) ? nevents : 0, true);
		start_manager = !kqworkq_manager_started;
		kqworkq_manager_started = true;
	}

	libsimple_lock_unlock(&kqworkq_lock);

	if (start_manager)
		workq_thread_request(kqworkq_manager_prepare, NULL);

	return rv;
}

void workq_kevent_manager_return(const struct kevent_qos_s* changelist, int nchanges)
{
	struct workq_batch batch;
	int n = 0;

	// As on XNU's parking path, changes that fail are the manager's next batch, ahead of any event: libdispatch
	// handles them like any failed registration, which includes crashing on those it can't recover from.
	if (nchanges > 0)
	{
		libsimple_lock_lock(&kqworkq_lock);
		n = kqworkq_apply(changelist, nchanges, manager_events, WQ_KEVENT_LIST_LEN, false);
		libsimple_lock_unlock(&kqworkq_lock);
	}

	if (n > 0)
		batch = (struct workq_batch) { .events = manager_events, .nevents = n, .flags = MANAGER_FLAGS };
	else
		kqworkq_manager_wait(&batch);

	workq_thread_enter(&batch);
}

void workq_kevent_atfork_child(void)
{
	// The child has none of the parent's threads, and libkqueue closes the parent's kqueues in it. What tracked
	// them is leaked rather than freed: this runs before libSystem makes malloc usable again in the child.
	kqworkq_lock = (libsimple_lock_t) LIBSIMPLE_LOCK_INITIALIZER;
	if (kqworkq_wakefd >= 0)
		LINUX_SYSCALL1(__NR_close, kqworkq_wakefd);
	kqworkq_wakefd = -1;
	kqworkq_kq = -1;
	kqworkq_dd = (struct kevent_deferdelete) {};
	kqworkq_manager_started = false;
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
