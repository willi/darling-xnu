// the operations and struct work_interval_create_params are PRIVATE in sys/work_interval.h
#define PRIVATE 1
#include <darling/emulation/xnu_syscall/bsd/impl/misc/work_interval_ctl.h>

#include <stdbool.h>
#include <sys/errno.h>
#include <sys/work_interval.h>
#include <mach/port.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/common/tsd.h>

// xnu-12377's, newer than this tree's sys/work_interval.h
#define WORK_INTERVAL_OPERATION_SET_NAME 0x0000000a
#define WORK_INTERVAL_OPERATION_SET_WORKLOAD_ID 0x0000000b

// XNU's work_interval_ctl() (bsd/kern/sys_work_interval.c) over kern_work_interval_create(), _destroy(), _notify() and
// _join() (osfmk/kern/work_interval.c), as of xnu-12377. XNU's work intervals are scheduler hints: what a thread is
// working toward and by when, so that the CPU's performance can follow. Linux has nothing to take them, so these are
// the calls' bookkeeping and answers only. UIKit creates a CA_CLIENT interval in the first commit of every event that
// begins a scroll (_UIQOSManagedCommitsBegin) and throws "Failed to create work interval" if the call fails.
//
// Kept here: the work interval the thread is in (its id, in the TSD; 0 for none), and whether this process has
// created its CA_CLIENT interval. XNU keeps the first in the thread and the second in the task (TF_CA_CLIENT_WI), so a
// fork child starts with neither (work_interval_atfork_child) and an exec, with its fresh memory, does too.
//
// Not kept: joinable work intervals, which XNU hands out as a port, a kernel object of its own (libdispatch's
// workgroups ask for those). A joinable create is ENOTSUP; no port is a work interval's, so every operation on one is
// XNU's answer for a port that isn't (EINVAL).

static bool ca_client_created;
static uint64_t last_id; // XNU's unique_work_interval_id; 0 is no interval

static uint64_t thread_interval(void)
{
	return (uint64_t)(uintptr_t)_pthread_getspecific_direct(__PTK_DARLING_WORK_INTERVAL);
}

static void thread_interval_set(uint64_t id)
{
	_pthread_setspecific_direct(__PTK_DARLING_WORK_INTERVAL, (void*)(uintptr_t)id);
}

void work_interval_atfork_child(void)
{
	thread_interval_set(0);
	__atomic_store_n(&ca_client_created, false, __ATOMIC_RELAXED);
}

// kern_work_interval_create()'s checks, in its order, and then the interval
static long create(struct work_interval_create_params* params)
{
	uint32_t flags = params->wicp_create_flags;

	// a non-joinable create also joins the thread to it, so it may not be in one yet
	if (!(flags & WORK_INTERVAL_FLAG_JOINABLE) && thread_interval() != 0)
		return -EALREADY;

	if ((flags & WORK_INTERVAL_TYPE_MASK) == WORK_INTERVAL_TYPE_CA_CLIENT)
	{
		// UIKit's or AppKit's, one per process, and in no thread group of its own
		if (flags & WORK_INTERVAL_FLAG_GROUP)
			return -EALREADY;
		// XNU checks task_is_app() here. A simulator's processes run on macOS's kernel, where one that isn't an app
		// gets a work interval that does nothing (WORK_INTERVAL_FLAG_IGNORED, kept in the kernel's copy of the flags
		// only: the caller's copy is the flags it passed): the same answer to the caller either way.
		// Once marked, a process stays marked: nothing in XNU clears TF_CA_CLIENT_WI, not even DESTROY.
		if (__atomic_exchange_n(&ca_client_created, true, __ATOMIC_RELAXED))
			return -EALREADY;
	}

	// CONFIG_SCHED_AUTO_JOIN's checks: KERN_NOT_SUPPORTED, which work_interval_ctl() answers as EINVAL
	if (flags & WORK_INTERVAL_FLAG_ENABLE_AUTO_JOIN)
	{
		if ((flags & WORK_INTERVAL_TYPE_MASK) != WORK_INTERVAL_TYPE_COREAUDIO || !(flags & WORK_INTERVAL_FLAG_GROUP))
			return -EINVAL;
	}
	if ((flags & WORK_INTERVAL_FLAG_ENABLE_DEFERRED_FINISH) && !(flags & WORK_INTERVAL_FLAG_ENABLE_AUTO_JOIN))
		return -EINVAL;

	// where XNU makes the interval's port
	if (flags & WORK_INTERVAL_FLAG_JOINABLE)
	{
		static bool told;

		if (!__atomic_exchange_n(&told, true, __ATOMIC_RELAXED))
			__simple_printf("work_interval_ctl: joinable work intervals (flags %#x) are not supported: ENOTSUP\n", flags);
		return -ENOTSUP;
	}

	uint64_t id = __atomic_add_fetch(&last_id, 1, __ATOMIC_RELAXED);
	thread_interval_set(id);
	params->wicp_id = id;
	params->wicp_port = MACH_PORT_NULL;
	return 0;
}

VISIBLE // made visible for xtrace
long sys_work_interval_ctl(uint32_t operation, uint64_t work_interval_id, void* arg, size_t len)
{
	switch (operation)
	{
		case WORK_INTERVAL_OPERATION_CREATE:
			return -ENOTSUP;
		case WORK_INTERVAL_OPERATION_CREATE2:
		{
			if (arg == NULL || work_interval_id != 0 || len < sizeof(struct work_interval_create_params))
				return -EINVAL;
			// XNU's PRIV_WORK_INTERVAL check comes next. A Mac grants it to the simulator's processes (SpringBoard
			// and third-party apps have no entitlement for it, and they scroll); Darling has no policy to ask.
			struct work_interval_create_params params = *(struct work_interval_create_params*)arg;
			long ret = create(&params);
			if (ret == 0)
				*(struct work_interval_create_params*)arg = params;
			return ret;
		}
		case WORK_INTERVAL_OPERATION_DESTROY:
			if (arg != NULL || work_interval_id == 0)
				return -EINVAL;
			// the thread's own interval only
			if (thread_interval() != work_interval_id)
				return -EINVAL;
			thread_interval_set(0);
			return 0;
		case WORK_INTERVAL_OPERATION_NOTIFY:
			if (arg == NULL || work_interval_id == 0 || len < sizeof(struct work_interval_notification))
				return -EINVAL;
			// the thread must be in it; XNU also wants its creator to be this process, which a thread's interval
			// here always is (a fork child's thread is in none)
			if (thread_interval() != work_interval_id)
				return -EINVAL;
			return 0;
		case WORK_INTERVAL_OPERATION_JOIN:
			if (arg != NULL)
				return -EINVAL;
			// MACH_PORT_NULL leaves the thread's interval, whatever it is; any other port isn't a work interval's
			if (work_interval_id != MACH_PORT_NULL)
				return -EINVAL;
			thread_interval_set(0);
			return 0;
		case WORK_INTERVAL_OPERATION_GET_FLAGS:
		case WORK_INTERVAL_OPERATION_SET_NAME:
		case WORK_INTERVAL_OPERATION_SET_WORKLOAD_ID:
			// a joinable interval's port only, and there are none
			return -EINVAL;
		default:
			return -ENOTSUP;
	}
}
