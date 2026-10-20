// THREAD_QOS_* are PRIVATE in mach/thread_policy.h
#define PRIVATE 1
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/qos_sched.h>

#include <stdint.h>
#include <mach/thread_policy.h>
#include <pthread/tsd_private.h>

#include <darling/emulation/common/tsd.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/workq_kernreturn.h>

#define LINUX_PRIO_PROCESS 0 // with who = 0: the calling thread, as Linux keeps nice per thread
#define LINUX_NICE_MAX 19

// The process's nice, which every QoS offset is added to.
static int base_nice;

static int qos_nice_offset(unsigned int qos)
{
	switch (qos)
	{
		case THREAD_QOS_UTILITY:
			return 10;
		case THREAD_QOS_BACKGROUND:
		case THREAD_QOS_MAINTENANCE:
			return LINUX_NICE_MAX;
		default:
			return 0;
	}
}

void qos_sched_init_base(void)
{
	// The raw system call answers 20 - nice (getpriority(2)), so that a negative nice can't read as an error.
	long r = LINUX_SYSCALL(__NR_getpriority, LINUX_PRIO_PROCESS, 0);

	if (r > 0)
		base_nice = 20 - (int) r;
}

void qos_sched_apply_self(unsigned int qos)
{
	static int raise_failed_logged;
	int nice = base_nice + qos_nice_offset(qos);

	if (nice > LINUX_NICE_MAX)
		nice = LINUX_NICE_MAX;

	// The TSD keeps the nice this last set, plus 21 so that it's never 0. 0 is a thread this hasn't set yet,
	// whose nice may be its creator's, as clone() copies it.
	uintptr_t want = (uintptr_t) (nice + 21);
	if (_pthread_getspecific_direct(__PTK_DARLING_QOS_NICE) == want)
		return;

	long r = LINUX_SYSCALL(__NR_setpriority, LINUX_PRIO_PROCESS, 0, nice);
	if (r < 0)
	{
		// Only a move up can fail (EPERM or EACCES without CAP_SYS_NICE); the thread stays where it is.
		if ((r == -LINUX_EPERM || r == -LINUX_EACCES) && !__atomic_exchange_n(&raise_failed_logged, 1, __ATOMIC_RELAXED))
			__simple_fprintf(2, "qos: raising a thread's priority failed (%s); threads keep their lowest QoS priority\n",
				(r == -LINUX_EPERM) ? "EPERM" : "EACCES");
		return;
	}
	_pthread_setspecific_direct(__PTK_DARLING_QOS_NICE, want);
}

void qos_sched_apply_wq_flags(int flags)
{
	// XNU runs the event manager at its own priority, above the QoS bands, and an outside-of-QoS workloop servicer
	// at its scheduling priority: both stay at the base here.
	if ((flags & (WQ_FLAG_THREAD_EVENT_MANAGER | WQ_FLAG_THREAD_OUTSIDEQOS)) || !(flags & WQ_FLAG_THREAD_PRIO_QOS))
		qos_sched_apply_self(THREAD_QOS_UNSPECIFIED);
	else
		qos_sched_apply_self(flags & WQ_FLAG_THREAD_PRIO_MASK);
}
