// THREAD_QOS_* and pthread_priority_t's encoding are PRIVATE in mach/thread_policy.h and pthread/priority_private.h
#define PRIVATE 1
#define __PTHREAD_EXPOSE_INTERNALS__ 1
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_ctl.h>

#include <sys/errno.h>
#include <pthread/priority_private.h>

#include <darling/emulation/xnu_syscall/bsd/helper/misc/host_basic_info.h>

// bsd/pthread/bsdthread_private.h
#define BSDTHREAD_CTL_QOS_MAX_PARALLELISM 0x800
#define _PTHREAD_QOS_PARALLELISM_COUNT_LOGICAL 0x1
#define _PTHREAD_QOS_PARALLELISM_REALTIME 0x2
#define _PTHREAD_QOS_PARALLELISM_CLUSTER_SHARED_RSRC 0x4

// XNU's bsdthread_get_max_parallelism (bsd/pthread/pthread_workqueue.c 2778-2806): its argument checks, then the
// scheduler's count (qos_max_parallelism, host_basic_info.h). libpthread takes any result that isn't -1 as the
// count, so the 0 this used to return meant "no CPUs" to every caller that doesn't fall back by itself as
// libdispatch does. A count Darling can't get is EINVAL, which makes libpthread fall back to the commpage's counts.
// ENOTSUP only for the cluster flag, as XNU: Darling's libpthread fork crashes on any errno but EINVAL here, and
// never sends that flag.
static long max_parallelism(unsigned long qos, unsigned long flags, unsigned long unused)
{
	if (unused != 0) // XNU's ENSURE_UNUSED(uap->arg3) (pthread_workqueue.c 2860)
		return -EINVAL;
	if (flags & ~(_PTHREAD_QOS_PARALLELISM_REALTIME | _PTHREAD_QOS_PARALLELISM_COUNT_LOGICAL |
			_PTHREAD_QOS_PARALLELISM_CLUSTER_SHARED_RSRC))
		return -EINVAL;
	// no cluster-shared units on this hardware, as on any non-AMP Mac
	if (flags & _PTHREAD_QOS_PARALLELISM_CLUSTER_SHARED_RSRC)
		return -ENOTSUP;
	if (flags & _PTHREAD_QOS_PARALLELISM_REALTIME) {
		if (qos != 0)
			return -EINVAL;
	} else if (qos == THREAD_QOS_UNSPECIFIED || qos >= THREAD_QOS_LAST) {
		return -EINVAL;
	}

	int count = qos_max_parallelism((int) qos, flags);
	return (count > 0) ? count : -EINVAL;
}

long sys_bsdthread_ctl(long command, void* arg1, void* arg2, void* arg3) {
	switch (command) {
	case BSDTHREAD_CTL_QOS_MAX_PARALLELISM:
		return max_parallelism((unsigned long) arg1, (unsigned long) arg2, (unsigned long) arg3);
	default:
		// QoS, overrides and the rest change nothing yet: every thread runs at its process's Linux priority
		return 0;
	}
};
