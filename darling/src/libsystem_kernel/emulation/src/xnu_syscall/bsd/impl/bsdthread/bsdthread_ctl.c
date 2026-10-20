// THREAD_QOS_* and pthread_priority_t's encoding are PRIVATE in mach/thread_policy.h and pthread/priority_private.h
#define PRIVATE 1
#define __PTHREAD_EXPOSE_INTERNALS__ 1
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_ctl.h>

#include <sys/errno.h>
#include <mach/host_info.h>
#include <mach/mach_host.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <pthread/priority_private.h>

// bsd/pthread/bsdthread_private.h
#define BSDTHREAD_CTL_QOS_MAX_PARALLELISM 0x800
#define _PTHREAD_QOS_PARALLELISM_COUNT_LOGICAL 0x1
#define _PTHREAD_QOS_PARALLELISM_REALTIME 0x2
#define _PTHREAD_QOS_PARALLELISM_CLUSTER_SHARED_RSRC 0x4

// XNU's bsdthread_get_max_parallelism (bsd/pthread/pthread_workqueue.c) over sched_qos_max_parallelism
// (osfmk/kern/sched_prim.c): the host's logical or physical CPU count, from the host_info that hw.logicalcpu and
// hw.physicalcpu answer from too. libpthread takes any result that isn't -1 as the count, so 0 meant "no CPUs" to
// every caller that doesn't fall back by itself as libdispatch does (SpotlightIndex's indexing pool, libmecabra,
// libSparse). A failed host_info is EINVAL, which makes libpthread fall back to the commpage's counts.
static long max_parallelism(unsigned long qos, unsigned long flags)
{
	static struct host_basic_info hinfo; // the same answer every time: a race only fills it twice

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

	if (hinfo.logical_cpu == 0) {
		struct host_basic_info info;
		mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;
		mach_port_t host = mach_host_self();
		kern_return_t kr = host_info(host, HOST_BASIC_INFO, (host_info_t) &info, &count);

		mach_port_deallocate(mach_task_self(), host);
		if (kr != KERN_SUCCESS || info.logical_cpu <= 0 || info.physical_cpu <= 0)
			return -EINVAL;
		hinfo = info;
	}
	return (flags & _PTHREAD_QOS_PARALLELISM_COUNT_LOGICAL) ? hinfo.logical_cpu : hinfo.physical_cpu;
}

long sys_bsdthread_ctl(long command, void* arg1, void* arg2, void* arg3) {
	switch (command) {
	case BSDTHREAD_CTL_QOS_MAX_PARALLELISM:
		return max_parallelism((unsigned long) arg1, (unsigned long) arg2);
	default:
		// QoS, overrides and the rest change nothing yet: every thread runs at its process's Linux priority
		return 0;
	}
};
