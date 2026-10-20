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

#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/qos_sched.h>

// bsd/pthread/bsdthread_private.h
#define BSDTHREAD_CTL_SET_SELF 0x100
#define BSDTHREAD_CTL_QOS_MAX_PARALLELISM 0x800
#define _PTHREAD_QOS_PARALLELISM_COUNT_LOGICAL 0x1
#define _PTHREAD_QOS_PARALLELISM_REALTIME 0x2
#define _PTHREAD_QOS_PARALLELISM_CLUSTER_SHARED_RSRC 0x4
// libpthread's _pthread_set_flags_t (private/pthread/qos_private.h), XNU's workq_set_self_flags
#define _PTHREAD_SET_SELF_QOS_FLAG 0x1

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
	case BSDTHREAD_CTL_SET_SELF:
		// arg1 is the thread's new pthread_priority_t, arg2 a voucher and arg3 the _PTHREAD_SET_SELF_* flags
		// (XNU's bsdthread_set_self). The QoS reaches Linux as the thread's nice (qos_sched.h). It returns 0 for
		// every input, as before: XNU's EINVAL cases (a malformed priority; a manager, above-UI or overcommit to
		// cooperative workqueue thread) need workqueue state Darling doesn't keep, and libdispatch crashes on
		// EINVAL here (_dispatch_set_priority_and_voucher_slow), so a wrong EINVAL costs more than a missing one.
		if ((unsigned long) arg3 & _PTHREAD_SET_SELF_QOS_FLAG)
			qos_sched_apply_self(_pthread_priority_thread_qos((pthread_priority_t) arg1));
		return 0;
	case BSDTHREAD_CTL_QOS_MAX_PARALLELISM:
		return max_parallelism((unsigned long) arg1, (unsigned long) arg2);
	default:
		// overrides and the rest change nothing yet
		return 0;
	}
};
