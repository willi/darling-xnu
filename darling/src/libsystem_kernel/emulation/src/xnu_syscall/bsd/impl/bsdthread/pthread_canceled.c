#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/pthread_canceled.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_create.h>

#include <darlingserver/rpc.h>

long sys_pthread_canceled(int action)
{
	// MEASUREMENT ONLY, never merged: action 0 answers "not canceled" here instead of asking darlingserver, which
	// answers -ENOSYS (call.cpp's PthreadCanceled is a stub), so both callers see what they see today, without the RPC
	if (action == 0)
		return -EINVAL;

	int ret = dserver_rpc_pthread_canceled(action);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
