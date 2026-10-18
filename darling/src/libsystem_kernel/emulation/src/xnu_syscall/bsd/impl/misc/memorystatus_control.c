#include <darling/emulation/xnu_syscall/bsd/impl/misc/memorystatus_control.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/errno.h>

#include <darlingserver/rpc.h>

// XNU's memorystatus_control() (bsd/kern/kern_memorystatus.c) keeps every process's jetsam priority, memory limits and
// flags, so it's darlingserver's (see its memorystatus.hpp)
VISIBLE // made visible for xtrace
long sys_memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void* buffer, size_t buffersize)
{
	int32_t retval = 0;
	int code = dserver_rpc_memorystatus_control((int32_t) command, pid, flags, buffer, buffersize, &retval);

	// memorystatus_control()'s own error, or an RPC failure: a negative Linux errno either way
	// Linux has one value for ENOTSUP and EOPNOTSUPP (95), which errno_linux_to_bsd() takes for EOPNOTSUPP (102):
	// memorystatus_control() answers ENOTSUP (45), as XNU's does, and RunningBoard expects that one
	if (code == -LINUX_EOPNOTSUPP)
		return -ENOTSUP;
	if (code != 0)
		return errno_linux_to_bsd(code);
	return retval;
}
