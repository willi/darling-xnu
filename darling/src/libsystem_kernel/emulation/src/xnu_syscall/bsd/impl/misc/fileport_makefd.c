#include <darling/emulation/xnu_syscall/bsd/impl/misc/fileport_makefd.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>

#include <darlingserver/rpc.h>

long sys_fileport_makefd(int port)
{
	int fd = -1;
	int code = dserver_rpc_fileport_makefd(port, &fd);

	if (code < 0)
		return errno_linux_to_bsd(code);

	return fd;
}
