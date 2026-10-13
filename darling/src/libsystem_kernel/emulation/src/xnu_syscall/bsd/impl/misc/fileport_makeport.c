#include <darling/emulation/xnu_syscall/bsd/impl/misc/fileport_makeport.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>

#include <darlingserver/rpc.h>

long sys_fileport_makeport(int fd, int* port)
{
	uint32_t port_name = 0;
	int code = dserver_rpc_fileport_makeport(fd, &port_name);

	if (code < 0)
		return errno_linux_to_bsd(code);

	*port = port_name;
	return 0;
}
