#include <darling/emulation/xnu_syscall/bsd/impl/unistd/readv.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

static long readv_body(int fd, struct iovec* iovp, unsigned int len, int cp);

long sys_readv(int fd, struct iovec* iovp, unsigned int len)
{
	CANCELATION_POINT();
	return readv_body(fd, iovp, len, 1);
}

long sys_readv_nocancel(int fd, struct iovec* iovp, unsigned int len)
{
	return readv_body(fd, iovp, len, 0);
}

static long readv_body(int fd, struct iovec* iovp, unsigned int len, int cp)
{
	int ret;

	ret = LINUX_SYSCALL_MAYBE_CP(cp, __NR_readv, fd, iovp, len);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	// on a socket, the error XNU's soreceive() would return (sostate.h)
	if (ret <= 0 && SOCKET_READ_HOOKED(ret))
		ret = socket_error_read(fd, ret, 0, socket_watchers != 0);

	return ret;
}
