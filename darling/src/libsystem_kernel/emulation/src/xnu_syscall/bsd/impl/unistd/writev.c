#include <darling/emulation/xnu_syscall/bsd/impl/unistd/writev.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/nosigpipe.h>

long sys_writev(int fd, struct iovec* iovp, unsigned int len)
{
	CANCELATION_POINT();
	return sys_writev_nocancel(fd, iovp, len);
}

long sys_writev_nocancel(int fd, struct iovec* iovp, unsigned int len)
{
	int ret;
	long route_ret;

	if (ROUTE_SOCKET_ACTIVE() && route_socket_writev(fd, iovp, len, 0, EINVAL, &route_ret))
		return route_ret;

	// a socket with SO_NOSIGPIPE (nosigpipe.h); an iovec count writev() refuses is left to it
	if (NOSIGPIPE_ACTIVE() && len <= 1024 /* UIO_MAXIOV */) {
		long sent;
		if (socket_nosigpipe_write(fd, iovp, len, &sent))
			return sent < 0 ? socket_send_done(fd, socket_error_send(fd, sent), 0, 0) : sent;
	}

	ret = LINUX_SYSCALL3(__NR_writev, fd, iovp, len);
	if (ret < 0) {
		// Linux raised SIGPIPE itself for its own EPIPE; a socket error made EPIPE gets XNU's (sostate.h)
		int linux_raised = ret == -LINUX_EPIPE;
		ret = errno_linux_to_bsd(ret);
		return socket_send_done(fd, socket_error_send(fd, ret), 0, linux_raised);
	}

	return ret;
}
