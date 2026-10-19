#include <darling/emulation/xnu_syscall/bsd/impl/unistd/write.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/socktables.h>

#include <sys/uio.h>

static long write_body(int fd, const void* mem, int len, int cp);

long sys_write(int fd, const void* mem, int len)
{
	CANCELATION_POINT();
	return write_body(fd, mem, len, 1);
}

__attribute__((visibility("default")))
long __write_for_xtrace(int fd, const void* mem, int len)
{
	return sys_write_nocancel(fd, mem, len);
}


long sys_write_nocancel(int fd, const void* mem, int len)
{
	return write_body(fd, mem, len, 0);
}

static long write_body(int fd, const void* mem, int len, int cp)
{
	int ret;
	long route_ret;

	if (ROUTE_SOCKET_ACTIVE() && route_socket_write(fd, mem, len, 0, &route_ret))
		return route_ret;

	// a socket with SO_NOSIGPIPE (nosigpipe.h)
	if (NOSIGPIPE_ACTIVE()) {
		struct iovec iov = { (void*) mem, len };
		long sent;
		if (socket_nosigpipe_write(fd, &iov, 1, &sent))
			return sent < 0 ? socket_send_failed(fd, sent, 0, 0) : sent;
	}

	ret = LINUX_SYSCALL_MAYBE_CP(cp, __NR_write, fd, mem, len);
	if (ret < 0) {
		// Linux raised SIGPIPE itself for its own EPIPE; a socket error made EPIPE gets XNU's (sostate.h)
		int linux_raised = ret == -LINUX_EPIPE;
		ret = errno_linux_to_bsd(ret);
		return socket_send_failed(fd, ret, 0, linux_raised);
	}

	return ret;
}
