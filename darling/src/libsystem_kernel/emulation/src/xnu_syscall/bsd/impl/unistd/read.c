#include <darling/emulation/xnu_syscall/bsd/impl/unistd/read.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/linux_premigration/misc/ioctl.h>
#include <darling/emulation/conversion/duct_errno.h>

#define LINUX_TCGETA 0x5405

static long read_body(int fd, void* mem, int len, int cp);

long sys_read(int fd, void* mem, int len)
{
	CANCELATION_POINT();
	return read_body(fd, mem, len, 1);
}

long sys_read_nocancel(int fd, void* mem, int len)
{
	return read_body(fd, mem, len, 0);
}

static long read_body(int fd, void* mem, int len, int cp)
{
	int ret;

	ret = LINUX_SYSCALL_MAYBE_CP(cp, __NR_read, fd, mem, len);
	if (ret < 0)
	{
		// When the slave side of a PTY is closed, Linux produces -EIO on the master side.
		// macOS produces an EOF.
		if (ret == -LINUX_EIO)
		{
			// Not making this static makes everything go boom. Do we have a too small stack somewhere?
			static char dummy[18];
			if (__real_ioctl(fd, LINUX_TCGETA, dummy) == 0) // "isatty(fd)"
				return 0;
		}
		ret = errno_linux_to_bsd(ret);
	}

	// on a socket, the error XNU's soreceive() would return (sostate.h)
	if (ret <= 0 && SOCKET_READ_HOOKED(ret))
		ret = socket_error_read(fd, ret, 0, socket_watchers != 0);

	return ret;
}
