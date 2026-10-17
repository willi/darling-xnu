#include <darling/emulation/xnu_syscall/bsd/impl/network/shutdown.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/socket.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>

long sys_shutdown(int fd, int how)
{
	int ret;

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SHUTDOWN,
			((long[6]) { fd, how }));
#else
	ret = LINUX_SYSCALL(__NR_shutdown, fd, how);
#endif

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else if (socket_watchers != 0) {
		// Linux reports a shutdown of only sending no way: a watched socket remembers it, and its knotes look again
		socket_shutdown(fd, how);
		kqueue_socket_changed(fd);
	}

	return ret;
}
