#include <darling/emulation/xnu_syscall/bsd/impl/unistd/dup2.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/nosigpipe.h>

extern void kqueue_dup(int oldfd, int newfd);

long sys_dup2(int fd_from, int fd_to)
{
	int ret;

	if (guard_table_check(fd_to, guard_flag_prevent_close)) {
		__simple_kprintf("*** Someone tried to close a guarded FD (%d) via dup2! ***", fd_to);
		__simple_abort();
	}

	// a routing socket fd_to names stops being one, as when it's closed
	if (ROUTE_SOCKET_ACTIVE() && fd_from != fd_to)
		route_socket_close(fd_to);
	if (NOSIGPIPE_ACTIVE() && fd_from != fd_to)
		socket_nosigpipe_close(fd_to);

	#if defined(__NR_dup2)
		ret = LINUX_SYSCALL2(__NR_dup2, fd_from, fd_to);
	#else		
		// It's not clear if 0 is offically a valid flag argument.
		// But we don't really have a choice.
		ret = LINUX_SYSCALL(__NR_dup3, fd_from, fd_to, 0);

		if (ret == LINUX_EINVAL && fd_from == fd_to)
			ret = fd_to;
	#endif
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else {
		kqueue_dup(fd_from, fd_to);
		if (ROUTE_SOCKET_ACTIVE())
			route_socket_dup(fd_from, fd_to);
		if (NOSIGPIPE_ACTIVE())
			socket_nosigpipe_dup(fd_from, fd_to);
	}

	return ret;
}
