#include <darling/emulation/xnu_syscall/bsd/impl/unistd/dup2.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/linux_premigration/ext/for-libkqueue.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/socktables.h>

long sys_dup2(int fd_from, int fd_to)
{
	int ret;
	unsigned long long replacing = 0;

	if (guard_table_check(fd_to, guard_flag_prevent_close)) {
		__simple_kprintf("*** Someone tried to close a guarded FD (%d) via dup2! ***", fd_to);
		__simple_abort();
	}

	// what fd_to was, if this replaces it
	if (fd_from != fd_to)
		replacing = socket_tables_replacing(fd_to);

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
		// fd_to was closed, as by close(): its knotes go (XNU's dup2() closes it with knote_fdclose())
		if (fd_from != fd_to) {
			socket_tables_replaced(fd_to, replacing);
			kqueue_closed_fd(fd_to);
		}
		kqueue_dup(fd_from, fd_to);
		socket_tables_dup(fd_from, fd_to);
	}

	return ret;
}
