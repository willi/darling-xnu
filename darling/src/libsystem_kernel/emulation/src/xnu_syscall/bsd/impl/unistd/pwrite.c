#include <darling/emulation/xnu_syscall/bsd/impl/unistd/pwrite.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

static long pwrite_body(int fd, const void* mem, int len, long long ofs, int cp);

long sys_pwrite(int fd, const void* mem, int len, long long ofs)
{
	CANCELATION_POINT();
	return pwrite_body(fd, mem, len, ofs, 1);
}

long sys_pwrite_nocancel(int fd, const void* mem, int len, long long ofs)
{
	return pwrite_body(fd, mem, len, ofs, 0);
}

static long pwrite_body(int fd, const void* mem, int len, long long ofs, int cp)
{
	int ret;

	ret = LINUX_SYSCALL_MAYBE_CP(cp, __NR_pwrite64, fd, mem, len, LL_ARG(ofs));
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return ret;
}
