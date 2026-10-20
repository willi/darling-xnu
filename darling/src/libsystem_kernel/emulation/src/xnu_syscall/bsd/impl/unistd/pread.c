#include <darling/emulation/xnu_syscall/bsd/impl/unistd/pread.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

static long pread_body(int fd, void* mem, int len, long long ofs, int cp);

long sys_pread(int fd, void* mem, int len, long long ofs)
{
	CANCELATION_POINT();
	return pread_body(fd, mem, len, ofs, 1);
}

long sys_pread_nocancel(int fd, void* mem, int len, long long ofs)
{
	return pread_body(fd, mem, len, ofs, 0);
}

static long pread_body(int fd, void* mem, int len, long long ofs, int cp)
{
	int ret;

	ret = LINUX_SYSCALL_MAYBE_CP(cp, __NR_pread64, fd, mem, len, LL_ARG(ofs));
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return ret;
}
