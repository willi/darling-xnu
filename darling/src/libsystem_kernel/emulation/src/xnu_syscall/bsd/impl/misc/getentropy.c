#include <darling/emulation/xnu_syscall/bsd/impl/misc/getentropy.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define LINUX_GRND_RANDOM 2

long sys_getentropy(void* buf, unsigned long size)
{
	long ret;

	// XNU (bsd/dev/random/randomdev.c) gives at most 256 bytes, as OpenBSD's getentropy() does
	if (size > 256)
		return -EINVAL;

	ret = LINUX_SYSCALL(__NR_getrandom, buf, size, 0);
	// a failure is negative, and compared unsigned with size it looked like a full read
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	if ((unsigned long) ret < size)
		return -EIO;

	return 0;
}
