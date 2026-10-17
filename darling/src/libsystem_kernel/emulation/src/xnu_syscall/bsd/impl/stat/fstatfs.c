#include <darling/emulation/xnu_syscall/bsd/impl/stat/fstatfs.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>

long sys_fstatfs(int fd, struct bsd_statfs* buf)
{
#ifdef __x86_64__
	return sys_fstatfs64(fd, (struct bsd_statfs64*) buf);
#else
#	warning Not implemented
	return 0;
#endif
}

long sys_fstatfs64(int fd, struct bsd_statfs64* buf)
{
	return mounts_fstatfs(fd, buf);
}
