#include <darling/emulation/xnu_syscall/bsd/impl/stat/getfsstat.h>

#include <stddef.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>

long sys_getfsstat(struct bsd_statfs* buf, int bufsize, int flags)
{
#ifdef __x86_64__
	return sys_getfsstat64((struct bsd_statfs64*) buf, bufsize, flags);
#else
#	warning Not implemented
	return 0;
#endif
}

long sys_getfsstat64(struct bsd_statfs64* buf, int bufsize, int flags)
{
	return mounts_list(buf, buf ? bufsize / (long) sizeof(struct bsd_statfs64) : 0);
}
