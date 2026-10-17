#include <darling/emulation/xnu_syscall/bsd/impl/stat/statfs.h>

#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>

long sys_statfs(const char* path, struct bsd_statfs* buf)
{
#ifdef __x86_64__
	return sys_statfs64(path, (struct bsd_statfs64*) buf);
#else
#	warning Not implemented
	return 0;
#endif
}

long sys_statfs64(const char* path, struct bsd_statfs64* buf)
{
	struct vchroot_expand_args vc;
	int ret;

	vc.flags = VCHROOT_FOLLOW;
	vc.dfd = get_perthread_wd();
	strcpy(vc.path, path);
	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return mounts_statfs(vc.path, buf);
}
