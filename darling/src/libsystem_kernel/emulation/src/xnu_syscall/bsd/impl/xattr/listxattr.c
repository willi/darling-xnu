#include <darling/emulation/xnu_syscall/bsd/impl/xattr/listxattr.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/xattr_names.h>

static long list(long path, char* buf, unsigned long size)
{
	return LINUX_SYSCALL(__NR_listxattr, (const char*) path, buf, size);
}

static long list_nofollow(long path, char* buf, unsigned long size)
{
	return LINUX_SYSCALL(__NR_llistxattr, (const char*) path, buf, size);
}

long sys_listxattr(const char* path, char* namebuf, unsigned long size, int options)
{
	struct vchroot_expand_args vc;
	long ret = xattr_path(path, options, &vc);

	if (ret < 0)
		return ret;
	return xattr_list((options & XATTR_NOFOLLOW) ? list_nofollow : list, (long) vc.path, namebuf, size);
}
