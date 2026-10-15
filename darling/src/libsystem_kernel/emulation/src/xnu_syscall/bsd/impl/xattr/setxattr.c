#include <darling/emulation/xnu_syscall/bsd/impl/xattr/setxattr.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/xattr_names.h>

long sys_setxattr(const char* path, const char* name, const void* value,
		unsigned long size, unsigned int pos, int options)
{
	char linux_name[XATTR_LINUX_NAME_MAX];
	struct vchroot_expand_args vc;
	long ret;

	if (pos != 0)
		return -ERANGE;
	ret = xattr_linux_name(name, linux_name);
	if (ret < 0)
		return ret;
	ret = xattr_path(path, options, &vc);
	if (ret < 0)
		return ret;

	if (options & XATTR_NOFOLLOW)
		ret = LINUX_SYSCALL(__NR_lsetxattr, vc.path, linux_name, value, size, xattr_linux_flags(options));
	else
		ret = LINUX_SYSCALL(__NR_setxattr, vc.path, linux_name, value, size, xattr_linux_flags(options));

	return ret < 0 ? xattr_errno(ret) : 0;
}
