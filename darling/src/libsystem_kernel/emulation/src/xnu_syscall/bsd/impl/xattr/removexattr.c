#include <darling/emulation/xnu_syscall/bsd/impl/xattr/removexattr.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/xattr_names.h>

long sys_removexattr(const char* path, const char* name, int options)
{
	char linux_name[XATTR_LINUX_NAME_MAX];
	struct vchroot_expand_args vc;
	long ret;

	ret = xattr_linux_name(name, linux_name);
	if (ret < 0)
		return ret;
	ret = xattr_path(path, options, &vc);
	if (ret < 0)
		return ret;

	if (options & XATTR_NOFOLLOW)
		ret = LINUX_SYSCALL(__NR_lremovexattr, vc.path, linux_name);
	else
		ret = LINUX_SYSCALL(__NR_removexattr, vc.path, linux_name);

	return ret < 0 ? xattr_errno(ret) : 0;
}
