#include <darling/emulation/xnu_syscall/bsd/impl/xattr/getxattr.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/xattr_names.h>

long sys_getxattr(const char* path, const char* name, char* value,
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

	// as XNU: without a buffer, the size of the value
	if (!value)
		size = 0;
	if (options & XATTR_NOFOLLOW)
		ret = LINUX_SYSCALL(__NR_lgetxattr, vc.path, linux_name, value, size);
	else
		ret = LINUX_SYSCALL(__NR_getxattr, vc.path, linux_name, value, size);

	return ret < 0 ? xattr_errno(ret) : ret;
}
