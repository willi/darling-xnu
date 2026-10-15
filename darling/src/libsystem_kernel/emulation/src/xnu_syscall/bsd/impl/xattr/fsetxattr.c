#include <darling/emulation/xnu_syscall/bsd/impl/xattr/fsetxattr.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/xattr_names.h>

long sys_fsetxattr(int fd, const char* name, const void* value,
		unsigned long size, unsigned int pos, int options)
{
	char linux_name[XATTR_LINUX_NAME_MAX];
	long ret;

	if (pos != 0)
		return -ERANGE;
	ret = xattr_linux_name(name, linux_name);
	if (ret < 0)
		return ret;

	ret = LINUX_SYSCALL(__NR_fsetxattr, fd, linux_name, value, size, xattr_linux_flags(options));

	return ret < 0 ? xattr_errno(ret) : 0;
}
