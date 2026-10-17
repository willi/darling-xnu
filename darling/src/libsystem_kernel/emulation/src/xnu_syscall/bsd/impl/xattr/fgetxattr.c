#include <darling/emulation/xnu_syscall/bsd/impl/xattr/fgetxattr.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/xattr_names.h>

long sys_fgetxattr(int fd, const char* name, char* value,
		unsigned long size, unsigned int pos, int options)
{
	char linux_name[XATTR_LINUX_NAME_MAX];
	long ret;

	if (pos != 0)
		return -ERANGE;
	ret = xattr_linux_name(name, linux_name);
	if (ret < 0)
		return ret;

	if (!value)
		size = 0;
	ret = LINUX_SYSCALL(__NR_fgetxattr, fd, linux_name, value, size);

	return ret < 0 ? xattr_errno(ret) : ret;
}
