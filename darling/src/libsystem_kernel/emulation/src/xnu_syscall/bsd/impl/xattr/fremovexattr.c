#include <darling/emulation/xnu_syscall/bsd/impl/xattr/fremovexattr.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/xattr_names.h>

long sys_fremovexattr(int fd, const char* name, int options)
{
	char linux_name[XATTR_LINUX_NAME_MAX];
	long ret;

	ret = xattr_linux_name(name, linux_name);
	if (ret < 0)
		return ret;

	ret = LINUX_SYSCALL(__NR_fremovexattr, fd, linux_name);

	return ret < 0 ? xattr_errno(ret) : 0;
}
