#include <darling/emulation/xnu_syscall/bsd/impl/xattr/flistxattr.h>

#include <sys/stat.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/xattr_names.h>

#ifdef __NR_fstat64
	#define STAT_CALL __NR_fstat64
#else
	#define STAT_CALL __NR_fstat
#endif

static long list_fd(long fd, char* buf, unsigned long size)
{
	return LINUX_SYSCALL(__NR_flistxattr, (int) fd, buf, size);
}

static long list_link(long path, char* buf, unsigned long size)
{
	return LINUX_SYSCALL(__NR_llistxattr, (const char*) path, buf, size);
}

long sys_flistxattr(int fd, char* namebuf, unsigned long size, int options)
{
	int ret;

	struct linux_stat st;
	ret = LINUX_SYSCALL(STAT_CALL, fd, &st);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	if (S_ISLNK(st.st_mode)) {
		// for links, we need to use `llistxattr`
		// so translate the fd to a Linux path
		char buf[64] = {0};
		char path[4096] = {0};
		__simple_sprintf(buf, "/proc/self/fd/%d", fd);
		#if defined(__NR_readlink)
			ret = LINUX_SYSCALL(__NR_readlink, buf, path, sizeof(path) - 1);
		#else
			ret = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, buf, path, sizeof(path) - 1);
		#endif
		if (ret < 0)
			return errno_linux_to_bsd(ret);
		path[ret] = '\0';
		return xattr_list(list_link, (long) path, namebuf, size);
	}

	return xattr_list(list_fd, fd, namebuf, size);
}
