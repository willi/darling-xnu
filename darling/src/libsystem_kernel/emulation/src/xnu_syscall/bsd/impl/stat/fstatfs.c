#include <darling/emulation/xnu_syscall/bsd/impl/stat/fstatfs.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>

long sys_fstatfs(int fd, struct bsd_statfs* buf)
{
#ifdef __x86_64__
	return sys_fstatfs64(fd, (struct bsd_statfs64*) buf);
#else
#	warning Not implemented
	return 0;
#endif
}

long sys_fstatfs64(int fd, struct bsd_statfs64* buf)
{
	char proc_path[32], path[4096];
	int ret;

	// the file's path as Linux knows it
	__simple_sprintf(proc_path, "/proc/self/fd/%d", fd);
	ret = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, proc_path, path, sizeof(path) - 1);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	path[ret] = '\0';

	// a socket's, a pipe's or a removed file's path leads nowhere: the file system's root stands in
	if (path[0] != '/' || mounts_statfs(path, buf) < 0)
		return mounts_statfs("/", buf);
	return 0;
}
