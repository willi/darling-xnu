#include <darling/emulation/xnu_syscall/bsd/impl/ioctl/ffsctl.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>
#include <sys/ioccom.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

// XNU's sys/fsctl.h
#ifndef FSIOC_FD_ONLY_OPEN_ONCE
#define FSIOC_FD_ONLY_OPEN_ONCE _IOWR('A', 21, uint32_t)
#endif

#define LINUX_AT_FDCWD -100
#define LINUX_F_SETOWN_EX 15
#define LINUX_F_GETOWN_EX 16
#define LINUX_F_SETLEASE 1024
#define LINUX_F_WRLCK 1
#define LINUX_F_UNLCK 2
#define LINUX_EAGAIN 11

struct linux_f_owner_ex {
	int type;
	int pid;
};

// XNU's file_vnode(): EBADF for no descriptor, EINVAL for one that isn't a vnode (a socket, a pipe, a kqueue)
static long fd_vnode_error(int fd)
{
	char path[32], target[16];
	long n;

	__simple_sprintf(path, "/proc/self/fd/%d", fd);
	n = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, path, target, sizeof(target));
	if (n < 0)
		return -EBADF;
	// the others' targets are "socket:[...]", "pipe:[...]" and "anon_inode:..."; a file's is its path
	return target[0] == '/' ? 0 : -EINVAL;
}

// XNU answers from the vnode's use count: 0 if the descriptor's open is the file's only one, else EBUSY. Linux
// grants a write lease on a file only when no other open of it exists (fs/locks.c, check_conflicting_open(): the
// file's counts of opens for reading and for writing are this open's own), and an open counts there until its last
// reference goes, a mapping's included, as a vnode's use count does. Where no lease can be had (a file system without
// them, a file of another owner), it's unknown, and the answer is XNU's other one: EBUSY never claims a lone open.
static long fd_only_open_once(int fd)
{
	struct linux_f_owner_ex owner;
	long ret;

	// taking the lease makes this process the file's signal owner, and someone opening the file before the lease is
	// let go breaks it with a SIGIO to its owner: give the owner back first
	if (LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_GETOWN_EX, &owner) < 0)
		return -EBUSY;

	ret = LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_SETLEASE, LINUX_F_WRLCK);
	if (ret < 0)
		return -EBUSY;

	LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_SETOWN_EX, &owner);
	LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_SETLEASE, LINUX_F_UNLCK);
	return 0;
}

long sys_ffsctl(int fd, unsigned long cmd, void* data, unsigned int options)
{
	long ret = fd_vnode_error(fd);

	if (ret != 0)
		return ret;

	switch (cmd)
	{
		case FSIOC_FD_ONLY_OPEN_ONCE:
			// XNU copies the argument in, and out again
			if (data == NULL)
				return -EFAULT;
			return fd_only_open_once(fd);
		default:
			// XNU passes other commands to the file system, and an ioctl it doesn't know is ENOTTY
			return -ENOTTY;
	}
}
