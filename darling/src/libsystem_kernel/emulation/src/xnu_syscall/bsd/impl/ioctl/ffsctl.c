#include <darling/emulation/xnu_syscall/bsd/impl/ioctl/ffsctl.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/ioccom.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>

// XNU's sys/fsctl.h
#ifndef FSIOC_FD_ONLY_OPEN_ONCE
#define FSIOC_FD_ONLY_OPEN_ONCE _IOWR('A', 21, uint32_t)
#endif
#ifndef FSIOC_SYNC_VOLUME
#define FSIOC_SYNC_VOLUME _IOW('A', 1, uint32_t)
#endif
#ifndef FSOPT_NOFOLLOW
#define FSOPT_NOFOLLOW 0x00000001
#endif
#ifndef O_EVTONLY
#define O_EVTONLY 0x00008000
#endif

#define LINUX_AT_FDCWD -100
#define LINUX_F_GETFD 1
#define LINUX_F_SETOWN_EX 15
#define LINUX_F_GETOWN_EX 16
#define LINUX_F_SETLEASE 1024
#define LINUX_F_WRLCK 1
#define LINUX_F_UNLCK 2
#define LINUX_S_IFMT 0170000
#define LINUX_S_IFCHR 0020000
#define LINUX_S_IFBLK 0060000
#define LINUX_OVERLAYFS_SUPER_MAGIC 0x794c7630

#ifdef __NR_fstat64
#define LINUX_NR_FSTAT __NR_fstat64
#else
#define LINUX_NR_FSTAT __NR_fstat
#endif

struct linux_f_owner_ex {
	int type;
	int pid;
};

// XNU's file_vnode(): EBADF for no descriptor, EINVAL for one that isn't a vnode (a socket, a pipe, a kqueue). Not
// told apart: a POSIX shared memory object (a file in /dev/shm here, DTYPE_PSXSHM on XNU, so EINVAL there).
static long fd_vnode_error(int fd)
{
	char path[48], target[16];

	if (LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_GETFD) < 0)
		return -EBADF;
	// this thread's table: /proc/self is the main thread's, gone if that thread has exited
	__simple_sprintf(path, "/proc/thread-self/fd/%d", fd);
	if (LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, path, target, sizeof(target)) < 1)
		return -EBADF;
	// the others' targets are "socket:[...]", "pipe:[...]" and "anon_inode:..."; a file's is its path
	return target[0] == '/' ? 0 : -EINVAL;
}

// Copies as XNU's copyin()/copyout() do: a bad address fails (EFAULT) instead of faulting here. Where
// process_vm_readv()/process_vm_writev() are refused (a seccomp filter, say), the memory is copied as it is.
static bool copy_user(void* to, const void* from, unsigned long len, bool out)
{
	struct { const void* base; unsigned long len; } local = { out ? from : to, len }, remote = { out ? to : from, len };
	long ret;

	if (to == NULL || from == NULL)
		return false;
	ret = LINUX_SYSCALL(out ? __NR_process_vm_writev : __NR_process_vm_readv, LINUX_SYSCALL0(__NR_getpid), &local, 1,
		&remote, 1, 0);
	if (ret == -LINUX_ENOSYS || ret == -LINUX_EPERM) {
		__builtin_memcpy(to, from, len);
		return true;
	}
	return ret == (long) len;
}

// Whether the process maps the file (st_dev, st_ino) anywhere, by /proc/thread-self/maps: "start-end perms offset
// major:minor inode path" a line
static bool mapped(int fd, const struct linux_stat* st)
{
	struct linux_statfs64 sfs;
#ifdef __NR_fstatfs64
	long r = LINUX_SYSCALL3(__NR_fstatfs64, fd, sizeof(sfs), &sfs);
#else
	long r = LINUX_SYSCALL2(__NR_fstatfs, fd, &sfs);
#endif
	// overlayfs maps the file beneath, of another device: there, the inode number alone (EBUSY for a file of the same
	// number on another device, but EBUSY never claims a lone open)
	bool any_device = r == 0 && sfs.f_type == LINUX_OVERLAYFS_SUPER_MAGIC;
	unsigned long long major = ((st->st_dev >> 8) & 0xfff) | ((st->st_dev >> 32) & ~0xfffull);
	unsigned long long minor = (st->st_dev & 0xff) | ((st->st_dev >> 12) & ~0xffull);
	char buf[4096], line[160];
	int len = 0, maps;
	long n;
	bool found = false;

	maps = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, "/proc/thread-self/maps", 0 /* O_RDONLY */ | 02000000 /* O_CLOEXEC */);
	if (maps < 0)
		return false;
	while (!found && (n = LINUX_SYSCALL(__NR_read, maps, buf, sizeof(buf))) > 0) {
		for (long i = 0; i < n && !found; i++) {
			if (buf[i] != '\n') {
				if (len < sizeof(line) - 1)
					line[len++] = buf[i];
				continue;
			}
			line[len] = '\0';
			len = 0;

			// the fourth and fifth fields
			char* p = line;
			for (int field = 0; field < 3 && *p != '\0'; p++)
				if (*p == ' ')
					field++;
			if (*p == '\0')
				continue;
			unsigned long long maj = 0, min = 0, ino = 0;
			for (; *p != ':' && *p != '\0'; p++)
				maj = maj * 16 + (*p <= '9' ? *p - '0' : (*p | 0x20) - 'a' + 10);
			if (*p++ != ':')
				continue;
			for (; *p != ' ' && *p != '\0'; p++)
				min = min * 16 + (*p <= '9' ? *p - '0' : (*p | 0x20) - 'a' + 10);
			for (p++; *p >= '0' && *p <= '9'; p++)
				ino = ino * 10 + (*p - '0');
			found = ino == st->st_ino && ino != 0 && (any_device || (maj == major && min == minor));
		}
	}
	close_internal(maps);
	return found;
}

// XNU answers from the vnode's use count: 0 if the descriptor's open is the file's only one, else EBUSY. Linux
// grants a write lease on a file only when no other open file description of it exists (fs/locks.c,
// check_conflicting_open(), since Linux 5.3: the file's counts of opens for reading and for writing are this open's
// own), and an open counts there until its last reference goes, so a mapping made through another open counts as
// that open, as on XNU. A mapping made through this very open isn't another open on Linux, but takes a use count of
// its own on XNU (ubc_map()): the process's mappings are looked through for the file.
//
// Where no lease can be had (a file system without them, a file of another owner, an O_PATH descriptor), it's
// unknown, and the answer is XNU's other one: EBUSY never claims a lone open. Not seen, as on overlayfs, whose files
// are opened and mapped as the files beneath: opens of those directly, and mappings whose descriptor is closed.
static long fd_only_open_once(int fd, const struct linux_stat* st)
{
	struct linux_f_owner_ex owner;
	unsigned long long all = ~0ull, mask;
	long ret = 0;

	// taking the lease makes this process the file's signal owner (so an open that breaks the lease sends it SIGIO),
	// and letting it go clears the owner: the one before is set again, before and after. While the lease is held,
	// another process's open waits for it (or fails with EAGAIN, if O_NONBLOCK): signals are blocked meanwhile, so that
	// nothing stops this thread holding it.
	if (LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_GETOWN_EX, &owner) < 0)
		return -EBUSY;

	LINUX_SYSCALL(__NR_rt_sigprocmask, 0 /* LINUX_SIG_BLOCK */, &all, &mask, sizeof(all));
	if (LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_SETLEASE, LINUX_F_WRLCK) < 0)
		ret = -EBUSY;
	else {
		LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_SETOWN_EX, &owner);
		if (LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_SETLEASE, LINUX_F_UNLCK) < 0
			&& LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_SETLEASE, LINUX_F_UNLCK) < 0) {
			// held until the descriptor is closed: opens elsewhere wait for it
			__simple_kprintf("ffsctl: fd %d: the lease taken to count its opens can't be let go\n", fd);
			ret = -EBUSY;
		}
	}
	LINUX_SYSCALL(__NR_fcntl, fd, LINUX_F_SETOWN_EX, &owner);
	LINUX_SYSCALL(__NR_rt_sigprocmask, 2 /* LINUX_SIG_SETMASK */, &mask, NULL, sizeof(mask));

	if (ret == 0 && mapped(fd, st))
		ret = -EBUSY;
	return ret;
}

// FSIOC_SYNC_VOLUME: the file system's data written out. A descriptor that can't do I/O (O_PATH) writes out all of
// them.
static long sync_volume(int fd)
{
	if (LINUX_SYSCALL(__NR_syncfs, fd) < 0)
		LINUX_SYSCALL0(__NR_sync);
	return 0;
}

// XNU's fsctl_internal(), for the commands the emulation knows: fd is a descriptor of the vnode
static long fsctl_common(int fd, unsigned long cmd, void* data)
{
	struct linux_stat st;
	unsigned char arg[128];
	unsigned long size = IOCPARM_LEN(cmd);
	long ret;

	if (LINUX_SYSCALL(LINUX_NR_FSTAT, fd, &st) < 0)
		return -EBADF;
	if ((st.st_mode & LINUX_S_IFMT) == LINUX_S_IFCHR || (st.st_mode & LINUX_S_IFMT) == LINUX_S_IFBLK)
		return -ENOTTY;
	if (size > IOCPARM_MAX)
		return -EINVAL;

	// the argument copied in, as XNU does before the command; only the commands below are known, and their argument
	// fits in arg
	if ((cmd & IOC_IN) && size > 0) {
		for (unsigned long off = 0; off < size; off += sizeof(arg)) {
			unsigned long n = size - off < sizeof(arg) ? size - off : sizeof(arg);
			if (!copy_user(arg, (char*) data + off, n, false))
				return -EFAULT;
		}
	} else if ((cmd & IOC_OUT) && size > 0)
		__builtin_memset(arg, 0, sizeof(arg));

	switch (cmd)
	{
		case FSIOC_SYNC_VOLUME:
			ret = sync_volume(fd);
			break;
		case FSIOC_FD_ONLY_OPEN_ONCE:
			ret = fd_only_open_once(fd, &st);
			break;
		default:
			// XNU passes other commands to the file system, and an ioctl it doesn't know is ENOTTY
			return -ENOTTY;
	}

	// and copied out again
	if (ret == 0 && (cmd & IOC_OUT) && size > 0 && size <= sizeof(arg) && !copy_user(data, arg, size, true))
		return -EFAULT;
	return ret;
}

long sys_ffsctl(int fd, unsigned long cmd, void* data, unsigned int options)
{
	long ret = fd_vnode_error(fd);

	if (ret != 0)
		return ret;
	return fsctl_common(fd, cmd, data);
}

long sys_fsctl(const char* path, unsigned long cmd, void* data, unsigned int options)
{
	long fd, ret;

	// XNU: by path, the file isn't open, so the only open can't be the caller's
	if (cmd == FSIOC_FD_ONLY_OPEN_ONCE)
		return -EINVAL;

	// an event-only descriptor (O_PATH) needs no access to the file, as XNU's lookup needs none
	fd = sys_open_nocancel(path, O_EVTONLY | O_CLOEXEC | ((options & FSOPT_NOFOLLOW) ? O_SYMLINK : 0), 0);
	if (fd < 0)
		return fd;
	ret = fsctl_common(fd, cmd, data);
	close_internal(fd);
	return ret;
}
