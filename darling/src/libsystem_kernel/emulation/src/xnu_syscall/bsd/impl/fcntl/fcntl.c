#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/fcntl.h>

#include <sys/errno.h>
#include <sys/fcntl.h>

#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/fcntl/fcntl.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fdpath.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/ext/for-libkqueue.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/socktables.h>

#define XNU_F_GETPROTECTIONCLASS 63
#define XNU_F_SETPROTECTIONCLASS 64

// locks of an open file description, rather than of a process: XNU's and Linux's are the same
#define XNU_F_OFD_SETLK 90
#define XNU_F_OFD_SETLKW 91
#define XNU_F_OFD_GETLK 92
#define LINUX_F_OFD_GETLK 36
#define LINUX_F_OFD_SETLK 37
#define LINUX_F_OFD_SETLKW 38
#define XNU_F_SETLKWTIMEOUT 10
#define XNU_F_OFD_SETLKWTIMEOUT 93

#define LINUX_CLOCK_MONOTONIC 1

#ifndef O_NOFOLLOW
#   define O_NOFOLLOW 0x0100
#endif
#ifndef O_DIRECTORY
#   define O_DIRECTORY 0x100000
#endif
#ifndef MAXPATHLEN
#	define MAXPATHLEN 1024
#endif

int oflags_bsd_to_linux(int flags);
int oflags_linux_to_bsd(int flags);

extern int sprintf(char *str, const char *format, ...);
long sys_readlink(const char* path, char* buf, unsigned long bsize);

static short int flock_type_linux_to_bsd(short int linux) {
	switch (linux) {
		case LINUX_F_RDLCK: return F_RDLCK;
		case LINUX_F_WRLCK: return F_WRLCK;
		case LINUX_F_UNLCK: return F_UNLCK;
		default:            return -1;
	};
};

static short int flock_type_bsd_to_linux(short int bsd) {
	switch (bsd) {
		case F_RDLCK: return LINUX_F_RDLCK;
		case F_WRLCK: return LINUX_F_WRLCK;
		case F_UNLCK: return LINUX_F_UNLCK;
		default:      return -1;
	};
};

static int cmd_bsd_to_linux(int bsd) {
	switch (bsd) {
		case F_DUPFD:  return LINUX_F_DUPFD;
		case F_GETFD:  return LINUX_F_GETFD;
		case F_SETFD:  return LINUX_F_SETFD;
		case F_GETFL:  return LINUX_F_GETFL;
		case F_SETFL:  return LINUX_F_SETFL;
		case F_GETOWN: return LINUX_F_GETOWN;
		case F_SETOWN: return LINUX_F_SETOWN;
		case F_SETLK:  return LINUX_F_SETLK;
		case F_SETLKW: return LINUX_F_SETLKW;
		case F_GETLK:  return LINUX_F_GETLK;
		// Apple's SQLite probes a file system's locking with F_OFD_GETLK; when that fails with anything but
		// ENOTSUP, it falls back to dot-file locks, which outlive a process that dies holding them (and a device
		// restarted after a shutdown found its databases locked for good)
		case XNU_F_OFD_SETLK:  return LINUX_F_OFD_SETLK;
		case XNU_F_OFD_SETLKW: return LINUX_F_OFD_SETLKW;
		case XNU_F_OFD_GETLK:  return LINUX_F_OFD_GETLK;
		case F_DUPFD_CLOEXEC: return LINUX_F_DUPFD_CLOEXEC;
		default:       return -1;
	};
};

struct timeout_timespec
{
	long tv_sec;
	long tv_nsec;
};

struct bsd_flocktimeout
{
	struct bsd_flock fl;
	struct timeout_timespec timeout;
};

static long long ns_now(void)
{
	struct timeout_timespec ts;
	LINUX_SYSCALL(__NR_clock_gettime, LINUX_CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

// F_SETLKWTIMEOUT and F_OFD_SETLKWTIMEOUT: as F_SETLKW and F_OFD_SETLKW, but failing with ETIMEDOUT once the timeout
// (from now; none: no limit) passes, as XNU's lf_setlock(). Linux has no such wait: the lock is tried again until
// then. Apple's SQLite waits for its locks this way.
static long setlk_timeout(int fd, int cmd, struct bsd_flocktimeout* ft)
{
	int ofd = cmd == XNU_F_OFD_SETLKWTIMEOUT;
	long long end, now, delay = 1000000;

	if (!ft)
		return -EFAULT;
	if (!ft->timeout.tv_sec && !ft->timeout.tv_nsec)
		return sys_fcntl_nocancel(fd, ofd ? XNU_F_OFD_SETLKW : F_SETLKW, (long) &ft->fl);

	end = ns_now() + ft->timeout.tv_sec * 1000000000LL + ft->timeout.tv_nsec;
	for (;;)
	{
		long rv = sys_fcntl_nocancel(fd, ofd ? XNU_F_OFD_SETLK : F_SETLK, (long) &ft->fl);
		if (rv != -EAGAIN && rv != -EACCES)
			return rv;
		now = ns_now();
		if (now >= end)
			return -ETIMEDOUT;
		if (delay > end - now)
			delay = end - now;
		struct timeout_timespec ts = { delay / 1000000000LL, delay % 1000000000LL };
		LINUX_SYSCALL(__NR_nanosleep, &ts, 0);
		if (delay < 16000000)
			delay *= 2;
	}
}

long sys_fcntl(int fd, int cmd, long arg)
{
	CANCELATION_POINT();
	return sys_fcntl_nocancel(fd, cmd, arg);
}

long sys_fcntl_nocancel(int fd, int cmd, long arg)
{
	int ret, linux_cmd = cmd_bsd_to_linux(cmd);
	long original_arg = arg;

	switch (cmd)
	{
		case F_CHECK_LV:
			return 0;
		case XNU_F_SETLKWTIMEOUT:
		case XNU_F_OFD_SETLKWTIMEOUT:
			return setlk_timeout(fd, cmd, (struct bsd_flocktimeout*) arg);
		// Darling does not enforce code signatures: accept the file's signature as covering the whole file.
		// dyld (and the iOS Simulator's dyld_sim) refuse to map an image whose signature does not reach its
		// code signature blob, so F_ADDFILESIGS_RETURN reports the largest end offset.
		case F_ADDFILESIGS:
		case F_ADDFILESIGS_FOR_DYLD_SIM:
		case F_ADDFILESIGS_RETURN:
		{
			fsignatures_t* sigs = (fsignatures_t*) arg;
			if (cmd != F_ADDFILESIGS && sigs != NULL)
				sigs->fs_file_start = 0x7fffffffffffffffLL;
			return 0;
		}
		// Data protection classes: Linux file systems have none, so do what XNU does on a volume without content
		// protection: setting a class is accepted and has no effect, and there's no class to get.
		case XNU_F_GETPROTECTIONCLASS:
		case XNU_F_SETPROTECTIONCLASS:
		{
			struct linux_stat st;
			ret = LINUX_SYSCALL(__NR_fstat, fd, &st);
			if (ret < 0)
				return errno_linux_to_bsd(ret);
			return cmd == XNU_F_SETPROTECTIONCLASS ? 0 : -ENOTSUP;
		}
		case F_SETFD:
			if (arg & ~FD_CLOEXEC)
				return -EINVAL;
			break;
		case F_SETFL:
			arg = oflags_bsd_to_linux(arg);
			break;
		case F_GETPATH:
		{
			ret = fdpath(fd, arg, MAXPATHLEN);
			if (ret < 0)
				return errno_linux_to_bsd(ret);

			return 0;
		}
		case F_SETLK:
		case F_SETLKW:
		case F_GETLK:
		case XNU_F_OFD_SETLK:
		case XNU_F_OFD_SETLKW:
		case XNU_F_OFD_GETLK: {
			struct bsd_flock* bsd_struct = arg;
			struct linux_flock* linux_struct = __builtin_alloca(sizeof(struct linux_flock));
			linux_struct->l_type = flock_type_bsd_to_linux(bsd_struct->l_type);
			linux_struct->l_whence = bsd_struct->l_whence;
			linux_struct->l_start = bsd_struct->l_start;
			linux_struct->l_len = bsd_struct->l_len;
			// XNU ignores it for an OFD lock; Linux wants it 0
			linux_struct->l_pid = (cmd == F_SETLK || cmd == F_SETLKW || cmd == F_GETLK) ? bsd_struct->l_pid : 0;
			arg = linux_struct;
		} break;
		case F_FULLFSYNC: {
			ret = LINUX_SYSCALL1(__NR_fsync, fd);
			if (ret < 0)
				ret = errno_linux_to_bsd(ret);
			return 0;
		};
		// TODO: implement remaining commands
		default:
			if (linux_cmd == -1)
				return -EINVAL;
	}

#ifdef __NR_fcntl64
	ret = LINUX_SYSCALL(__NR_fcntl64, fd, linux_cmd, arg);
#else
	ret = LINUX_SYSCALL(__NR_fcntl, fd, linux_cmd, arg);
#endif
	if (ret < 0)
	{
		ret = errno_linux_to_bsd(ret);
		return ret;
	}

	switch (cmd)
	{
		case F_GETFL:
			ret = oflags_linux_to_bsd(ret);
			break;
		case F_SETLK:
		case F_SETLKW:
		case F_GETLK:
		case XNU_F_OFD_SETLK:
		case XNU_F_OFD_SETLKW:
		case XNU_F_OFD_GETLK: {
			struct bsd_flock* bsd_struct = original_arg;
			struct linux_flock* linux_struct = arg;
			bsd_struct->l_type = flock_type_linux_to_bsd(linux_struct->l_type);
			bsd_struct->l_whence = linux_struct->l_whence;
			bsd_struct->l_start = linux_struct->l_start;
			bsd_struct->l_len = linux_struct->l_len;
			bsd_struct->l_pid = linux_struct->l_pid;
		} break;
		case F_DUPFD:
		case F_DUPFD_CLOEXEC:
			kqueue_dup(fd, ret);
			socket_tables_dup(fd, ret);
			break;
	}

	return ret;
}
