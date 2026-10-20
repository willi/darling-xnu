#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/openat.h>

#include <sys/fcntl.h>

#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/open.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

#include <darlingserver/rpc.h>

#ifndef LINUX_O_PATH
#	define LINUX_O_PATH 010000000
#endif
#ifndef XNU_O_EVTONLY
#	define XNU_O_EVTONLY 0x8000
#endif
#ifndef LINUX_ELOOP
#	define LINUX_ELOOP 40
#endif

#ifndef O_NOFOLLOW
#	define O_NOFOLLOW 0x0100
#endif
#ifndef O_CLOEXEC
#	define O_CLOEXEC 0x1000000
#endif
#ifndef O_DIRECTORY
#	define O_DIRECTORY 0x100000
#endif

extern int strcmp(const char *s1, const char *s2);
extern char* strcpy(char* dst, const char* src);

long sys_openat(int fd, const char* filename, int flags, unsigned int mode)
{
	CANCELATION_POINT();
	return openat_body(fd, filename, flags, mode, 1);
}

long sys_openat_nocancel(int fd, const char* filename, int flags, unsigned int mode)
{
	return openat_body(fd, filename, flags, mode, 0);
}

long openat_body(int fd, const char* filename, int flags, unsigned int mode, int cp)
{
	int ret, linux_flags;
	if (!filename)
		return -EFAULT;

	linux_flags = oflags_bsd_to_linux(flags);

	if (sizeof(void*) == 4)
	{
		linux_flags |= LINUX_O_LARGEFILE;
	}

	// XNU /dev/random behaves like Linux /dev/urandom
	if (strcmp(filename, "/dev/random") == 0)
		filename = "/dev/urandom";
	// Expected by launchd and CF
	else if (strcmp(filename, "/dev/autofs_nowait") == 0)
		filename = "/dev/null";
	else if (strcmp(filename, "/dev/console") == 0) {
		// redirect console output to darlingserver
		int err = dserver_rpc_console_open(&ret);
		if (err < 0) {
			__simple_printf("dserver_rpc_console_open failed internally: %d", err);
			__simple_abort();
		}
		if (err > 0) {
			ret = errno_linux_to_bsd(-err);
		}
		return ret;
	}

	struct vchroot_expand_args vc;
	vc.flags = (flags & BSD_O_SYMLINK || flags & BSD_O_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(fd);

	strcpy(vc.path, filename);
	ret = vchroot_expand(&vc);
	if (ret < 0) {
		return errno_linux_to_bsd(ret);
	}

	// when we're given O_SYMLINK, `oflags_bsd_to_linux` translates it into
	// O_NOFOLLOW and O_PATH
	// this is the only way to open the symlink itself on Linux
	// unfortunately, this presents additional challenges
	// only a select few Linux syscalls support O_PATH descriptors, which means
	// that for other syscalls, we either have to check for this and use an
	// `l` variant (e.g. `llistxattr` instead of `listxatrr`) or we're screwed
	//
	// so, as XNU, O_SYMLINK only changes anything when the object is a symlink:
	// anything else is opened as without it (O_NOFOLLOW fails with ELOOP on a
	// symlink, and only then is the O_PATH descriptor needed). MobileInstallation
	// opens the directories it copies with O_SYMLINK and lists them with
	// getattrlistbulk(), which an O_PATH descriptor can't do.
	//
	// an event-only descriptor (O_EVTONLY, for watching the object) needs no access to it: that stays O_PATH
	if ((flags & BSD_O_SYMLINK) && !(flags & XNU_O_EVTONLY))
	{
		ret = LINUX_SYSCALL_MAYBE_CP(cp, __NR_openat, vc.dfd, vc.path, linux_flags & ~LINUX_O_PATH, mode);
		if (ret != -LINUX_ELOOP)
			return ret < 0 ? errno_linux_to_bsd(ret) : ret;
	}

	ret = LINUX_SYSCALL_MAYBE_CP(cp, __NR_openat, vc.dfd, vc.path, linux_flags, mode);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
