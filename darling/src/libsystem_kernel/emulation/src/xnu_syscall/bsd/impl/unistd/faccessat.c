#include <darling/emulation/xnu_syscall/bsd/impl/unistd/faccessat.h>

#include <sys/errno.h>

#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/linux_path.h>

extern char* strcpy(char* dst, const char* src);

long sys_faccessat(int fd, const char* filename, int amode, int flag)
{
	int ret;

	struct vchroot_expand_args vc;
	int linux_flags;

	if (!filename)
		return -EFAULT;

	vc.flags = (flag & BSD_AT_SYMLINK_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(fd);

	strcpy(vc.path, filename);

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	linux_flags = atflags_bsd_to_linux(flag);
	if (linux_flags == LINUX_AT_INVALID)
		return -EINVAL;
	// faccessat2()'s flags (Linux's AT_REMOVEDIR is its AT_EACCESS); AT_EACCESS, which atflags_bsd_to_linux() drops,
	// checks as the effective ids. With AT_SYMLINK_NOFOLLOW Linux answers by a link's own mode, which is always 0777:
	// XNU's link modes come from its umask (usually 0755), so XNU may refuse writing a link Linux allows.
	linux_flags &= LINUX_AT_SYMLINK_NOFOLLOW | LINUX_AT_EMPTY_PATH;
	if (flag & BSD_AT_EACCESS)
		linux_flags |= LINUX_AT_EACCESS;

	return linux_path_access(vc.dfd, vc.path, amode, linux_flags);
}
