#include <darling/emulation/xnu_syscall/bsd/impl/unistd/renameatx_np.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

extern char* strcpy(char* dst, const char* src);

// XNU's flags (sys/stdio.h)
#define XNU_RENAME_SECLUDE 0x1
#define XNU_RENAME_SWAP 0x2
#define XNU_RENAME_EXCL 0x4

// Linux's renameat2 flags
#define LINUX_RENAME_NOREPLACE 0x1
#define LINUX_RENAME_EXCHANGE 0x2

// renameatx_np(2): renameat with RENAME_SWAP (exchange the two, atomically) or RENAME_EXCL (fail if `to` exists),
// which Linux's renameat2 has as RENAME_EXCHANGE and RENAME_NOREPLACE. RENAME_SECLUDE (fail if `from` is open
// elsewhere) has no Linux equivalent.
long sys_renameatx_np(int oldfd, const char* oldpath, int newfd, const char* newpath, unsigned int flags)
{
	int ret, linux_flags = 0;
	struct vchroot_expand_args vc, vc2;

	if (flags & ~(XNU_RENAME_SECLUDE | XNU_RENAME_SWAP | XNU_RENAME_EXCL))
		return -EINVAL;
	if ((flags & (XNU_RENAME_SWAP | XNU_RENAME_EXCL)) == (XNU_RENAME_SWAP | XNU_RENAME_EXCL))
		return -EINVAL;
	if (flags & XNU_RENAME_SECLUDE)
		return -ENOTSUP;
	if (flags & XNU_RENAME_SWAP)
		linux_flags |= LINUX_RENAME_EXCHANGE;
	if (flags & XNU_RENAME_EXCL)
		linux_flags |= LINUX_RENAME_NOREPLACE;

	vc.flags = 0;
	vc.dfd = atfd(oldfd);
	strcpy(vc.path, oldpath);

	vc2.flags = 0;
	vc2.dfd = atfd(newfd);
	strcpy(vc2.path, newpath);

	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = vchroot_expand(&vc2);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_renameat2, vc.dfd, vc.path, vc2.dfd, vc2.path, linux_flags);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	return 0;
}
