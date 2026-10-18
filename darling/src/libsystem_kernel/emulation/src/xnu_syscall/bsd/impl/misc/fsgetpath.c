#include <darling/emulation/xnu_syscall/bsd/impl/misc/fsgetpath.h>

#include <stdint.h>
#include <sys/errno.h>

#include <darling/emulation/xnu_syscall/bsd/helper/misc/fileid.h>

// fsgetpath() and fsgetpath_ext(): the path of a file system object, by its volume's ID (statfs()'s f_fsid, ATTR_CMN_FSID:
// the device it is on, under Darling) and its object ID (ATTR_CMN_FILEID, st_ino), found by fileid_find(). Their
// arguments, errors and result follow XNU's fsgetpath_extended() and fsgetpath_internal() (apple-oss-distributions/xnu,
// bsd/vfs/vfs_syscalls.c): options other than FSOPT_NOFIRMLINKPATH and FSOPT_ISREALFSID are EINVAL; then a buffer of 0
// or more than MAXLONGPATHLEN (8192 since xnu-10063, macOS 14; a page before) is EINVAL; an ID no volume has is
// ENOTSUP; an object the volume doesn't have is ENOENT; a path that doesn't fit the buffer is ENOSPC (build_path(),
// bsd/vfs/vfs_cache.c), and only then a NULL buffer EFAULT; and the result is the path's length counting its
// terminating NUL.

// sys/syslimits.h, as xnu-12377's fsgetpath_extended() checks it. Darling's own paths are shorter (VCHROOT_PATH_MAX
// as Linux has them, 19 bytes more outside the prefix): a longer one is ENOSPC.
#define XNU_MAXLONGPATHLEN 8192
#define FSOPT_NOFIRMLINKPATH 0x00000080
#define FSOPT_ISREALFSID 0x00000200

long sys_fsgetpath_ext(char* buf, unsigned long size, void* fsid, unsigned long long objid, unsigned int options)
{
	if (options & ~(FSOPT_NOFIRMLINKPATH | FSOPT_ISREALFSID))
		return -EINVAL;
	if (!fsid)
		return -EFAULT;
	// fsid_t's first word is the volume (XNU's volfs ID): under Darling, the device as a 32-bit number; the second, the
	// Linux mount it was handed out for (mounts_fsid())
	unsigned long long dev = ((const uint32_t*) fsid)[0], mount_id = ((const uint32_t*) fsid)[1];
	if (size == 0 || size > XNU_MAXLONGPATHLEN)
		return -EINVAL;

	long ret = fileid_find(dev, mount_id, objid, buf, size);
	return ret > 0 && !buf ? -EFAULT : ret;
}

long sys_fsgetpath(char* buf, unsigned long size, void* fsid, unsigned long long objid)
{
	return sys_fsgetpath_ext(buf, size, fsid, objid, 0);
}
