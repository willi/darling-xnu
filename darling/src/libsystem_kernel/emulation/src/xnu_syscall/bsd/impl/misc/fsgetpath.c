#include <darling/emulation/xnu_syscall/bsd/impl/misc/fsgetpath.h>

#include <stdint.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/conversion/mman/duct_mman.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fileid_cache.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>

// fsgetpath() and fsgetpath_ext(): the path of a file system object, by its volume's ID (statfs()'s f_fsid, ATTR_CMN_FSID:
// the device it is on, under Darling) and its object ID (ATTR_CMN_FILEID, st_ino). Their arguments, errors and result
// follow XNU's fsgetpath_extended() and fsgetpath_internal() (apple-oss-distributions/xnu, bsd/vfs/vfs_syscalls.c):
// options other than FSOPT_NOFIRMLINKPATH and FSOPT_ISREALFSID are EINVAL; then a buffer of 0 or more than
// MAXLONGPATHLEN (8192 since xnu-10063, macOS 14; a page before) is EINVAL; an ID no volume has is ENOTSUP; an object
// the volume doesn't have is ENOENT; a path that doesn't fit the buffer is ENOSPC (build_path(), bsd/vfs/vfs_cache.c);
// and the result is the path's length counting its terminating NUL.
// Object ID 2 is the volume's root, as XNU's VFS_ROOT().
//
// Linux can't open a file by its inode number (open_by_handle_at() needs a file system's own handle, and
// CAP_DAC_READ_SEARCH), so the path is the one this process last looked the object up by (fileid_cache.h), if it still
// leads there, or else found by searching the volume's mounts: one device, symlinks not followed, unreadable
// directories passed over.
//
// A file on an overlay is on its layer's device, which no mount is of: fsgetpath() finds it only by a lookup this
// process made, which is why getattrlist() leaves VOL_CAP_FMT_PATH_FROM_ID off for an overlay.

#ifndef __NR_fstatat64
#	define __NR_fstatat64 __NR_newfstatat
#endif

// sys/syslimits.h, as xnu-12377's fsgetpath_extended() checks it. Darling's own paths are shorter (VCHROOT_PATH_MAX
// as Linux has them, 19 bytes more outside the prefix): a longer one is ENOSPC.
#define XNU_MAXLONGPATHLEN 8192
#define FSOPT_NOFIRMLINKPATH 0x00000080
#define FSOPT_ISREALFSID 0x00000200
#define ROOT_OBJID 2

#define LINUX_S_IFMT 0170000
#define LINUX_S_IFDIR 0040000
#define LINUX_DT_DIR 4
#define LINUX_DT_UNKNOWN 0

// the search: a directory per level being read, each with its own getdents64() buffer, in one mapping
#define DEPTH_MAX 128
#define DIRENTS_SIZE 2048

struct level
{
	int fd, len, pos, pathlen;
	char dirents[DIRENTS_SIZE];
};

struct search
{
	unsigned long long dev, objid;
	char path[VCHROOT_PATH_MAX]; // a Linux path; the one found, once found
	// the path found as the process sees it: outside the prefix, under /Volumes/SystemRoot, so longer than path can be
	char seen[VCHROOT_PATH_MAX + sizeof("/Volumes/SystemRoot")];
	struct level levels[DEPTH_MAX];
};

static int append(struct search* s, int at, const char* name)
{
	int n = 0;
	while (name[n])
		n++;
	if (at + 1 + n >= (int) sizeof(s->path))
		return -1;
	s->path[at] = '/';
	for (int i = 0; i <= n; i++)
		s->path[at + 1 + i] = name[i];
	return at + 1 + n;
}

// searches the mount at mount_point: 1 when s->path names the object, 0 when it isn't there, -ENOSPC when it is but its
// path is too long to give (as XNU's build_path())
static int search_mount(const char* mount_point, void* ctx)
{
	struct search* s = ctx;
	struct linux_stat st;
	int depth = 0, len = 0;

	while (mount_point[len] && len < (int) sizeof(s->path) - 1)
	{
		s->path[len] = mount_point[len];
		len++;
	}
	s->path[len] = '\0';

	int fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, s->path, LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_CLOEXEC, 0);
	if (fd < 0)
		return 0;
	if (LINUX_SYSCALL(__NR_fstatat64, fd, "", &st, LINUX_AT_EMPTY_PATH) == 0 && st.st_ino == s->objid)
	{
		close_internal(fd);
		return 1;
	}
	// "/" is a mount point's path when it is Linux's root
	if (len == 1)
		len = 0;
	s->levels[0] = (struct level) { .fd = fd, .pathlen = len };

	while (depth >= 0)
	{
		struct level* l = &s->levels[depth];
		if (l->pos >= l->len)
		{
			l->len = LINUX_SYSCALL(__NR_getdents64, l->fd, l->dirents, sizeof(l->dirents));
			l->pos = 0;
			if (l->len <= 0)
			{
				close_internal(l->fd);
				depth--;
				continue;
			}
		}
		struct linux_dirent64* d = (struct linux_dirent64*) &l->dirents[l->pos];
		l->pos += d->d_reclen;
		if (d->d_name[0] == '.' && (!d->d_name[1] || (d->d_name[1] == '.' && !d->d_name[2])))
			continue;
		if (d->d_ino != s->objid && d->d_type != LINUX_DT_DIR && d->d_type != LINUX_DT_UNKNOWN)
			continue;
		if (LINUX_SYSCALL(__NR_fstatat64, l->fd, d->d_name, &st, LINUX_AT_SYMLINK_NOFOLLOW) < 0)
			continue;
		if (st.st_ino == s->objid && (uint32_t) st.st_dev == s->dev)
		{
			int end = append(s, l->pathlen, d->d_name);
			for (; depth >= 0; depth--)
				close_internal(s->levels[depth].fd);
			return end < 0 ? -ENOSPC : 1;
		}
		// into a directory on the same device; one that can't be read (EACCES) has nothing to find
		if ((st.st_mode & LINUX_S_IFMT) != LINUX_S_IFDIR || (uint32_t) st.st_dev != s->dev || depth + 1 >= DEPTH_MAX)
			continue;
		int end = append(s, l->pathlen, d->d_name);
		if (end < 0)
			continue;
		int sub = LINUX_SYSCALL(__NR_openat, l->fd, d->d_name,
			LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0);
		if (sub < 0)
			continue;
		depth++;
		s->levels[depth] = (struct level) { .fd = sub, .pathlen = end };
	}
	return 0;
}

// the volume's first mount point, a Linux path
static int first_root(const char* mount_point, void* ctx)
{
	char* path = ctx;
	int i;
	for (i = 0; mount_point[i] && i < VCHROOT_PATH_MAX - 1; i++)
		path[i] = mount_point[i];
	path[i] = '\0';
	return 1;
}

// the Linux path of (dev, objid) into s->path: 0, or a negative XNU errno
static long find_object(struct search* s)
{
	if (s->objid != ROOT_OBJID && fileid_cache_find(s->dev, s->objid, s->path, sizeof(s->path)))
		return 0;

	// no mount of the volume: as XNU when no mount has the volfs ID
	long ret = mounts_each_root(s->dev, first_root, s->path);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return -ENOTSUP;
	if (s->objid == ROOT_OBJID)
		return 0;

	ret = mounts_each_root(s->dev, search_mount, s);
	if (ret < 0)
		return ret;
	if (ret == 0)
		return -ENOENT;
	fileid_cache_note(s->dev, s->objid, s->path);
	return 0;
}

long sys_fsgetpath_ext(char* buf, unsigned long size, void* fsid, unsigned long long objid, unsigned int options)
{
	if (options & ~(FSOPT_NOFIRMLINKPATH | FSOPT_ISREALFSID))
		return -EINVAL;
	if (!fsid)
		return -EFAULT;
	// fsid_t's first word is the volume (XNU's volfs ID): under Darling, the device as a 32-bit number
	unsigned long long dev = ((const uint32_t*) fsid)[0];
	if (size == 0 || size > XNU_MAXLONGPATHLEN)
		return -EINVAL;

	// the search's state is more than a thread's stack should hold
	unsigned long map_size = (sizeof(struct search) + 4095) & ~4095ul;
	struct search* s = (struct search*) LINUX_SYSCALL6(__NR_mmap, 0, map_size, LINUX_PROT_READ | LINUX_PROT_WRITE,
		LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
	if ((unsigned long) s > (unsigned long) -4096)
		return -ENOMEM;
	s->dev = dev;
	s->objid = objid;

	long ret = find_object(s);
	if (ret == 0)
	{
		// the path as the process sees it: under the prefix, or /Volumes/SystemRoot outside it
		vchroot_is_root(s->path); // vchroot_unexpand() needs the prefix, which this makes known
		if (vchroot_unexpand_into(s->path, s->seen, sizeof(s->seen)) < 0)
			ret = -ENOSPC;
	}
	if (ret == 0)
	{
		unsigned long length = 0;
		while (s->seen[length])
			length++;
		length++;
		if (length > size)
			ret = -ENOSPC;
		else if (!buf)
			ret = -EFAULT;
		else
		{
			for (unsigned long i = 0; i < length; i++)
				buf[i] = s->seen[i];
			ret = (long) length;
		}
	}
	LINUX_SYSCALL(__NR_munmap, s, map_size);
	return ret;
}

long sys_fsgetpath(char* buf, unsigned long size, void* fsid, unsigned long long objid)
{
	return sys_fsgetpath_ext(buf, size, fsid, objid, 0);
}
