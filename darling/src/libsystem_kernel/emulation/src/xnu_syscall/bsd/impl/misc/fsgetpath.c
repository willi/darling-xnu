#include <darling/emulation/xnu_syscall/bsd/impl/misc/fsgetpath.h>

#include <stdint.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/duct_errno.h>
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
// Object ID 2 is the volume's root, as XNU's VFS_ROOT(), unless the Linux file system has another object there.
//
// Binds of one file system into the process's mount namespace are one volume (one device): a search starts at the
// mount fsid_t's second word hints at, then the others, in mountinfo's order. A bind's own objects are found in it as
// long as binds of one file system don't overlap: otherwise another process may be given the other bind's path to an
// object (one that's read-only, say).
//
// Linux opens a file by inode number only with a file system's own handle and CAP_DAC_READ_SEARCH
// (open_by_handle_at()), so the path is:
// - the one this process last looked the object up by (fileid_cache.h), if it still leads there;
// - on ext4, with that capability (root's, in a container), open_by_handle_at() with a handle of the inode number and
//   any generation: no such inode (ESTALE) is ENOENT at once, and an object whose path Linux knows (a directory, a
//   file looked up lately) is found by it;
// - else found by searching from the roots of the mounts of the object's device: into directories on that device (on
//   btrfs, into its subvolumes too), symlinks not followed, unreadable directories passed over. Each search is logged
//   (kprintf, "fsgetpath: searched"), with what it took.
// What wasn't there is remembered for a while (fileid_cache_absent()).
//
// That finds the objects of a volume when they report the device of a mount (fsgetpath_volume_searchable(), which
// decides getattrlist()'s VOL_CAP_FMT_PATH_FROM_ID). Most file systems' do. An overlay's do when its layers are on one
// file system, or with xino; otherwise its files report their layers' devices, which no mount is of (Darling's own
// prefix, over the image and /root), and fsgetpath() finds them only by a lookup this process made. A btrfs subvolume
// with no mount of its own has a device of its own too, found by crossing into subvolumes from the file system's mounts.

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
#define LINUX_OVERLAYFS_SUPER_MAGIC 0x794c7630
#define LINUX_BTRFS_SUPER_MAGIC 0x9123683E
// a btrfs subvolume's root directory's inode
#define BTRFS_FIRST_FREE_OBJECTID 256
// how many directories of an overlay are looked into for a file, to see which device its files report
#define OVERLAY_SAMPLE_DIRS 64
#define LINUX_EXT4_SUPER_MAGIC 0xEF53
// include/linux/exportfs.h: a 32-bit inode number and its generation, which ext4 takes 0 of as any
#define LINUX_FILEID_INO32_GEN 1
#define LINUX_O_PATH 010000000

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
	// the volume (and as a hint, the Linux mount: mounts_fsid()) and the object
	unsigned long long dev, mount_id, objid;
	// on btrfs, from mounts of other devices: into subvolumes; whether one of dev was found
	int subvolumes, found_dev;
	// directories the search read
	long dirs;
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

static long fs_type(int fd)
{
	struct linux_statfs64 fs;
#ifdef __NR_fstatfs64
	long ret = LINUX_SYSCALL3(__NR_fstatfs64, fd, sizeof(fs), &fs);
#else
	long ret = LINUX_SYSCALL2(__NR_fstatfs, fd, &fs);
#endif
	return ret < 0 ? 0 : (unsigned int) fs.f_type;
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
	if (LINUX_SYSCALL(__NR_fstatat64, fd, "", &st, LINUX_AT_EMPTY_PATH) == 0 && (uint32_t) st.st_dev == s->dev &&
		st.st_ino == s->objid)
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
		int is_dir = (st.st_mode & LINUX_S_IFMT) == LINUX_S_IFDIR;
		if ((uint32_t) st.st_dev == s->dev && is_dir)
			s->found_dev = 1;
		// a subvolume's ID 2, its root, as a volume's (it has no inode 2)
		if ((uint32_t) st.st_dev == s->dev && (st.st_ino == s->objid ||
			(s->subvolumes && s->objid == ROOT_OBJID && is_dir && st.st_ino == BTRFS_FIRST_FREE_OBJECTID)))
		{
			int end = append(s, l->pathlen, d->d_name);
			for (; depth >= 0; depth--)
				close_internal(s->levels[depth].fd);
			return end < 0 ? -ENOSPC : 1;
		}
		// into a directory on the same device, or on btrfs into a subvolume; one that can't be read (EACCES) has
		// nothing to find
		if (!is_dir || ((uint32_t) st.st_dev != s->dev && !s->subvolumes) || depth + 1 >= DEPTH_MAX)
			continue;
		int end = append(s, l->pathlen, d->d_name);
		if (end < 0)
			continue;
		int sub = LINUX_SYSCALL(__NR_openat, l->fd, d->d_name,
			LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0);
		if (sub < 0)
			continue;
		if (s->subvolumes && fs_type(sub) != LINUX_BTRFS_SUPER_MAGIC)
		{
			close_internal(sub);
			continue;
		}
		depth++;
		s->dirs++;
		s->levels[depth] = (struct level) { .fd = sub, .pathlen = end };
	}
	return 0;
}

// whether the object is on the file system mounted at mount_point, by open_by_handle_at(): 1 and its path in s->path,
// 2 when it is but Linux doesn't know a path to it through this mount, 0 when no such object is there, or -1 when that
// can't be told (not ext4, no CAP_DAC_READ_SEARCH)
static int probe_at(struct search* s, const char* mount_point)
{
	struct
	{
		uint32_t handle_bytes;
		int handle_type;
		uint32_t ino, generation;
	} handle = { 8, LINUX_FILEID_INO32_GEN, (uint32_t) s->objid, 0 };
	struct linux_stat st;
	char proc[32];

	if (s->objid > 0xFFFFFFFFull)
		return -1;
	// not O_PATH: open_by_handle_at() wants a descriptor it can use (EBADF otherwise)
	int mfd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, mount_point, LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_CLOEXEC, 0);
	if (mfd < 0)
		return -1;
	if (fs_type(mfd) != LINUX_EXT4_SUPER_MAGIC)
	{
		close_internal(mfd);
		return -1;
	}
	int fd = LINUX_SYSCALL(__NR_open_by_handle_at, mfd, &handle, LINUX_O_PATH | LINUX_O_CLOEXEC);
	close_internal(mfd);
	if (fd == -LINUX_ESTALE || fd == -LINUX_ENOENT)
		return 0;
	if (fd < 0)
		return -1;

	__simple_sprintf(proc, "/proc/self/fd/%d", fd);
	long n = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, proc, s->path, sizeof(s->path) - 1);
	close_internal(fd);
	if (n <= 0 || s->path[0] != '/')
		return 2;
	s->path[n] = '\0';
	// a path Linux has for it, if it leads there (a disconnected one is just "/", or a name)
	if (LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, s->path, &st, LINUX_AT_SYMLINK_NOFOLLOW) < 0 ||
		(uint32_t) st.st_dev != s->dev || st.st_ino != s->objid)
		return 2;
	return 1;
}

// probe_at() through each of the device's mounts, until one has a path to it
struct probe
{
	struct search* s;
	int there;
};

static int probe_root(const char* mount_point, void* ctx)
{
	struct probe* p = ctx;
	p->there = probe_at(p->s, mount_point);
	// a path, or not there (one file system: the same answer through any mount), or can't tell
	return p->there != 2;
}

static int probe(struct search* s)
{
	struct probe p = { .s = s, .there = -1 };
	mounts_each_root_from(s->dev, s->mount_id, probe_root, &p);
	return p.there;
}

static long long now_ms(void)
{
	struct { long tv_sec, tv_nsec; } ts;
	if (LINUX_SYSCALL(__NR_clock_gettime, 1 /* CLOCK_MONOTONIC */, &ts) < 0)
		return 0;
	return ts.tv_sec * 1000ll + ts.tv_nsec / 1000000;
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

// searches the volume's mounts, the hinted one first, logging what it took: as search_mount()
static long search(struct search* s)
{
	long long t0 = now_ms();
	s->dirs = 0;
	long ret = mounts_each_root_from(s->dev, s->mount_id, search_mount, s);
	__simple_kprintf("fsgetpath: searched device %llx for %llu: %s, %ld directories, %lld ms\n", s->dev, s->objid,
		ret > 0 ? "found" : ret == 0 ? "not there" : "error", s->dirs, now_ms() - t0);
	return ret;
}

// ID 2, with the volume's root in s->path: XNU's volumes have their root there, but a Linux file system may have
// another object at 2 (tmpfs numbers its root 1, and the first object made in it 2). That one when there is one, else
// the root.
static long find_root(struct search* s)
{
	struct linux_stat st;
	if (LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, s->path, &st, 0) == 0 && st.st_ino == ROOT_OBJID)
		return 0;
	int fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, s->path, LINUX_O_PATH | LINUX_O_CLOEXEC, 0);
	long type = fd < 0 ? 0 : fs_type(fd);
	if (fd >= 0)
		close_internal(fd);
	// ext4's inode 2 is its root, above any directory a mount can have as its root: this one stands in for it
	if (type == LINUX_EXT4_SUPER_MAGIC || fileid_cache_absent(s->dev, ROOT_OBJID))
		return 0;

	unsigned i;
	for (i = 0; s->path[i]; i++)
		s->seen[i] = s->path[i];
	s->seen[i] = '\0';
	long ret = search(s);
	if (ret > 0)
	{
		fileid_cache_note(s->dev, s->objid, s->path);
		return 0;
	}
	fileid_cache_note_absent(s->dev, ROOT_OBJID);
	for (i = 0; s->seen[i]; i++)
		s->path[i] = s->seen[i];
	s->path[i] = '\0';
	return ret < 0 ? ret : 0;
}

// the Linux path of (dev, objid) into s->path: 0, or a negative XNU errno
static long find_object(struct search* s)
{
	if (fileid_cache_find(s->dev, s->objid, s->path, sizeof(s->path)))
		return 0;

	// the volume's root: the hinted mount's, or the first
	long ret = mounts_each_root_from(s->dev, s->mount_id, first_root, s->path);
	if (ret < 0)
		return ret;
	if (ret == 0)
	{
		// no mount of the device: a btrfs subvolume's, from the file system's mounts; or, as XNU when no mount has the
		// volfs ID, ENOTSUP
		s->subvolumes = 1;
		ret = mounts_each_of_type("btrfs", search_mount, s);
		if (ret < 0)
			return ret;
		if (ret == 0)
			return s->found_dev ? -ENOENT : -ENOTSUP;
		fileid_cache_note(s->dev, s->objid, s->path);
		return 0;
	}
	if (s->objid == ROOT_OBJID)
		return find_root(s);
	if (fileid_cache_absent(s->dev, s->objid))
		return -ENOENT;

	int there = probe(s);
	if (there == 0)
	{
		fileid_cache_note_absent(s->dev, s->objid);
		return -ENOENT;
	}
	if (there == 1)
	{
		fileid_cache_note(s->dev, s->objid, s->path);
		return 0;
	}

	ret = search(s);
	if (ret < 0)
		return ret;
	if (ret == 0)
	{
		fileid_cache_note_absent(s->dev, s->objid);
		return -ENOENT;
	}
	fileid_cache_note(s->dev, s->objid, s->path);
	return 0;
}

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

	// the search's state is more than a thread's stack should hold
	unsigned long map_size = (sizeof(struct search) + 4095) & ~4095ul;
	struct search* s = (struct search*) LINUX_SYSCALL6(__NR_mmap, 0, map_size, LINUX_PROT_READ | LINUX_PROT_WRITE,
		LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
	if ((unsigned long) s > (unsigned long) -4096)
		return -ENOMEM;
	s->dev = dev;
	s->mount_id = mount_id;
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

static int any_root(const char* mount_point, void* ctx)
{
	return 1;
}

// whether the overlay whose root s->path is has its files report its device: by the first file found under it
static int overlay_reports_its_device(struct search* s)
{
	struct linux_stat root, st;
	int depth = 0, dirs = 1, ret = 0;

	int fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, s->path, LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_CLOEXEC, 0);
	if (fd < 0)
		return 0;
	if (LINUX_SYSCALL(__NR_fstatat64, fd, "", &root, LINUX_AT_EMPTY_PATH) < 0)
	{
		close_internal(fd);
		return 0;
	}
	s->levels[0] = (struct level) { .fd = fd };
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
		if (LINUX_SYSCALL(__NR_fstatat64, l->fd, d->d_name, &st, LINUX_AT_SYMLINK_NOFOLLOW) < 0)
			continue;
		if ((st.st_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
		{
			ret = st.st_dev == root.st_dev;
			break;
		}
		if (st.st_dev != root.st_dev || depth + 1 >= DEPTH_MAX || dirs >= OVERLAY_SAMPLE_DIRS)
			continue;
		int sub = LINUX_SYSCALL(__NR_openat, l->fd, d->d_name,
			LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_NOFOLLOW | LINUX_O_CLOEXEC, 0);
		if (sub < 0)
			continue;
		dirs++;
		depth++;
		s->levels[depth] = (struct level) { .fd = sub };
	}
	for (; depth >= 0; depth--)
		close_internal(s->levels[depth].fd);
	return ret;
}

int fsgetpath_volume_searchable(int fd)
{
	struct linux_stat st;
	if (LINUX_SYSCALL(__NR_fstatat64, fd, "", &st, LINUX_AT_EMPTY_PATH) < 0)
		return 0;
	long type = fs_type(fd);
	if (type == LINUX_BTRFS_SUPER_MAGIC)
		return 1;

	unsigned long map_size = (sizeof(struct search) + 4095) & ~4095ul;
	struct search* s = (struct search*) LINUX_SYSCALL6(__NR_mmap, 0, map_size, LINUX_PROT_READ | LINUX_PROT_WRITE,
		LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
	if ((unsigned long) s > (unsigned long) -4096)
		return 0;
	// objects on a device no mount is of (an overlay's file) can't be searched for
	int ret = mounts_each_root((uint32_t) st.st_dev, first_root, s->path) > 0;
	if (ret && type == LINUX_OVERLAYFS_SUPER_MAGIC)
		ret = overlay_reports_its_device(s);
	LINUX_SYSCALL(__NR_munmap, s, map_size);
	return ret;
}
