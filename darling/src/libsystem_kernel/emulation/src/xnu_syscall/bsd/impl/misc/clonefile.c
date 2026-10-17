#include <darling/emulation/xnu_syscall/bsd/impl/misc/clonefile.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/linux_path.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>

extern char* strcpy(char* dst, const char* src);
extern int strcmp(const char* a, const char* b);
extern int __simple_sprintf(char* buf, const char* format, ...);

// clonefileat(2) and fclonefileat(2) make a copy-on-write clone, which only APFS can. No Linux file system
// is presented as one: getattrlist's ATTR_VOL_CAPABILITIES leaves out VOL_CAP_INT_CLONE. XNU answers that
// with ENOTSUP from VNOP_CLONEFILE, which callers take as "copy instead" (copyfile's COPYFILE_CLONE,
// Biome's bm_replace_file). First, though, XNU checks the arguments, the source and the target, and those
// errors (EEXIST above all, which callers retry on with another name) come first here too. This follows
// clonefileat(), fclonefileat() and clonefile_internal() in xnu-12377.121.6 bsd/vfs/vfs_syscalls.c.

// bsd/sys/clonefile.h
#define XNU_CLONE_NOFOLLOW 0x0001
#define XNU_CLONE_NOOWNERCOPY 0x0002
#define XNU_CLONE_ACL 0x0004
#define XNU_CLONE_NOFOLLOW_ANY 0x0008
#define XNU_CLONE_RESOLVE_BENEATH 0x0010
#define XNU_CLONE_FLAGS                                                                                  \
	(XNU_CLONE_NOFOLLOW | XNU_CLONE_NOOWNERCOPY | XNU_CLONE_ACL | XNU_CLONE_NOFOLLOW_ANY | \
	 XNU_CLONE_RESOLVE_BENEATH)

#define XNU_R_OK 0x4
#define XNU_W_OK 0x2

#define LINUX_F_GETFL 3
#define LINUX_O_ACCMODE 03
#define LINUX_O_WRONLY 01

// Whether two objects are on the same mount: 1 or 0, or a negative XNU errno. When Linux can't tell, they are: a
// missed EXDEV only means a copy where XNU would refuse, which copying callers then do anyway.
static long clone_same_mount(int adfd, const char* a, int aflags, const char* b)
{
	unsigned long long ida, idb;
	long ret = mounts_id(adfd, a, aflags, &ida);

	if (ret <= 0)
		return ret < 0 ? ret : 1;
	ret = mounts_id(LINUX_AT_FDCWD, b, 0, &idb);
	if (ret <= 0)
		return ret < 0 ? ret : 1;
	return ida == idb;
}

// A directory can't be cloned if it's the root or a mount point (vnode_isvroot, vnode_ismount): its
// parent is itself, or on another mount. 0, or a negative XNU errno. path is a resolved Linux path.
static long clone_dir_is_mount(const char* path)
{
	char parent[VCHROOT_PATH_MAX];
	long ret;

	ret = linux_path_parent(path, parent);
	if (ret < 0)
		return ret;
	if (strcmp(parent, path) == 0)
		return -EINVAL;
	ret = clone_same_mount(LINUX_AT_FDCWD, path, 0, parent);
	if (ret < 0)
		return ret;
	return ret ? 0 : -EINVAL;
}

// the source as clonefile_internal() checks it, and the target's lookup, mount and directory permission.
// src_path is where to check the source's permissions; real_path is its resolved Linux path.
static long clone_to(const char* src_path, const char* real_path, const struct linux_stat* src, int dst_fd,
	const char* dst, uint32_t flags)
{
	struct vchroot_expand_args vc;
	struct linux_stat st, dst_st;
	char parent[VCHROOT_PATH_MAX];
	unsigned int type = src->st_mode & LINUX_S_IFMT;
	long ret;

	// a regular file, a symbolic link, or a directory that isn't a volume's root or a mount point
	if (type == LINUX_S_IFDIR)
	{
		ret = clone_dir_is_mount(real_path);
		if (ret < 0)
			return ret;
	}
	else if (type != LINUX_S_IFREG && type != LINUX_S_IFLNK)
		return -EINVAL;

	if (!dst)
		return -EFAULT;
	vc.flags = (flags & XNU_CLONE_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(dst_fd);
	strcpy(vc.path, dst);
	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	// namei(CREATE): the target must not exist, and its directory must
	ret = linux_path_stat(LINUX_AT_FDCWD, vc.path, LINUX_AT_SYMLINK_NOFOLLOW, &dst_st);
	if (ret == 0)
		return -EEXIST;
	if (ret != -ENOENT)
		return ret;
	ret = linux_path_parent(vc.path, parent);
	if (!ret)
		ret = linux_path_stat(LINUX_AT_FDCWD, parent, 0, &st);
	if (ret < 0)
		return ret;
	if ((st.st_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
		return -ENOTDIR;

	// the source's mount: a symbolic link's is its directory's (Linux follows a link it's asked about)
	if (type == LINUX_S_IFLNK)
	{
		char link_dir[VCHROOT_PATH_MAX];
		ret = linux_path_parent(real_path, link_dir);
		if (ret < 0)
			return ret;
		ret = clone_same_mount(LINUX_AT_FDCWD, link_dir, 0, parent);
	}
	else
		ret = clone_same_mount(LINUX_AT_FDCWD, src_path, 0, parent);
	if (ret < 0)
		return ret;
	if (!ret)
		return -EXDEV;

	// KAUTH_VNODE_ADD_FILE (or ADD_SUBDIRECTORY) on the directory, then the source's read rights
	// (KAUTH_VNODE_GENERIC_READ_BITS: posix read, also when fclonefileat's open file has read the data). A
	// symbolic link's own permissions grant everything (Linux's are 0777), and asking Linux about a link would
	// ask about what it points to.
	ret = linux_path_access(LINUX_AT_FDCWD, parent, XNU_W_OK, LINUX_AT_EACCESS);
	if (!ret && type != LINUX_S_IFLNK)
		ret = linux_path_access(LINUX_AT_FDCWD, src_path, XNU_R_OK, LINUX_AT_EACCESS);
	if (ret < 0)
		return ret;

	// VNOP_CLONEFILE
	return -ENOTSUP;
}

long sys_clonefileat(int src_fd, const char* src_path, int dest_fd, const char* dest_path, uint32_t flags)
{
	struct vchroot_expand_args vc;
	struct linux_stat st;
	int ret;

	if (flags & ~XNU_CLONE_FLAGS)
		return -EINVAL;
	if (!src_path)
		return -EFAULT;

	vc.flags = (flags & XNU_CLONE_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(src_fd);
	strcpy(vc.path, src_path);
	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = linux_path_stat(LINUX_AT_FDCWD, vc.path, (flags & XNU_CLONE_NOFOLLOW) ? LINUX_AT_SYMLINK_NOFOLLOW : 0, &st);
	if (ret < 0)
		return ret;

	return clone_to(vc.path, vc.path, &st, dest_fd, dest_path, flags);
}

long sys_fclonefileat(int src_fd, int dest_fd, const char* dest_path, uint32_t flags)
{
	struct linux_statfs64 sfs;
	struct linux_stat st;
	char path[32], real_path[VCHROOT_PATH_MAX];
	long ret;
	int fl;

	if (flags & ~XNU_CLONE_FLAGS)
		return -EINVAL;

	// fp_getfvp(): EBADF for no file, ENOTSUP for one that isn't a vnode (a pipe, a socket, ...)
	fl = LINUX_SYSCALL(__NR_fcntl, src_fd, LINUX_F_GETFL);
	if (fl < 0)
		return errno_linux_to_bsd(fl);
#ifdef __NR_fstatfs64
	ret = LINUX_SYSCALL3(__NR_fstatfs64, src_fd, sizeof(sfs), &sfs);
#else
	ret = LINUX_SYSCALL2(__NR_fstatfs, src_fd, &sfs);
#endif
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	if (!mounts_fs_has_files(sfs.f_type))
		return -ENOTSUP;
	// opened for reading (FREAD). Darling opens a symbolic link for O_SYMLINK as O_PATH, which leaves the
	// access mode as it was given.
	if ((fl & LINUX_O_ACCMODE) == LINUX_O_WRONLY)
		return -EBADF;

	// the open file, through /proc, for its permissions; and where it is, for a directory's mount check
	__simple_sprintf(path, "/proc/self/fd/%d", src_fd);
	ret = linux_path_stat(LINUX_AT_FDCWD, path, 0, &st);
	if (ret < 0)
		return ret;
#ifdef __NR_readlink
	ret = LINUX_SYSCALL(__NR_readlink, path, real_path, sizeof(real_path) - 1);
#else
	ret = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, path, real_path, sizeof(real_path) - 1);
#endif
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	real_path[ret] = '\0';

	return clone_to(path, real_path, &st, dest_fd, dest_path, flags);
}
