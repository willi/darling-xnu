#include <darling/emulation/xnu_syscall/bsd/impl/misc/clonefile.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/fcntl/fcntl.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/linux_path.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>

extern char* strcpy(char* dst, const char* src);
extern char* strcat(char* dst, const char* src);
extern __SIZE_TYPE__ strlen(const char* str);
extern int strcmp(const char* a, const char* b);
extern void* memcpy(void* dst, const void* src, __SIZE_TYPE__ len);
extern void* memmove(void* dst, const void* src, __SIZE_TYPE__ len);
extern int __simple_sprintf(char* buf, const char* format, ...);

// clonefileat(2) and fclonefileat(2) make a copy-on-write clone, which only APFS can. No Linux file system
// is presented as one: getattrlist's ATTR_VOL_CAPABILITIES leaves out VOL_CAP_INT_CLONE. XNU answers that
// with ENOTSUP from VNOP_CLONEFILE. Biome's bm_replace_file() depends on that errno: it copies on ENOTSUP,
// retries another name on EEXIST, and fails on anything else (Darling's ENOSYS: "fclonefileat() failed").
// copyfile(COPYFILE_CLONE) copies after any failure. First, though, XNU checks the arguments, the source and
// the target, and those errors come first here too. This follows clonefileat(), fclonefileat() and
// clonefile_internal() in xnu-12377.121.6 bsd/vfs/vfs_syscalls.c, and namei()'s NAMEI_NOFOLLOW_ANY and
// NAMEI_RESOLVE_BENEATH in bsd/vfs/vfs_lookup.c.

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

// bsd/sys/errno.h; Darling's copy predates it
#define XNU_ENOTCAPABLE 107
// bsd/sys/param.h
#define XNU_MAXSYMLINKS 32
// namei(): copyinstr() of a path of MAXPATHLEN bytes or more is ENAMETOOLONG
#define XNU_MAXPATHLEN 1024

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

struct clone_walk
{
	struct vchroot_expand_args vc;
	char rest[XNU_MAXPATHLEN]; // what's left of the path: namei() keeps it in MAXPATHLEN
	char link[XNU_MAXPATHLEN];
	char done[VCHROOT_PATH_MAX]; // the directories walked so far, relative to dfd
};

// NAMEI_NOFOLLOW_ANY and NAMEI_RESOLVE_BENEATH, which vchroot_expand() doesn't know: a symbolic link anywhere on the path
// (at its end too, when followed, or followed by a slash) is ELOOP; and the path may not leave dfd's directory: an
// absolute path, a ".." above it, or a symbolic link to an absolute path is ENOTCAPABLE. The walk goes over the path a
// component at a time, looking each one up without following it, and stops at the first one it can't look up: the
// lookup proper then answers. 0, or a negative XNU errno. Only a call with one of the flags walks.
static __attribute__((noinline)) long clone_walk(int dfd, const char* path, int follow, uint32_t flags)
{
	struct clone_walk w;
	struct linux_stat st;
	const int beneath = flags & XNU_CLONE_RESOLVE_BENEATH, noany = flags & XNU_CLONE_NOFOLLOW_ANY;
	__SIZE_TYPE__ len, done_len, sep, k, rest_len;
	char *p, *end;
	int depth = 0, links = 0, last;
	long ret;

	// namei_setup_at_dir(): a relative path's directory is checked before any of its components
	if (path[0] != '/' && dfd != LINUX_AT_FDCWD)
	{
		ret = linux_path_stat(dfd, "", LINUX_AT_EMPTY_PATH, &st);
		if (ret < 0)
			return ret;
		if ((st.st_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
			return -ENOTDIR;
	}
	if (beneath && path[0] == '/')
		return -XNU_ENOTCAPABLE;

	strcpy(w.rest, path);
	strcpy(w.done, path[0] == '/' ? "/" : "");
	p = w.rest;
	for (;;)
	{
		while (*p == '/')
			p++;
		if (*p == '\0')
			return 0;
		for (end = p; *end && *end != '/'; end++)
			;
		len = end - p;
		for (k = 0; end[k] == '/'; k++)
			;
		last = end[k] == '\0';

		if (len == 1 && p[0] == '.')
		{
			p = end;
			continue;
		}
		done_len = strlen(w.done);
		sep = done_len && w.done[done_len - 1] != '/';
		if (len == 2 && p[0] == '.' && p[1] == '.')
		{
			if (beneath && depth == 0)
				return -XNU_ENOTCAPABLE;
			if (depth > 0)
			{
				while (done_len > 0 && w.done[done_len - 1] != '/')
					done_len--;
				while (done_len > 1 && w.done[done_len - 1] == '/')
					done_len--;
				w.done[done_len] = '\0';
				depth--;
			}
			else if (done_len + sep + 2 < sizeof(w.done))
				strcat(w.done, sep ? "/.." : "..");
			p = end;
			continue;
		}

		// the component, not followed
		if (done_len + sep + len >= sizeof(w.done))
			return -ENAMETOOLONG;
		strcpy(w.vc.path, w.done);
		if (sep)
			w.vc.path[done_len] = '/';
		memcpy(w.vc.path + done_len + sep, p, len);
		w.vc.path[done_len + sep + len] = '\0';
		w.vc.flags = 0;
		w.vc.dfd = dfd;
		if (vchroot_expand(&w.vc) < 0 || linux_path_stat(LINUX_AT_FDCWD, w.vc.path, LINUX_AT_SYMLINK_NOFOLLOW, &st) < 0)
			return 0;

		// a link is followed when it isn't the last component, when the lookup follows, and before a slash
		if ((st.st_mode & LINUX_S_IFMT) == LINUX_S_IFLNK && (!last || follow || k > 0))
		{
			if (noany || ++links > XNU_MAXSYMLINKS)
				return -ELOOP;
#ifdef __NR_readlink
			ret = LINUX_SYSCALL(__NR_readlink, w.vc.path, w.link, sizeof(w.link));
#else
			ret = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, w.vc.path, w.link, sizeof(w.link));
#endif
			if (ret < 0)
				return 0;
			// lookup_handle_symlink(): the link's text and the rest of the path within MAXPATHLEN
			rest_len = strlen(end);
			if (ret + rest_len + 1 > sizeof(w.rest))
				return -ENAMETOOLONG;
			// a symbolic link that restarts at the root
			if (ret > 0 && w.link[0] == '/')
				return -XNU_ENOTCAPABLE;
			// the link's text, then the rest of the path (from the slash after the link), from the link's directory
			memmove(w.rest + ret, end, rest_len + 1);
			memcpy(w.rest, w.link, ret);
			p = w.rest;
			continue;
		}
		if ((st.st_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
			return 0;
		if (sep)
			w.done[done_len] = '/';
		memcpy(w.done + done_len + sep, p, len);
		w.done[done_len + sep + len] = '\0';
		depth++;
		p = end;
	}
}

// The source as clonefile_internal() checks it, then the target's lookup, mount and directory permission. The source
// is src_path relative to src_dfd with src_flags (linux_path's), and real_path, a directory's resolved Linux path.
static long clone_to(int src_dfd, const char* src_path, int src_flags, const char* real_path, const struct linux_stat* src,
	int dst_fd, const char* dst, uint32_t flags)
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
	if (strlen(dst) >= XNU_MAXPATHLEN)
		return -ENAMETOOLONG;
	if (flags & (XNU_CLONE_NOFOLLOW_ANY | XNU_CLONE_RESOLVE_BENEATH))
	{
		ret = clone_walk(atfd(dst_fd), dst, !(flags & XNU_CLONE_NOFOLLOW), flags);
		if (ret < 0)
			return ret;
	}
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

	// the source's mount (a symbolic link's own: src_flags doesn't follow one)
	ret = clone_same_mount(src_dfd, src_path, src_flags, parent);
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
		ret = linux_path_access(src_dfd, src_path, XNU_R_OK, LINUX_AT_EACCESS | (src_flags & LINUX_AT_EMPTY_PATH));
	if (ret < 0)
		return ret;

	// VNOP_CLONEFILE
	return -ENOTSUP;
}

long sys_clonefileat(int src_fd, const char* src_path, int dest_fd, const char* dest_path, uint32_t flags)
{
	struct vchroot_expand_args vc;
	struct linux_stat st;
	const int nofollow = (flags & XNU_CLONE_NOFOLLOW) ? LINUX_AT_SYMLINK_NOFOLLOW : 0;
	long ret;

	if (flags & ~XNU_CLONE_FLAGS)
		return -EINVAL;
	if (!src_path)
		return -EFAULT;
	if (strlen(src_path) >= XNU_MAXPATHLEN)
		return -ENAMETOOLONG;

	if (flags & (XNU_CLONE_NOFOLLOW_ANY | XNU_CLONE_RESOLVE_BENEATH))
	{
		ret = clone_walk(atfd(src_fd), src_path, !nofollow, flags);
		if (ret < 0)
			return ret;
	}
	vc.flags = nofollow ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(src_fd);
	strcpy(vc.path, src_path);
	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = linux_path_stat(LINUX_AT_FDCWD, vc.path, nofollow, &st);
	if (ret < 0)
		return ret;

	return clone_to(LINUX_AT_FDCWD, vc.path, nofollow, vc.path, &st, dest_fd, dest_path, flags);
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

	// the open file itself (for a symbolic link opened O_SYMLINK, the link)
	ret = linux_path_stat(src_fd, "", LINUX_AT_EMPTY_PATH, &st);
	if (ret < 0)
		return ret;
	// a directory's path, to find its parent
	real_path[0] = '\0';
	if ((st.st_mode & LINUX_S_IFMT) == LINUX_S_IFDIR)
	{
		__simple_sprintf(path, "/proc/self/fd/%d", src_fd);
#ifdef __NR_readlink
		ret = LINUX_SYSCALL(__NR_readlink, path, real_path, sizeof(real_path) - 1);
#else
		ret = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, path, real_path, sizeof(real_path) - 1);
#endif
		if (ret < 0)
			return errno_linux_to_bsd(ret);
		real_path[ret] = '\0';
	}

	return clone_to(src_fd, "", LINUX_AT_EMPTY_PATH, real_path, &st, dest_fd, dest_path, flags);
}
