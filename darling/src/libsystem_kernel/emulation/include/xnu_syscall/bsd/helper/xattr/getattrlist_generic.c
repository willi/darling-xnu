#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fdpath.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/attrlist_pack.h>
#include <darling/emulation/xnu_syscall/bsd/impl/stat/fstatfs.h>

// getattrlist(), fgetattrlist() and getattrlistat(): the attributes of an object, or of the volume it is on, packed as
// attrlist_pack.h says.

#ifndef __NR_fstatat64
#	define __NR_fstatat64 __NR_newfstatat
#endif

#define LINUX_O_PATH 010000000
#define LINUX_S_IFMT 0170000
#define LINUX_S_IFDIR 0040000
#define XNU_MAXPATHLEN 1024

#define min(a,b) (((a) < (b)) ? (a) : (b))

extern void *memcpy(void *dest, const void *src, __SIZE_TYPE__ n);
extern void *memset(void *s, int c, __SIZE_TYPE__ n);
extern char *strcpy(char *dest, const char *src);

static char* last_slash(char* s)
{
	char* last = 0;
	for (; *s; s++)
		if (*s == '/')
			last = s;
	return last;
}

// what's known of the object open as objfd, without following it if it's a symlink
struct object
{
	struct linux_stat st, parent;
	char proc_path[32], fullpath[XNU_MAXPATHLEN];
	struct attrlist_object obj;
};

static long describe(int objfd, struct object* o)
{
	struct linux_stat* st = &o->st;
	char linux_path[4096];
	char* name;
	int rv;

	rv = LINUX_SYSCALL(__NR_fstatat64, objfd, "", st, LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW);
	if (rv < 0)
		return errno_linux_to_bsd(rv);

	// the object by a path that works for any file descriptor, even of a file that was since removed
	__simple_sprintf(o->proc_path, "/proc/self/fd/%d", objfd);

	// the directory it's in; a file system's root, or a removed file, stands in for its own
	o->parent = *st;
	rv = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, o->proc_path, linux_path, sizeof(linux_path) - 1);
	if (rv > 0 && linux_path[0] == '/')
	{
		char* slash;
		linux_path[rv] = '\0';
		slash = last_slash(linux_path);
		if (slash == linux_path)
			slash++;
		*slash = '\0';
		if (LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, linux_path, &o->parent, 0) < 0)
			o->parent = *st;
	}

	// the path as the process sees it (inside the prefix), with every symlink resolved: what F_GETPATH returns
	rv = fdpath(objfd, o->fullpath, sizeof(o->fullpath));
	if (rv < 0)
		return errno_linux_to_bsd(rv);
	name = last_slash(o->fullpath);
	name = (name && name[1]) ? name + 1 : o->fullpath;

	o->obj = (struct attrlist_object) { .st = st, .parent = &o->parent, .dirfd = LINUX_AT_FDCWD, .lookup = o->proc_path,
		.name = name, .fullpath = o->fullpath };
	return 0;
}

static long pack_object(int objfd, const struct xnu_attrlist* alist, unsigned long options, char* out)
{
	struct object o;
	long rv = describe(objfd, &o);

	if (rv < 0)
		return rv;
	rv = attrlist_check(alist, options, (o.st.st_mode & LINUX_S_IFMT) == LINUX_S_IFDIR);
	if (rv < 0)
		return rv;
	return attrlist_pack(alist, options, &o.obj, out);
}

// the volume the object open as objfd is on: its attributes, and the common ones of its root
static long pack_volume(int objfd, const struct xnu_attrlist* alist, unsigned long options, char* out)
{
	struct bsd_statfs64 fs;
	struct vchroot_expand_args vc;
	struct object root;
	const char* name;
	long rv;

	rv = attrlist_check_volume(alist, options);
	if (rv < 0)
		return rv;
	rv = sys_fstatfs64(objfd, &fs);
	if (rv < 0)
		return rv;
	if (!fs.f_mntonname[0])
		strcpy(fs.f_mntonname, "/");

	vc.flags = VCHROOT_FOLLOW;
	vc.dfd = LINUX_AT_FDCWD;
	strcpy(vc.path, fs.f_mntonname);
	rv = vchroot_expand(&vc);
	if (rv < 0)
		return rv;
	int rootfd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, vc.path, LINUX_O_PATH | LINUX_O_CLOEXEC, 0);
	if (rootfd < 0)
		return errno_linux_to_bsd(rootfd);
	rv = describe(rootfd, &root);
	close_internal(rootfd);
	if (rv < 0)
		return rv;

	// the root volume is named as a Mac's, which is where the iOS Simulator's file system is
	name = last_slash(fs.f_mntonname);
	name = (name && name[1]) ? name + 1 : "Macintosh HD";
	root.obj.name = name;

	struct attrlist_volume vol = { .fs = &fs, .name = name };
	return attrlist_pack_volume(alist, options, &root.obj, &vol, out);
}

long
FUNC_NAME(int fd,

#if HAS_PATH
const char* path,
#endif

struct xnu_attrlist* alist, void *attributeBuffer, __SIZE_TYPE__ bufferSize, unsigned long options)
{
	long rv;
	char out[ATTRLIST_PACK_MAX];
	uint32_t size;

	if (!alist)
		return -EFAULT;
	if (alist->bitmapcount != ATTR_BIT_MAP_COUNT)
		return -EINVAL;

#if HAS_PATH
	if (!path)
		return -EFAULT;

	struct vchroot_expand_args vc;
	vc.flags = (options & FSOPT_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc.dfd = atfd(fd);

	strcpy(vc.path, path);
	rv = vchroot_expand(&vc);

	if (rv < 0)
		return rv;
#endif

	{
#if HAS_PATH
		int objfd = LINUX_SYSCALL(__NR_openat, vc.dfd, vc.path,
				LINUX_O_PATH | LINUX_O_CLOEXEC | ((options & FSOPT_NOFOLLOW) ? LINUX_O_NOFOLLOW : 0), 0);
		if (objfd < 0)
			return errno_linux_to_bsd(objfd);
#else
		int objfd = fd;
#endif
		rv = alist->volattr ? pack_volume(objfd, alist, options, out) : pack_object(objfd, alist, options, out);
#if HAS_PATH
		close_internal(objfd);
#endif
		if (rv < 0)
			return rv;
		size = rv;
	}

	// as XNU: the length is of what was returned, or with FSOPT_REPORT_FULLSIZE of everything asked for (so the caller
	// can size its buffer)
	uint32_t length = (options & FSOPT_REPORT_FULLSIZE) ? size : min(bufferSize, size);
	memcpy(out, &length, sizeof(length));
	memcpy(attributeBuffer, out, min(bufferSize, size));

	return 0;
}
