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
#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fileid_cache.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/fsgetpath.h>

// getattrlist(), fgetattrlist() and getattrlistat(): the attributes of an object, or of the volume it is on, packed as
// attrlist_pack.h says.

#ifndef __NR_fstatat64
#	define __NR_fstatat64 __NR_newfstatat
#endif

#define LINUX_O_PATH 010000000
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
	char proc_path[32], fullpath[XNU_MAXPATHLEN], name[256];
	struct attrlist_object obj;
};

#define ATTR_CMN_OBJID 0x00000020
#define ATTR_CMN_PAROBJID 0x00000080
#define ATTR_CMN_FILEID 0x02000000
#define ATTR_CMN_FULLPATH 0x08000000
#define ATTR_CMN_PARENTID 0x40000000
#define ATTR_DIR_MOUNTSTATUS 0x00000004
#define ATTR_CMNEXT_RELPATH 0x00000004
#define ATTR_CMNEXT_NOFIRMLINKPATH 0x00000020

// the directory it's in and its path are only looked up for the attributes that need them: they cost path walks, and
// a path can be too long for the process to be given
static int needs_parent(const struct xnu_attrlist* al)
{
	return (al->commonattr & (ATTR_CMN_PAROBJID | ATTR_CMN_PARENTID)) || (al->dirattr & ATTR_DIR_MOUNTSTATUS);
}

static int needs_path(const struct xnu_attrlist* al, unsigned long options)
{
	return (al->commonattr & (ATTR_CMN_NAME | ATTR_CMN_FULLPATH)) ||
		((options & FSOPT_ATTR_CMN_EXTENDED) && (al->forkattr & (ATTR_CMNEXT_RELPATH | ATTR_CMNEXT_NOFIRMLINKPATH)));
}

// the mount the object is on, for its fsid_t's second word
static int needs_mount(const struct xnu_attrlist* al, unsigned long options)
{
	return (al->commonattr & ATTR_CMN_FSID) || ((options & FSOPT_ATTR_CMN_EXTENDED) && (al->forkattr & ATTR_CMNEXT_REALFSID));
}

static __attribute__((noinline)) long describe(int objfd, const struct xnu_attrlist* al, unsigned long options,
	struct object* o)
{
	struct linux_stat* st = &o->st;
	char linux_path[4096];
	const char* fullpath = 0;
	int rv, linked = 0;

	rv = LINUX_SYSCALL(__NR_fstatat64, objfd, "", st, LINUX_AT_EMPTY_PATH | LINUX_AT_SYMLINK_NOFOLLOW);
	if (rv < 0)
		return errno_linux_to_bsd(rv);

	// the object by a path that works for any file descriptor, even of a file that was since removed
	__simple_sprintf(o->proc_path, "/proc/self/fd/%d", objfd);
	o->parent = *st;
	o->name[0] = '\0';

	if (needs_parent(al) || needs_path(al, options))
	{
		rv = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, o->proc_path, linux_path, sizeof(linux_path) - 1);
		linked = rv > 0 && linux_path[0] == '/';
		if (linked)
			linux_path[rv] = '\0';
	}

	if (needs_path(al, options))
	{
		// the path as the process sees it (inside the prefix), with every symlink resolved: what F_GETPATH returns.
		// Without it (a path too long for the process), there's no full path, and the name is Linux's.
		const char* from = 0;
		if (fdpath(objfd, o->fullpath, sizeof(o->fullpath)) >= 0)
			from = fullpath = o->fullpath;
		else if (linked)
			from = linux_path;
		if (from)
		{
			const char* name = last_slash((char*) from);
			name = (name && name[1]) ? name + 1 : from;
			for (rv = 0; name[rv] && rv < (int) sizeof(o->name) - 1; rv++)
				o->name[rv] = name[rv];
			o->name[rv] = '\0';
		}
	}

	// the directory it's in; a file system's root, or a removed file, stands in for its own
	if (needs_parent(al) && linked)
	{
		char* slash = last_slash(linux_path);
		if (slash == linux_path)
			slash++;
		*slash = '\0';
		if (LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, linux_path, &o->parent, 0) < 0)
			o->parent = *st;
	}

	o->obj = (struct attrlist_object) { .st = st, .parent = &o->parent, .dirfd = LINUX_AT_FDCWD, .lookup = o->proc_path,
		.name = o->name, .fullpath = fullpath };
	if (needs_mount(al, options))
		mounts_id(objfd, "", LINUX_AT_EMPTY_PATH, &o->obj.mount_id);
	return 0;
}

// linux_path: the absolute Linux path objfd was opened by, or NULL
static long pack_object(int objfd, const char* linux_path, const struct xnu_attrlist* alist, unsigned long options,
	char* out)
{
	struct object o;
	long rv = describe(objfd, alist, options, &o);

	if (rv < 0)
		return rv;
	// an ID handed out by path, which fsgetpath() can then answer without a search
	if (linux_path && (alist->commonattr & (ATTR_CMN_OBJID | ATTR_CMN_FILEID)))
		fileid_cache_note((unsigned int) o.st.st_dev, o.st.st_ino, linux_path);
	rv = attrlist_check(alist, options, (o.st.st_mode & LINUX_S_IFMT) == LINUX_S_IFDIR);
	if (rv < 0)
		return rv;
	return attrlist_pack(alist, options, &o.obj, out);
}

// the volume the object open as objfd is on: its attributes, and the common ones of its root. Not inlined: its locals
// are only on the stack of a call that asks for a volume.
static __attribute__((noinline)) long pack_volume(int objfd, const struct xnu_attrlist* alist, unsigned long options,
	char* out)
{
	struct bsd_statfs64 fs;
	struct object root;
	const char* name;
	long rv;

	rv = attrlist_check_volume(alist, options);
	if (rv < 0)
		return rv;
	rv = mounts_fstatfs(objfd, &fs);
	if (rv < 0)
		return rv;

	int rootfd = mounts_open_root(&fs);
	if (rootfd < 0)
		return rootfd;
	rv = describe(rootfd, alist, options, &root);
	close_internal(rootfd);
	if (rv < 0)
		return rv;

	name = mounts_volume_name(&fs);
	root.obj.name = name;

	// a few lookups: only for the capabilities that report it
	struct attrlist_volume vol = { .fs = &fs, .name = name,
		.path_from_id = (alist->volattr & ATTR_VOL_CAPABILITIES) && fsgetpath_volume_searchable(objfd) };
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
#if HAS_PATH
		const char* linux_path = vc.path;
#else
		const char* linux_path = 0;
#endif
		rv = alist->volattr ? pack_volume(objfd, alist, options, out) : pack_object(objfd, linux_path, alist, options, out);
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
