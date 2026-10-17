#include <darling/emulation/xnu_syscall/bsd/impl/unistd/access_extended.h>

#include <sys/errno.h>
#include <sys/mount.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/linux_path.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getuid.h>

extern void* memcpy(void* dst, const void* src, __SIZE_TYPE__ len);

// access_extended(2), syscall 284: Libc's accessx_np checks access to a list of files in one call.
// CoreServicesInternal's _URLReplaceObject asks it before every atomic replace, so without it
// lsd could never save its database. This follows xnu-12377.121.6 (iOS 26):
// access_extended() and access1() in bsd/vfs/vfs_syscalls.c, and how vnode_authorize() answers them
// (vnode_authorize_callback_int, vnode_attr_authorize_internal, vnode_authorize_checkimmutable,
// vnode_authorize_delete and vnode_authorize_simple in bsd/vfs/vfs_subr.c) for a file without an ACL.
//
// The identity is the Linux process's real uid and groups (linux_real_uid() says why not Darling's own uid), as XNU
// checks the real identity here and as Darling's access() does. Linux's faccessat() without AT_EACCESS answers the posix
// permission questions, groups and POSIX ACLs included. What comes before them in XNU is decided here, in XNU's order:
// the read-only and noexec mounts, chattr's immutable and append-only flags (XNU's IMMUTABLE and APPEND), the
// superuser's rules, and deleting (the parent, its sticky bit).
//
// The table is read where it is: the caller's memory is this process's, so XNU's copy-in has nothing to cross. An
// unreadable table or results array faults, as Darling's system calls do, where XNU answers EFAULT.

// bsd/sys/unistd.h
struct xnu_accessx_descriptor
{
	unsigned int ad_name_offset;
	int ad_flags;
	int ad_pad[2];
};
#define XNU_ACCESSX_MAX_DESCRIPTORS 100
#define XNU_ACCESSX_MAX_TABLESIZE (16 * 1024)

#define XNU_X_OK 0x1
#define XNU_W_OK 0x2
#define XNU_R_OK 0x4
#define XNU_ACCESS_EXTENDED_MASK 0x003ffe00 // _READ_OK (1<<9) to _CHOWN_OK (1<<21)
#define XNU_DELETE_OK (1 << 12)

// bsd/sys/kauth.h; an extended access bit is its right shifted left by 8 (access1: action = uflags >> 8)
#define KAUTH_VNODE_READ_DATA (1U << 1)
#define KAUTH_VNODE_WRITE_DATA (1U << 2)
#define KAUTH_VNODE_ADD_FILE KAUTH_VNODE_WRITE_DATA
#define KAUTH_VNODE_EXECUTE (1U << 3)
#define KAUTH_VNODE_DELETE (1U << 4)
#define KAUTH_VNODE_APPEND_DATA (1U << 5)
#define KAUTH_VNODE_ADD_SUBDIRECTORY KAUTH_VNODE_APPEND_DATA
#define KAUTH_VNODE_DELETE_CHILD (1U << 6)
#define KAUTH_VNODE_WRITE_ATTRIBUTES (1U << 8)
#define KAUTH_VNODE_READ_EXTATTRIBUTES (1U << 9)
#define KAUTH_VNODE_WRITE_EXTATTRIBUTES (1U << 10)
#define KAUTH_VNODE_WRITE_SECURITY (1U << 12)
#define KAUTH_VNODE_TAKE_OWNERSHIP (1U << 13)
#define KAUTH_VNODE_CHANGE_OWNER KAUTH_VNODE_TAKE_OWNERSHIP
#define KAUTH_VNODE_WRITE_RIGHTS                                                                                  \
	(KAUTH_VNODE_ADD_FILE | KAUTH_VNODE_ADD_SUBDIRECTORY | KAUTH_VNODE_DELETE_CHILD | KAUTH_VNODE_WRITE_DATA |    \
	 KAUTH_VNODE_APPEND_DATA | KAUTH_VNODE_DELETE | KAUTH_VNODE_WRITE_ATTRIBUTES | KAUTH_VNODE_WRITE_EXTATTRIBUTES | \
	 KAUTH_VNODE_WRITE_SECURITY | KAUTH_VNODE_TAKE_OWNERSHIP)

// namei(): a path of MAXPATHLEN bytes or more is ENAMETOOLONG
#define XNU_MAXPATHLEN 1024

// what a lookup found: the object, and its parent when a descriptor wants to delete it
struct accessx_node
{
	struct vchroot_expand_args vc; // vc.path: the object's Linux path
	struct linux_stat st;
	char parent[VCHROOT_PATH_MAX];
	struct linux_stat pst;
};

// the descriptor i of the table, which needn't be aligned
static void accessx_descriptor(const char* table, size_t i, struct xnu_accessx_descriptor* d)
{
	memcpy(d, table + i * sizeof(*d), sizeof(*d));
}

// namei(FOLLOW, and WANTPARENT for a delete) of the name at offset in the table: 0, or the lookup's (positive) XNU
// errno. XNU forces the table's last byte to NUL, so a name ends there at the latest.
static int accessx_lookup(const char* table, size_t size, size_t offset, int wantparent, struct accessx_node* node)
{
	const char* name = table + offset;
	size_t len = 0, max = size - 1 - offset;
	long ret;

	while (len < max && name[len] != '\0')
		len++;
	if (len >= XNU_MAXPATHLEN)
		return ENAMETOOLONG;

	node->vc.flags = VCHROOT_FOLLOW;
	node->vc.dfd = atfd(BSD_AT_FDCWD);
	memcpy(node->vc.path, name, len);
	node->vc.path[len] = '\0';
	ret = vchroot_expand(&node->vc);
	if (ret < 0)
		return -errno_linux_to_bsd(ret);

	// the lookup itself, with the real ids' search permissions; vchroot_expand() doesn't check any
	ret = linux_path_access(LINUX_AT_FDCWD, node->vc.path, 0, 0);
	if (!ret)
		ret = linux_path_stat(LINUX_AT_FDCWD, node->vc.path, 0, &node->st);
	if (!ret && wantparent)
		ret = linux_path_parent(node->vc.path, node->parent);
	if (!ret && wantparent)
		ret = linux_path_stat(LINUX_AT_FDCWD, node->parent, 0, &node->pst);
	return -ret;
}

// vnode_authorize_checkimmutable(): an immutable file allows no write rights, and an append-only one only appending
// (adding entries, to a directory) and its extended attributes. Writing to a socket, a FIFO or a device changes no file
// system data. 0 or EPERM. Linux's statx() reports chattr's +i and +a; where it can't, nothing is either.
static int accessx_immutable(const char* path, unsigned int type, unsigned int rights)
{
	struct linux_path_statx sx;
	unsigned int append_rights;

	if (type == LINUX_S_IFSOCK || type == LINUX_S_IFIFO || type == LINUX_S_IFBLK || type == LINUX_S_IFCHR)
		rights &= ~KAUTH_VNODE_WRITE_DATA;
	if (!(rights & KAUTH_VNODE_WRITE_RIGHTS))
		return 0;
	if (linux_path_statx(LINUX_AT_FDCWD, path, 0, 0, &sx) < 0)
		return 0;

	if (sx.attributes & LINUX_STATX_ATTR_IMMUTABLE)
		return EPERM;
	if (type == LINUX_S_IFDIR)
		append_rights = KAUTH_VNODE_ADD_FILE | KAUTH_VNODE_ADD_SUBDIRECTORY | KAUTH_VNODE_WRITE_EXTATTRIBUTES;
	else
		append_rights = KAUTH_VNODE_APPEND_DATA | KAUTH_VNODE_WRITE_EXTATTRIBUTES;
	if ((sx.attributes & LINUX_STATX_ATTR_APPEND) && (rights & KAUTH_VNODE_WRITE_RIGHTS & ~append_rights))
		return EPERM;
	return 0;
}

// vnode_authorize_simple()'s posix mode bits for rights
static int accessx_posix_mode(unsigned int rights)
{
	int mode = 0;

	if (rights & (KAUTH_VNODE_READ_DATA | KAUTH_VNODE_READ_EXTATTRIBUTES))
		mode |= XNU_R_OK;
	if (rights & (KAUTH_VNODE_WRITE_DATA | KAUTH_VNODE_APPEND_DATA | KAUTH_VNODE_DELETE_CHILD |
			KAUTH_VNODE_WRITE_ATTRIBUTES | KAUTH_VNODE_WRITE_EXTATTRIBUTES))
		mode |= XNU_W_OK;
	if (rights & KAUTH_VNODE_EXECUTE)
		mode |= XNU_X_OK;
	return mode;
}

// access1(): one descriptor's flags against what the lookup found: 0, or a (positive) XNU errno
static int accessx_check(const struct accessx_node* node, int uflags)
{
	const unsigned int type = node->st.st_mode & LINUX_S_IFMT;
	const int isdir = type == LINUX_S_IFDIR, isreg = type == LINUX_S_IFREG, islnk = type == LINUX_S_IFLNK;
	unsigned int rights;
	int uid, owner, mode, ret;

	if (!(uflags & XNU_ACCESS_EXTENDED_MASK))
	{
		rights = 0;
		if (uflags & XNU_R_OK)
			rights |= KAUTH_VNODE_READ_DATA;
		if (uflags & XNU_W_OK)
			rights |= isdir ? (KAUTH_VNODE_ADD_FILE | KAUTH_VNODE_ADD_SUBDIRECTORY) : KAUTH_VNODE_WRITE_DATA;
		if (uflags & XNU_X_OK)
			rights |= KAUTH_VNODE_EXECUTE;
	}
	else
		rights = (unsigned int) uflags >> 8;

	// "action == 0 means only check for existence"
	if (rights == 0)
		return 0;

	// vnode_authorize_callback_int: the mount's read-only and noexec flags come first
	if (rights & (KAUTH_VNODE_WRITE_RIGHTS | KAUTH_VNODE_EXECUTE))
	{
		struct linux_statfs64 sfs;
		unsigned int mnt_flags;
#ifdef __NR_statfs64
		ret = LINUX_SYSCALL3(__NR_statfs64, node->vc.path, sizeof(sfs), &sfs);
#else
		ret = LINUX_SYSCALL2(__NR_statfs, node->vc.path, &sfs);
#endif
		if (ret < 0)
			return -errno_linux_to_bsd(ret);
		mnt_flags = statfs_flags_linux_to_bsd(sfs.f_flags);
		if ((rights & KAUTH_VNODE_WRITE_RIGHTS) && (mnt_flags & MNT_RDONLY) &&
			(isreg || isdir || islnk || (rights & (KAUTH_VNODE_DELETE | KAUTH_VNODE_DELETE_CHILD))))
			return EROFS;
		if ((rights & KAUTH_VNODE_EXECUTE) && isreg && (mnt_flags & MNT_NOEXEC))
			return EACCES;
	}

	// vnode_attr_authorize_internal: immutability, the file's and, to delete it, its directory's, for everyone
	ret = accessx_immutable(node->vc.path, type, rights);
	if (!ret && (rights & KAUTH_VNODE_DELETE))
		ret = accessx_immutable(node->parent, LINUX_S_IFDIR, KAUTH_VNODE_DELETE_CHILD);
	if (ret)
		return ret;

	uid = linux_real_uid();
	if (uid == 0)
	{
		// the superuser: anything but executing a regular file that no one may execute. Linux is still asked about
		// reading and writing, which XNU's superuser always may: Linux's own root may not, in a user namespace, for
		// a file whose owner isn't mapped into it.
		if ((rights & KAUTH_VNODE_EXECUTE) && isreg && !(node->st.st_mode & 0111))
			return EPERM;
		mode = accessx_posix_mode(rights) & (XNU_R_OK | XNU_W_OK);
		return mode ? -linux_path_access(LINUX_AT_FDCWD, node->vc.path, mode, 0) : 0;
	}

	// vnode_authorize_delete, no ACL: the parent must be writable, and its sticky bit leaves a file to
	// the file's and the directory's owners
	if (rights & KAUTH_VNODE_DELETE)
	{
		ret = -linux_path_access(LINUX_AT_FDCWD, node->parent, XNU_W_OK, 0);
		if (ret)
			return ret;
		if ((node->pst.st_mode & LINUX_S_ISVTX) && node->st.st_uid != uid && node->pst.st_uid != uid)
			return EACCES;
		rights &= ~KAUTH_VNODE_DELETE;
	}

	// vnode_authorize_simple, no ACL: the owner may change the permissions and attributes; no one else may
	// change the permissions or the owner; the rest is the posix mode
	owner = node->st.st_uid == uid;
	if (owner)
		rights &= ~(KAUTH_VNODE_WRITE_SECURITY | KAUTH_VNODE_WRITE_ATTRIBUTES);
	if ((rights & KAUTH_VNODE_TAKE_OWNERSHIP) && (rights & KAUTH_VNODE_WRITE_SECURITY))
		rights &= ~KAUTH_VNODE_WRITE_SECURITY;
	if (rights & (KAUTH_VNODE_CHANGE_OWNER | KAUTH_VNODE_WRITE_SECURITY))
		return EACCES;

	mode = accessx_posix_mode(rights);
	return mode ? -linux_path_access(LINUX_AT_FDCWD, node->vc.path, mode, 0) : 0;
}

// entries: the descriptors, then the names they point to (by offset from entries; 0 is the previous
// descriptor's name); results: an errno for each descriptor. uid, the uid to check as, is ignored, as XNU
// ignores it ("XXX: Need to support the check-as uid argument").
long sys_access_extended(const void* entries, size_t size, int* results, unsigned int uid)
{
	const char* table = entries;
	struct xnu_accessx_descriptor d, next;
	int result[XNU_ACCESSX_MAX_DESCRIPTORS];
	struct accessx_node node;
	size_t desc_max, desc_actual, i, j;
	int error, wantdelete;

	(void) uid;

	if (size > XNU_ACCESSX_MAX_TABLESIZE)
		return -ENOMEM;
	if (size < sizeof(struct xnu_accessx_descriptor) + 2)
		return -EINVAL;
	if (!entries)
		return -EFAULT;

	// Count the descriptors: they end where the lowest-addressed name begins.
	desc_max = (size - 2) / sizeof(struct xnu_accessx_descriptor);
	desc_actual = desc_max;
	for (i = 0; i < desc_actual; i++)
	{
		accessx_descriptor(table, i, &d);
		j = d.ad_name_offset / sizeof(struct xnu_accessx_descriptor);

		// past the table, or into a descriptor (other than a reference to the previous name)
		if (j > desc_max || (j != 0 && j <= i))
			return -EINVAL;
		if (d.ad_name_offset >= size)
			return -EINVAL;
		// 0: the previous descriptor's name, which the first descriptor doesn't have
		if (j == 0)
		{
			if (i == 0)
				return -EINVAL;
			continue;
		}
		if (j < desc_actual)
			desc_actual = j;
	}
	if (desc_actual > XNU_ACCESSX_MAX_DESCRIPTORS)
		return -ENOMEM;

	error = 0;
	for (i = 0; i < desc_actual; i++)
	{
		accessx_descriptor(table, i, &d);
		if (d.ad_name_offset != 0)
		{
			// the parent is needed if this name's descriptors (this one and the 0s after it) delete
			wantdelete = d.ad_flags & XNU_DELETE_OK;
			for (j = i + 1; j < desc_actual; j++)
			{
				accessx_descriptor(table, j, &next);
				if (next.ad_name_offset != 0)
					break;
				if (next.ad_flags & XNU_DELETE_OK)
					wantdelete = 1;
			}
			error = accessx_lookup(table, size, d.ad_name_offset, wantdelete, &node);
		}

		// A lookup that failed on the file answers its descriptors; any other failure is the call's.
		switch (error)
		{
			case ENOENT:
			case EACCES:
			case EPERM:
			case ENOTDIR:
				result[i] = error;
				break;
			case 0:
				result[i] = accessx_check(&node, d.ad_flags);
				break;
			default:
				return -error;
		}
	}

	// copyout(): the results are written only once every name has been looked up
	if (!results)
		return -EFAULT;
	memcpy(results, result, desc_actual * sizeof(int));
	return 0;
}
