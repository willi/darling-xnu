#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

extern char *strcpy(char *dest, const char *src);
extern void *memcpy(void *dest, const void *src, __SIZE_TYPE__ n);
extern int do_linux_fchmodat(int fd, const char* path, int mode, int flag);

// setattrlist(), fsetattrlist() and setattrlistat(): as XNU, any attribute XNU can set is accepted. The times of
// modification and access, the permissions and the owner are set; the rest have nowhere to go on a Linux file system
// (creation and backup times, Finder information, flags, ACLs, protection classes, a volume's name) and are ignored.

#define ATTR_BIT_MAP_COUNT 5

#define ATTR_CMN_SCRIPT 0x00000100
#define ATTR_CMN_CRTIME 0x00000200
#define ATTR_CMN_MODTIME 0x00000400
#define ATTR_CMN_CHGTIME 0x00000800
#define ATTR_CMN_ACCTIME 0x00001000
#define ATTR_CMN_BKUPTIME 0x00002000
#define ATTR_CMN_FNDRINFO 0x00004000
#define ATTR_CMN_OWNERID 0x00008000
#define ATTR_CMN_GRPID 0x00010000
#define ATTR_CMN_ACCESSMASK 0x00020000

// what XNU can set (sys/attr.h)
#define ATTR_CMN_SETMASK 0x51C7FF00
#define ATTR_CMN_VOLSETMASK 0x00006700
#define ATTR_VOL_SETMASK 0x80002000
#define ATTR_DIR_SETMASK 0x00000000
#define ATTR_FILE_SETMASK 0x00000020
#define ATTR_FORK_SETMASK 0x00000000

#define FSOPT_NOFOLLOW 1

#define LINUX_UTIME_OMIT	((1l << 30) - 2l)

struct timespec
{
	long tv_sec;
	long tv_nsec;
};

long
FUNC_NAME(int fd,

#if HAS_PATH
const char* path,
#endif

struct xnu_attrlist* alist, void *attributeBuffer, __SIZE_TYPE__ bufferSize, unsigned long options)
{
	int rv;
	const char* next;
	int linux_at_flag = 0;
	struct timespec times[2] = { { 0, LINUX_UTIME_OMIT }, { 0, LINUX_UTIME_OMIT } };
	uint32_t owner = -1, group = -1;

	if (options & FSOPT_NOFOLLOW)
		linux_at_flag |= LINUX_AT_SYMLINK_NOFOLLOW;

	if (!alist)
		return -EFAULT;

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

	if (alist->bitmapcount != ATTR_BIT_MAP_COUNT)
		return -EINVAL;
	if (alist->volattr)
	{
		if ((alist->volattr & ~ATTR_VOL_SETMASK) || (alist->commonattr & ~ATTR_CMN_VOLSETMASK) || alist->fileattr ||
				alist->forkattr)
			return -EINVAL;
	}
	else if ((alist->commonattr & ~ATTR_CMN_SETMASK) || (alist->fileattr & ~ATTR_FILE_SETMASK) ||
			(alist->dirattr & ~ATTR_DIR_SETMASK) || (alist->forkattr & ~ATTR_FORK_SETMASK))
		return -EINVAL;

	// the values, in the order of their bits; only those up to the permissions are needed
	next = (const char*) attributeBuffer;
	if (alist->commonattr & ATTR_CMN_SCRIPT)
		next += sizeof(uint32_t);
	if (alist->commonattr & ATTR_CMN_CRTIME)
		next += sizeof(struct timespec);
	if (alist->commonattr & ATTR_CMN_MODTIME)
	{
		memcpy(&times[1], next, sizeof(struct timespec));
		next += sizeof(struct timespec);
	}
	if (alist->commonattr & ATTR_CMN_CHGTIME)
		next += sizeof(struct timespec);
	if (alist->commonattr & ATTR_CMN_ACCTIME)
	{
		memcpy(&times[0], next, sizeof(struct timespec));
		next += sizeof(struct timespec);
	}
	if (alist->commonattr & ATTR_CMN_BKUPTIME)
		next += sizeof(struct timespec);
	if (alist->commonattr & ATTR_CMN_FNDRINFO)
		next += 32;
	if (alist->commonattr & ATTR_CMN_OWNERID)
	{
		memcpy(&owner, next, sizeof(owner));
		next += sizeof(uint32_t);
	}
	if (alist->commonattr & ATTR_CMN_GRPID)
	{
		memcpy(&group, next, sizeof(group));
		next += sizeof(uint32_t);
	}

	if (alist->commonattr & (ATTR_CMN_OWNERID | ATTR_CMN_GRPID))
	{
#if HAS_PATH
		rv = LINUX_SYSCALL(__NR_fchownat, LINUX_AT_FDCWD, vc.path, owner, group, linux_at_flag);
#else
		rv = LINUX_SYSCALL(__NR_fchown, fd, owner, group);
#endif
		if (rv < 0)
			return errno_linux_to_bsd(rv);
	}
	if (alist->commonattr & ATTR_CMN_ACCESSMASK)
	{
		uint32_t perms;
		memcpy(&perms, next, sizeof(perms));
#if HAS_PATH
		rv = do_linux_fchmodat(LINUX_AT_FDCWD, vc.path, perms, linux_at_flag);
#else
		rv = LINUX_SYSCALL(__NR_fchmod, fd, perms);
#endif
		if (rv < 0)
			return errno_linux_to_bsd(rv);
	}
	if (alist->commonattr & (ATTR_CMN_MODTIME | ATTR_CMN_ACCTIME))
	{
#if HAS_PATH
		rv = LINUX_SYSCALL(__NR_utimensat, LINUX_AT_FDCWD, vc.path, times, linux_at_flag);
#else
		rv = LINUX_SYSCALL(__NR_utimensat, fd, 0, times, linux_at_flag);
#endif
		if (rv < 0)
			return errno_linux_to_bsd(rv);
	}

	return 0;
}
