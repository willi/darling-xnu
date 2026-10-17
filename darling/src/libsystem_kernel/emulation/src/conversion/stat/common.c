// This is needed so stat is not stat64
#define _DARWIN_NO_64_BIT_INODE

// NOTE: in this case, platform-include/sys/stat.h is used
#include <sys/stat.h>
#include <sys/mount.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getuid.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getgid.h>

void stat_linux_to_bsd(const struct linux_stat* lstat, struct stat* stat)
{
	stat->st_dev = lstat->st_dev;
	stat->st_mode = lstat->st_mode;
	stat->st_nlink = lstat->st_nlink;
	stat->st_ino = lstat->st_ino;
	stat->st_uid = /*lstat->st_uid*/ sys_getuid();
	stat->st_gid = /*lstat->st_gid*/ sys_getgid();
	stat->st_rdev = lstat->st_rdev;
	stat->st_size = lstat->st_size;
	stat->st_blksize = lstat->st_blksize;
	stat->st_blocks = lstat->st_blocks;
	stat->st_atimespec.tv_sec = lstat->st_atime;
	stat->st_atimespec.tv_nsec = lstat->st_atime_nsec;
	stat->st_mtimespec.tv_sec = lstat->st_mtime;
	stat->st_mtimespec.tv_nsec = lstat->st_mtime_nsec;
	stat->st_ctimespec.tv_sec = lstat->st_ctime;
	stat->st_ctimespec.tv_nsec = lstat->st_ctime_nsec;
	stat->st_flags = 0;
}

void stat_linux_to_bsd64(const struct linux_stat* lstat, struct stat64* stat)
{
	stat->st_dev = lstat->st_dev;
	stat->st_mode = lstat->st_mode;
	stat->st_nlink = lstat->st_nlink;
	stat->st_ino = lstat->st_ino;
	stat->st_uid = /*lstat->st_uid*/ sys_getuid();
	stat->st_gid = /*lstat->st_gid*/ sys_getgid();
	stat->st_rdev = lstat->st_rdev;
	stat->st_size = lstat->st_size;
	stat->st_blksize = lstat->st_blksize;
	stat->st_blocks = lstat->st_blocks;
	stat->st_atimespec.tv_sec = lstat->st_atime;
	stat->st_atimespec.tv_nsec = lstat->st_atime_nsec;
	stat->st_mtimespec.tv_sec = lstat->st_mtime;
	stat->st_mtimespec.tv_nsec = lstat->st_mtime_nsec;
	stat->st_ctimespec.tv_sec = lstat->st_ctime;
	stat->st_ctimespec.tv_nsec = lstat->st_ctime_nsec;
	stat->st_flags = 0;
}

// statvfs(3)'s ST_* flags, which Linux's statfs() reports in f_flags
#define LINUX_ST_RDONLY 0x0001
#define LINUX_ST_NOSUID 0x0002
#define LINUX_ST_NODEV 0x0004
#define LINUX_ST_NOEXEC 0x0008
#define LINUX_ST_SYNCHRONOUS 0x0010
#define LINUX_ST_NOATIME 0x0400
// f_flags is valid (Linux 2.6.36 and later)
#define LINUX_ST_VALID 0x0020

// Linux's ST_* bits as XNU's MNT_* ones (MNT_LOCAL is mounts.c's)
static unsigned int statfs_flags_linux_to_bsd(long lflags)
{
	unsigned int flags = 0;

	if (!(lflags & LINUX_ST_VALID))
		return 0;

	if (lflags & LINUX_ST_RDONLY)
		flags |= MNT_RDONLY;
	if (lflags & LINUX_ST_NOSUID)
		flags |= MNT_NOSUID;
	if (lflags & LINUX_ST_NODEV)
		flags |= MNT_NODEV;
	if (lflags & LINUX_ST_NOEXEC)
		flags |= MNT_NOEXEC;
	if (lflags & LINUX_ST_SYNCHRONOUS)
		flags |= MNT_SYNCHRONOUS;
	if (lflags & LINUX_ST_NOATIME)
		flags |= MNT_NOATIME;
	return flags;
}

void statfs_linux_to_bsd64(const struct linux_statfs64* lstat, struct bsd_statfs64* stat)
{
	stat->f_type = lstat->f_type;
	stat->f_bsize = lstat->f_bsize;
	stat->f_blocks = lstat->f_blocks;
	stat->f_bfree = lstat->f_bfree;
	stat->f_bavail = lstat->f_bavail;
	stat->f_files = lstat->f_files;
	stat->f_ffree = lstat->f_ffree;
	stat->f_fsid = lstat->f_fsid;
	stat->f_flags = statfs_flags_linux_to_bsd(lstat->f_flags);
}
