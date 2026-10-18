#include <darling/emulation/xnu_syscall/bsd/impl/xattr/getattrlistbulk.h>

#include <stdint.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fileid_cache.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>
#include <darling/emulation/xnu_syscall/bsd/helper/xattr/attrlist_pack.h>

// getattrlistbulk(): the entries of a directory with the attributes of each, as XNU packs them. MobileInstallation's
// file system scanner enumerates the runtime's apps with it (lsd registers no system app without it, and SpringBoard
// then has no app to show).
//
// Each entry is packed as getattrlist() packs an object (attrlist_pack.h), padded to 8 bytes; the common extended
// attributes are always the fork attributes, as on XNU. The directory's offset advances past the entries returned.

#ifndef __NR_fstatat64
#	define __NR_fstatat64 __NR_newfstatat
#endif

#define LINUX_SEEK_SET 0
#define LINUX_SEEK_CUR 1
#define ATTR_CMN_OBJID 0x00000020
#define ATTR_CMN_FILEID 0x02000000
// the longest path fileid_cache_note() keeps
#define NOTED_PATH_MAX 1024


extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n);
extern void* memset(void* s, int c, __SIZE_TYPE__ n);

// an ID handed out for an entry of the directory at dir_path (a Linux path, or NULL), for fsgetpath()
static void note(const char* dir_path, const char* name, const struct linux_stat* st)
{
	char path[NOTED_PATH_MAX];
	int n = 0;
	if (!dir_path)
		return;
	for (; dir_path[n] && n < NOTED_PATH_MAX - 1; n++)
		path[n] = dir_path[n];
	if (n > 1 && n < NOTED_PATH_MAX - 1)
		path[n++] = '/';
	for (int i = 0; name[i] && n < NOTED_PATH_MAX - 1; i++)
		path[n++] = name[i];
	if (n >= NOTED_PATH_MAX - 1)
		return;
	path[n] = '\0';
	fileid_cache_note(st->st_dev, st->st_ino, path);
}

// one entry into out (ATTRLIST_PACK_MAX bytes); returns its size, or 0 to leave the entry out
static uint32_t pack_entry(int dirfd, const struct linux_stat* dir_st, unsigned long long mount_id, const char* dir_path,
	const char* name, const struct xnu_attrlist* al, uint64_t options, char* out)
{
	struct linux_stat st;
	uint32_t size;
	int err = LINUX_SYSCALL(__NR_fstatat64, dirfd, name, &st, LINUX_AT_SYMLINK_NOFOLLOW);

	if (err < 0)
	{
		// the entry is gone, or can't be looked at: XNU reports it with ATTR_CMN_ERROR, when that was asked for
		if (!(al->commonattr & ATTR_CMN_ERROR))
			return 0;
		size = attrlist_pack_error(al, name, -errno_linux_to_bsd(err), out);
	}
	else
	{
		struct attrlist_object obj = {
			.st = &st, .parent = dir_st, .dirfd = dirfd, .lookup = name, .name = name, .fullpath = 0,
			// the directory's: an entry another file system is mounted on is on another, but this is only a hint
			.mount_id = mount_id
		};
		size = attrlist_pack(al, options, &obj, out);
		note(dir_path, name, &st);
	}

	uint32_t padded = (size + 7) & ~7;
	memset(out + size, 0, padded - size);
	memcpy(out, &padded, sizeof(padded));
	return padded;
}

long sys_getattrlistbulk(int dirfd, struct xnu_attrlist* alist, void* attributeBuffer, __SIZE_TYPE__ bufferSize,
	uint64_t options)
{
	char dents[4096];
	char entry[ATTRLIST_PACK_MAX];
	struct linux_stat dir_st;
	char* out = attributeBuffer;
	__SIZE_TYPE__ used = 0;
	long count = 0;
	long long resume;
	int rv;

	if (!alist || !attributeBuffer)
		return -EFAULT;
	// as XNU: the returned attributes and the name are required, volume attributes can't be asked for, and the fork
	// attributes are the common extended ones
	options |= FSOPT_ATTR_CMN_EXTENDED;
	if ((alist->commonattr & (ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME)) != (ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_NAME) ||
		alist->volattr || attrlist_check(alist, options, 1) < 0 || attrlist_check(alist, options, 0) < 0)
		return -EINVAL;

	rv = LINUX_SYSCALL(__NR_fstat, dirfd, &dir_st);
	if (rv < 0)
		return errno_linux_to_bsd(rv);
	if ((dir_st.st_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
		return -ENOTDIR;

	// the directory's path, when IDs are handed out: enumerating a directory is where CFURL and LaunchServices get most
	// of theirs
	char dir_path[NOTED_PATH_MAX], proc[32];
	const char* noted_in = 0;
	if (alist->commonattr & (ATTR_CMN_OBJID | ATTR_CMN_FILEID))
	{
		__simple_sprintf(proc, "/proc/self/fd/%d", dirfd);
		int n = LINUX_SYSCALL(__NR_readlinkat, LINUX_AT_FDCWD, proc, dir_path, sizeof(dir_path) - 1);
		if (n > 0 && n < (int) sizeof(dir_path) - 1 && dir_path[0] == '/')
		{
			dir_path[n] = '\0';
			noted_in = dir_path;
		}
	}

	unsigned long long mount_id = 0;
	if ((alist->commonattr & ATTR_CMN_FSID) || (alist->forkattr & ATTR_CMNEXT_REALFSID))
		mounts_id(dirfd, "", LINUX_AT_EMPTY_PATH, &mount_id);

	resume = LINUX_SYSCALL(__NR_lseek, dirfd, 0, LINUX_SEEK_CUR);
	if (resume < 0)
		return errno_linux_to_bsd(resume);

	for (;;)
	{
		int n = LINUX_SYSCALL(__NR_getdents64, dirfd, dents, sizeof(dents));
		if (n < 0)
			return count ? count : errno_linux_to_bsd(n);
		if (n == 0)
			return count;

		for (int off = 0; off < n; off += ((struct linux_dirent64*) (dents + off))->d_reclen)
		{
			struct linux_dirent64* d = (struct linux_dirent64*) (dents + off);
			uint32_t size = 0;

			if (!(d->d_name[0] == '.' && (d->d_name[1] == 0 || (d->d_name[1] == '.' && d->d_name[2] == 0))))
				size = pack_entry(dirfd, &dir_st, mount_id, noted_in, d->d_name, alist, options, entry);
			if (size > bufferSize - used)
			{
				// the rest are for the next call: the directory's offset goes back to the first of them
				LINUX_SYSCALL(__NR_lseek, dirfd, resume, LINUX_SEEK_SET);
				return count ? count : -ERANGE;
			}
			if (size)
			{
				memcpy(out + used, entry, size);
				used += size;
				count++;
			}
			resume = d->d_off;
		}
	}
}
