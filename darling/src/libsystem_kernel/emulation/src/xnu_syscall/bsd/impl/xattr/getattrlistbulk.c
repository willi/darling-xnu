#include <darling/emulation/xnu_syscall/bsd/impl/xattr/getattrlistbulk.h>

#include <stdint.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
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

#define LINUX_S_IFMT 0170000
#define LINUX_S_IFDIR 0040000

extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n);
extern void* memset(void* s, int c, __SIZE_TYPE__ n);

// one entry into out (ATTRLIST_PACK_MAX bytes); returns its size, or 0 to leave the entry out
static uint32_t pack_entry(int dirfd, const struct linux_stat* dir_st, const char* name, const struct xnu_attrlist* al,
	uint64_t options, char* out)
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
			.st = &st, .parent = dir_st, .dirfd = dirfd, .lookup = name, .name = name, .fullpath = 0
		};
		size = attrlist_pack(al, options, &obj, out);
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
				size = pack_entry(dirfd, &dir_st, d->d_name, alist, options, entry);
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
