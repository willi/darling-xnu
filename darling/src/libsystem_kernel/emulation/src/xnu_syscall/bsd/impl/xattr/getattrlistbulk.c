#include <darling/emulation/xnu_syscall/bsd/impl/xattr/getattrlistbulk.h>

#include <stdint.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>

// getattrlistbulk(): the entries of a directory with the attributes of each, as XNU packs them. MobileInstallation's
// file system scanner enumerates the runtime's apps with it (lsd registers no system app without it, and SpringBoard
// then has no app to show).
//
// Each entry is a uint32_t length, the attribute_set_t of what was returned, the fixed-size attributes in the order of
// their bits, then the variable-size data (the name) the attrreference_t's point to, padded to 4 bytes; the entry is
// padded to 8. An attribute a Linux file system has no answer for is left out of the entry and of its returned set,
// as XNU does for one the file system doesn't support. The directory's offset advances past the entries returned.

#ifndef __NR_fstatat64
#	define __NR_fstatat64 __NR_newfstatat
#endif

#define LINUX_SEEK_SET 0
#define LINUX_SEEK_CUR 1
#define LINUX_R_OK 4
#define LINUX_W_OK 2
#define LINUX_X_OK 1

#define ATTR_BIT_MAP_COUNT 5

#define ATTR_CMN_NAME 0x00000001
#define ATTR_CMN_DEVID 0x00000002
#define ATTR_CMN_FSID 0x00000004
#define ATTR_CMN_OBJTYPE 0x00000008
#define ATTR_CMN_OBJTAG 0x00000010
#define ATTR_CMN_OBJID 0x00000020
#define ATTR_CMN_OBJPERMANENTID 0x00000040
#define ATTR_CMN_PAROBJID 0x00000080
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
#define ATTR_CMN_FLAGS 0x00040000
#define ATTR_CMN_GEN_COUNT 0x00080000
#define ATTR_CMN_DOCUMENT_ID 0x00100000
#define ATTR_CMN_USERACCESS 0x00200000
#define ATTR_CMN_FILEID 0x02000000
#define ATTR_CMN_PARENTID 0x04000000
#define ATTR_CMN_ERROR 0x20000000
#define ATTR_CMN_DATA_PROTECT_FLAGS 0x40000000
#define ATTR_CMN_RETURNED_ATTRS 0x80000000

#define ATTR_DIR_LINKCOUNT 0x00000001
#define ATTR_DIR_ENTRYCOUNT 0x00000002
#define ATTR_DIR_MOUNTSTATUS 0x00000004
#define ATTR_DIR_ALLOCSIZE 0x00000008
#define ATTR_DIR_IOBLOCKSIZE 0x00000010
#define ATTR_DIR_DATALENGTH 0x00000020

#define ATTR_FILE_LINKCOUNT 0x00000001
#define ATTR_FILE_TOTALSIZE 0x00000002
#define ATTR_FILE_ALLOCSIZE 0x00000004
#define ATTR_FILE_IOBLOCKSIZE 0x00000008
#define ATTR_FILE_CLUMPSIZE 0x00000010
#define ATTR_FILE_DEVTYPE 0x00000020
#define ATTR_FILE_DATALENGTH 0x00000200
#define ATTR_FILE_DATAALLOCSIZE 0x00000400
#define ATTR_FILE_RSRCLENGTH 0x00001000
#define ATTR_FILE_RSRCALLOCSIZE 0x00002000

// the attributes there is an answer for; ATTR_CMN_ERROR only for an entry that couldn't be looked at
#define COMMON_SUPPORTED                                                                                               \
	(ATTR_CMN_NAME | ATTR_CMN_DEVID | ATTR_CMN_FSID | ATTR_CMN_OBJTYPE | ATTR_CMN_OBJTAG | ATTR_CMN_OBJID |             \
		ATTR_CMN_OBJPERMANENTID | ATTR_CMN_PAROBJID | ATTR_CMN_SCRIPT | ATTR_CMN_CRTIME | ATTR_CMN_MODTIME |           \
		ATTR_CMN_CHGTIME | ATTR_CMN_ACCTIME | ATTR_CMN_BKUPTIME | ATTR_CMN_FNDRINFO | ATTR_CMN_OWNERID |              \
		ATTR_CMN_GRPID | ATTR_CMN_ACCESSMASK | ATTR_CMN_FLAGS | ATTR_CMN_GEN_COUNT | ATTR_CMN_DOCUMENT_ID |          \
		ATTR_CMN_USERACCESS | ATTR_CMN_FILEID | ATTR_CMN_PARENTID | ATTR_CMN_DATA_PROTECT_FLAGS |                     \
		ATTR_CMN_RETURNED_ATTRS)
#define DIR_SUPPORTED                                                                                                  \
	(ATTR_DIR_LINKCOUNT | ATTR_DIR_ENTRYCOUNT | ATTR_DIR_MOUNTSTATUS | ATTR_DIR_ALLOCSIZE | ATTR_DIR_IOBLOCKSIZE |      \
		ATTR_DIR_DATALENGTH)
#define FILE_SUPPORTED                                                                                                 \
	(ATTR_FILE_LINKCOUNT | ATTR_FILE_TOTALSIZE | ATTR_FILE_ALLOCSIZE | ATTR_FILE_IOBLOCKSIZE | ATTR_FILE_CLUMPSIZE |    \
		ATTR_FILE_DEVTYPE | ATTR_FILE_DATALENGTH | ATTR_FILE_DATAALLOCSIZE | ATTR_FILE_RSRCLENGTH |                    \
		ATTR_FILE_RSRCALLOCSIZE)

#define DIR_MNTSTATUS_MNTPOINT 0x00000001
#define VT_HFS 16

// fsobj_type_t
enum { VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO };

#define LINUX_S_IFMT 0170000
#define LINUX_S_IFDIR 0040000

// the largest entry: the fixed-size attributes (under 300 bytes) and a name of up to 255 bytes
#define ENTRY_MAX 1024

extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n);
extern void* memset(void* s, int c, __SIZE_TYPE__ n);
extern __SIZE_TYPE__ strlen(const char* s);

struct packer
{
	char* next;
};

static void put(struct packer* p, const void* data, __SIZE_TYPE__ size)
{
	memcpy(p->next, data, size);
	p->next += size;
}

static void put32(struct packer* p, uint32_t v)
{
	put(p, &v, sizeof(v));
}

static void put64(struct packer* p, uint64_t v)
{
	put(p, &v, sizeof(v));
}

static void put_timespec(struct packer* p, long sec, long nsec)
{
	long ts[2] = { sec, nsec };
	put(p, ts, sizeof(ts));
}

static uint32_t objtype(unsigned int mode)
{
	switch (mode & LINUX_S_IFMT)
	{
		case 0100000: return VREG;
		case 0040000: return VDIR;
		case 0060000: return VBLK;
		case 0020000: return VCHR;
		case 0120000: return VLNK;
		case 0140000: return VSOCK;
		case 0010000: return VFIFO;
		default: return VNON;
	}
}

// the entries of a directory, but . and ..
static uint32_t entry_count(int dirfd, const char* name)
{
	char buf[1024];
	uint32_t count = 0;
	int fd = LINUX_SYSCALL(__NR_openat, dirfd, name, LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_CLOEXEC, 0);

	if (fd < 0)
		return 0;
	for (;;)
	{
		int n = LINUX_SYSCALL(__NR_getdents64, fd, buf, sizeof(buf));
		if (n <= 0)
			break;
		for (int off = 0; off < n; off += ((struct linux_dirent64*) (buf + off))->d_reclen)
		{
			const char* d = ((struct linux_dirent64*) (buf + off))->d_name;
			if (!(d[0] == '.' && (d[1] == 0 || (d[1] == '.' && d[2] == 0))))
				count++;
		}
	}
	close_internal(fd);
	return count;
}

// one entry into out (ENTRY_MAX bytes); returns its size, or 0 to leave the entry out
static uint32_t pack_entry(int dirfd, const struct linux_stat* dir_st, const char* name, const struct xnu_attrlist* al,
	char* out)
{
	struct linux_stat st;
	struct packer p = { out + sizeof(uint32_t) };
	uint32_t returned[ATTR_BIT_MAP_COUNT] = { 0 };
	uint32_t* returned_at;
	__SIZE_TYPE__ name_size = strlen(name) + 1;
	int32_t* name_ref = 0;
	int err = LINUX_SYSCALL(__NR_fstatat64, dirfd, name, &st, LINUX_AT_SYMLINK_NOFOLLOW);

	if (err < 0)
	{
		// the entry is gone, or can't be looked at: XNU reports it with ATTR_CMN_ERROR, when that was asked for
		if (!(al->commonattr & ATTR_CMN_ERROR))
			return 0;
		returned[0] = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_ERROR | (al->commonattr & ATTR_CMN_NAME);
	}
	else
	{
		int is_dir = (st.st_mode & LINUX_S_IFMT) == LINUX_S_IFDIR;
		returned[0] = al->commonattr & COMMON_SUPPORTED;
		returned[2] = is_dir ? al->dirattr & DIR_SUPPORTED : 0;
		returned[3] = is_dir ? 0 : al->fileattr & FILE_SUPPORTED;
	}

	returned_at = (uint32_t*) p.next;
	p.next += sizeof(returned);

	uint32_t c = returned[0];
	if (c & ATTR_CMN_NAME)
	{
		// filled in once the variable-size data's place is known
		name_ref = (int32_t*) p.next;
		p.next += 2 * sizeof(int32_t);
	}
	if (err < 0)
	{
		put32(&p, errno_linux_to_bsd(err) * -1);
		goto variable;
	}
	if (c & ATTR_CMN_DEVID)
		put32(&p, (uint32_t) st.st_dev);
	if (c & ATTR_CMN_FSID)
	{
		put32(&p, (uint32_t) st.st_dev);
		put32(&p, 0);
	}
	if (c & ATTR_CMN_OBJTYPE)
		put32(&p, objtype(st.st_mode));
	if (c & ATTR_CMN_OBJTAG)
		put32(&p, VT_HFS);
	if (c & ATTR_CMN_OBJID)
	{
		put32(&p, (uint32_t) st.st_ino);
		put32(&p, 0);
	}
	if (c & ATTR_CMN_OBJPERMANENTID)
	{
		put32(&p, (uint32_t) st.st_ino);
		put32(&p, 0);
	}
	if (c & ATTR_CMN_PAROBJID)
	{
		put32(&p, (uint32_t) dir_st->st_ino);
		put32(&p, 0);
	}
	if (c & ATTR_CMN_SCRIPT)
		put32(&p, 0);
	// Linux's stat() has no birth time: the modification time stands in, as Darling's stat() does
	if (c & ATTR_CMN_CRTIME)
		put_timespec(&p, st.st_mtime, st.st_mtime_nsec);
	if (c & ATTR_CMN_MODTIME)
		put_timespec(&p, st.st_mtime, st.st_mtime_nsec);
	if (c & ATTR_CMN_CHGTIME)
		put_timespec(&p, st.st_ctime, st.st_ctime_nsec);
	if (c & ATTR_CMN_ACCTIME)
		put_timespec(&p, st.st_atime, st.st_atime_nsec);
	if (c & ATTR_CMN_BKUPTIME)
		put_timespec(&p, 0, 0);
	if (c & ATTR_CMN_FNDRINFO)
	{
		memset(p.next, 0, 32);
		p.next += 32;
	}
	if (c & ATTR_CMN_OWNERID)
		put32(&p, st.st_uid);
	if (c & ATTR_CMN_GRPID)
		put32(&p, st.st_gid);
	if (c & ATTR_CMN_ACCESSMASK)
		put32(&p, st.st_mode & 07777);
	if (c & ATTR_CMN_FLAGS)
		put32(&p, 0);
	if (c & ATTR_CMN_GEN_COUNT)
		put32(&p, 0);
	if (c & ATTR_CMN_DOCUMENT_ID)
		put32(&p, 0);
	if (c & ATTR_CMN_USERACCESS)
	{
		uint32_t access = 0;
		if (LINUX_SYSCALL(__NR_faccessat, dirfd, name, LINUX_R_OK) == 0)
			access |= LINUX_R_OK;
		if (LINUX_SYSCALL(__NR_faccessat, dirfd, name, LINUX_W_OK) == 0)
			access |= LINUX_W_OK;
		if (LINUX_SYSCALL(__NR_faccessat, dirfd, name, LINUX_X_OK) == 0)
			access |= LINUX_X_OK;
		put32(&p, access); // R_OK, W_OK and X_OK are the same on XNU
	}
	if (c & ATTR_CMN_FILEID)
		put64(&p, st.st_ino);
	if (c & ATTR_CMN_PARENTID)
		put64(&p, dir_st->st_ino);
	if (c & ATTR_CMN_DATA_PROTECT_FLAGS)
		put32(&p, 0);

	uint32_t d = returned[2];
	if (d & ATTR_DIR_LINKCOUNT)
		put32(&p, st.st_nlink);
	if (d & ATTR_DIR_ENTRYCOUNT)
		put32(&p, entry_count(dirfd, name));
	if (d & ATTR_DIR_MOUNTSTATUS)
		put32(&p, st.st_dev != dir_st->st_dev ? DIR_MNTSTATUS_MNTPOINT : 0);
	if (d & ATTR_DIR_ALLOCSIZE)
		put64(&p, (uint64_t) st.st_blocks * 512);
	if (d & ATTR_DIR_IOBLOCKSIZE)
		put32(&p, st.st_blksize);
	if (d & ATTR_DIR_DATALENGTH)
		put64(&p, st.st_size);

	uint32_t f = returned[3];
	if (f & ATTR_FILE_LINKCOUNT)
		put32(&p, st.st_nlink);
	if (f & ATTR_FILE_TOTALSIZE)
		put64(&p, st.st_size);
	if (f & ATTR_FILE_ALLOCSIZE)
		put64(&p, (uint64_t) st.st_blocks * 512);
	if (f & ATTR_FILE_IOBLOCKSIZE)
		put32(&p, st.st_blksize);
	if (f & ATTR_FILE_CLUMPSIZE)
		put32(&p, st.st_blksize);
	if (f & ATTR_FILE_DEVTYPE)
		put32(&p, (uint32_t) st.st_rdev);
	if (f & ATTR_FILE_DATALENGTH)
		put64(&p, st.st_size);
	if (f & ATTR_FILE_DATAALLOCSIZE)
		put64(&p, (uint64_t) st.st_blocks * 512);
	if (f & ATTR_FILE_RSRCLENGTH)
		put64(&p, 0);
	if (f & ATTR_FILE_RSRCALLOCSIZE)
		put64(&p, 0);

variable:
	if (name_ref)
	{
		// attrreference_t: the data's offset from the attrreference_t itself, and its length (with the NUL)
		name_ref[0] = p.next - (char*) name_ref;
		name_ref[1] = name_size;
		memcpy(p.next, name, name_size);
		p.next += (name_size + 3) & ~3;
	}

	memcpy(returned_at, returned, sizeof(returned));
	uint32_t size = ((p.next - out) + 7) & ~7;
	memset(p.next, 0, out + size - p.next);
	memcpy(out, &size, sizeof(size));
	return size;
}

long sys_getattrlistbulk(int dirfd, struct xnu_attrlist* alist, void* attributeBuffer, __SIZE_TYPE__ bufferSize,
	uint64_t options)
{
	char dents[4096];
	char entry[ENTRY_MAX];
	struct linux_stat dir_st;
	char* out = attributeBuffer;
	__SIZE_TYPE__ used = 0;
	long count = 0;
	long long resume;
	int rv;

	if (!alist || !attributeBuffer)
		return -EFAULT;
	// as XNU: the returned attributes are required, and volume attributes can't be asked for
	if (alist->bitmapcount != ATTR_BIT_MAP_COUNT || !(alist->commonattr & ATTR_CMN_RETURNED_ATTRS) || alist->volattr)
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
				size = pack_entry(dirfd, &dir_st, d->d_name, alist, entry);
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
