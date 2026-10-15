#include <darling/emulation/xnu_syscall/bsd/helper/xattr/attrlist_pack.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/dirent/getdirentries.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>

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
#define ATTR_CMN_EXTENDED_SECURITY 0x00400000
#define ATTR_CMN_UUID 0x00800000
#define ATTR_CMN_GRPUUID 0x01000000
#define ATTR_CMN_FILEID 0x02000000
#define ATTR_CMN_PARENTID 0x04000000
#define ATTR_CMN_FULLPATH 0x08000000
#define ATTR_CMN_ADDEDTIME 0x10000000
#define ATTR_CMN_DATA_PROTECT_FLAGS 0x40000000

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

#define ATTR_CMNEXT_RELPATH 0x00000004
#define ATTR_CMNEXT_PRIVATESIZE 0x00000008
#define ATTR_CMNEXT_LINKID 0x00000010
#define ATTR_CMNEXT_NOFIRMLINKPATH 0x00000020
#define ATTR_CMNEXT_REALDEVID 0x00000040
#define ATTR_CMNEXT_REALFSID 0x00000080
#define ATTR_CMNEXT_CLONEID 0x00000100
#define ATTR_CMNEXT_EXT_FLAGS 0x00000200
#define ATTR_CMNEXT_RECURSIVE_GENCOUNT 0x00000400
#define ATTR_CMNEXT_ATTRIBUTION_TAG 0x00000800
#define ATTR_CMNEXT_CLONE_REFCNT 0x00001000

#define ATTR_VOL_FSTYPE 0x00000001
#define ATTR_VOL_SIGNATURE 0x00000002
#define ATTR_VOL_SIZE 0x00000004
#define ATTR_VOL_SPACEFREE 0x00000008
#define ATTR_VOL_SPACEAVAIL 0x00000010
#define ATTR_VOL_MINALLOCATION 0x00000020
#define ATTR_VOL_ALLOCATIONCLUMP 0x00000040
#define ATTR_VOL_IOBLOCKSIZE 0x00000080
#define ATTR_VOL_OBJCOUNT 0x00000100
#define ATTR_VOL_FILECOUNT 0x00000200
#define ATTR_VOL_DIRCOUNT 0x00000400
#define ATTR_VOL_MAXOBJCOUNT 0x00000800
#define ATTR_VOL_MOUNTPOINT 0x00001000
#define ATTR_VOL_NAME 0x00002000
#define ATTR_VOL_MOUNTFLAGS 0x00004000
#define ATTR_VOL_MOUNTEDDEVICE 0x00008000
#define ATTR_VOL_ENCODINGSUSED 0x00010000
#define ATTR_VOL_UUID 0x00040000
#define ATTR_VOL_MOUNTEXTFLAGS 0x00080000
#define ATTR_VOL_FSTYPENAME 0x00100000
#define ATTR_VOL_FSSUBTYPE 0x00200000
#define ATTR_VOL_OWNER 0x00400000
#define ATTR_VOL_SPACEUSED 0x00800000
#define ATTR_VOL_QUOTA_SIZE 0x10000000
#define ATTR_VOL_RESERVED_SIZE 0x20000000
#define ATTR_VOL_ATTRIBUTES 0x40000000

// vol_capabilities_attr_t: what a Linux file system (under Darling) can do, reported as XNU would for it
#define VOL_CAP_FMT_SYMBOLICLINKS 0x00000002
#define VOL_CAP_FMT_HARDLINKS 0x00000004
#define VOL_CAP_FMT_SPARSE_FILES 0x00000040
#define VOL_CAP_FMT_CASE_SENSITIVE 0x00000100
#define VOL_CAP_FMT_CASE_PRESERVING 0x00000200
#define VOL_CAP_FMT_FAST_STATFS 0x00000400
#define VOL_CAP_FMT_2TB_FILESIZE 0x00000800
#define VOL_CAP_FMT_64BIT_OBJECT_IDS 0x00020000
#define VOL_CAP_INT_ATTRLIST 0x00000002
#define VOL_CAP_INT_ADVLOCK 0x00000100
#define VOL_CAP_INT_FLOCK 0x00000200
#define VOL_CAP_INT_EXTENDED_ATTR 0x00004000
#define VOL_CAP_INT_RENAME_SWAP 0x00040000
#define VOL_CAP_INT_RENAME_EXCL 0x00080000
#define VOL_CAPABILITIES_FORMAT_KNOWN 0x03ffffff
#define VOL_CAPABILITIES_INTERFACES_KNOWN 0x003fffff

// the bits XNU's attribute tables know (xnu-12377, iOS 26's); any other is EINVAL
#define DIR_KNOWN 0x0000003f
#define FILE_KNOWN 0x0000363f
#define CMNEXT_KNOWN 0x00001ffc
#define FORK_KNOWN 0x00000003
// of a volume: the common attributes but the path, the added time, the protection class, and the two counters
#define VOL_CMN_KNOWN 0xa7e7ffff
#define VOL_KNOWN 0xf0ffffff

// what a volume has an answer for (ATTR_VOL_ATTRIBUTES)
#define VOL_CMN_ANSWERED                                                                                               \
	(VOL_CMN_KNOWN & ~(ATTR_CMN_EXTENDED_SECURITY | ATTR_CMN_UUID | ATTR_CMN_GRPUUID | ATTR_CMN_ERROR))
#define VOL_ANSWERED                                                                                                   \
	(ATTR_VOL_FSTYPE | ATTR_VOL_SIZE | ATTR_VOL_SPACEFREE | ATTR_VOL_SPACEAVAIL | ATTR_VOL_MINALLOCATION |             \
		ATTR_VOL_ALLOCATIONCLUMP | ATTR_VOL_IOBLOCKSIZE | ATTR_VOL_OBJCOUNT | ATTR_VOL_MAXOBJCOUNT |                  \
		ATTR_VOL_MOUNTPOINT | ATTR_VOL_NAME | ATTR_VOL_MOUNTFLAGS | ATTR_VOL_MOUNTEDDEVICE | ATTR_VOL_ENCODINGSUSED | \
		ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES | ATTR_VOL_INFO | ATTR_VOL_MOUNTEXTFLAGS |                    \
		ATTR_VOL_FSTYPENAME | ATTR_VOL_FSSUBTYPE | ATTR_VOL_OWNER | ATTR_VOL_SPACEUSED)

#define DIR_MNTSTATUS_MNTPOINT 0x00000001
#define VT_HFS 16

#define LINUX_R_OK 4
#define LINUX_W_OK 2
#define LINUX_X_OK 1

#define LINUX_S_IFMT 0170000
#define LINUX_S_IFDIR 0040000

// fsobj_type_t
enum { VNON, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO };

// the indexes of attribute_set_t
enum { CMN, VOL, DIR, FILE, EXT };

extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n);
extern void* memset(void* s, int c, __SIZE_TYPE__ n);
extern __SIZE_TYPE__ strlen(const char* s);

struct packer
{
	char* next;
	uint32_t returned[ATTR_BIT_MAP_COUNT];
	int return_valid;
	int pack_invalid;
	// the attrreference_t's, filled in once the variable-size data's place is known
	struct
	{
		int32_t* at;
		const char* data;
	} refs[7];
	int nrefs;
};

static void put(struct packer* p, int group, uint32_t bit, const void* data, __SIZE_TYPE__ size)
{
	memcpy(p->next, data, size);
	p->next += size;
	p->returned[group] |= bit;
}

static void put32(struct packer* p, int group, uint32_t bit, uint32_t v)
{
	put(p, group, bit, &v, sizeof(v));
}

static void put64(struct packer* p, int group, uint32_t bit, uint64_t v)
{
	put(p, group, bit, &v, sizeof(v));
}

static void put_timespec(struct packer* p, int group, uint32_t bit, long sec, long nsec)
{
	long ts[2] = { sec, nsec };
	put(p, group, bit, ts, sizeof(ts));
}

// an attribute there's no answer for
static void put_none(struct packer* p, __SIZE_TYPE__ size)
{
	if (p->return_valid && !p->pack_invalid)
		return;
	memset(p->next, 0, size);
	p->next += size;
}

// a string, as an attrreference_t to it
static void put_ref(struct packer* p, int group, uint32_t bit, const char* s)
{
	if (!s)
	{
		put_none(p, 2 * sizeof(int32_t));
		return;
	}
	p->refs[p->nrefs].at = (int32_t*) p->next;
	p->refs[p->nrefs].data = s;
	p->nrefs++;
	p->next += 2 * sizeof(int32_t);
	p->returned[group] |= bit;
}

static uint32_t finish(struct packer* p, char* out)
{
	for (int i = 0; i < p->nrefs; i++)
	{
		// attrreference_t: the data's offset from the attrreference_t itself, and its length (with the NUL)
		uint32_t size = strlen(p->refs[i].data) + 1;
		p->refs[i].at[0] = p->next - (char*) p->refs[i].at;
		p->refs[i].at[1] = size;
		memcpy(p->next, p->refs[i].data, size);
		memset(p->next + size, 0, ((size + 3) & ~3) - size);
		p->next += (size + 3) & ~3;
	}
	if (p->return_valid)
	{
		p->returned[CMN] |= ATTR_CMN_RETURNED_ATTRS;
		memcpy(out + sizeof(uint32_t), p->returned, sizeof(p->returned));
	}

	uint32_t size = p->next - out;
	memcpy(out, &size, sizeof(size));
	return size;
}

static void start(struct packer* p, const struct xnu_attrlist* al, uint64_t options, char* out)
{
	memset(p, 0, sizeof(*p));
	p->return_valid = (al->commonattr & ATTR_CMN_RETURNED_ATTRS) != 0;
	p->pack_invalid = (options & FSOPT_PACK_INVAL_ATTRS) != 0;
	p->next = out + sizeof(uint32_t);
	if (p->return_valid)
		p->next += sizeof(p->returned);
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

static uint32_t user_access(int dirfd, const char* name)
{
	uint32_t access = 0;
	// R_OK, W_OK and X_OK are the same on XNU
	if (LINUX_SYSCALL(__NR_faccessat, dirfd, name, LINUX_R_OK) == 0)
		access |= LINUX_R_OK;
	if (LINUX_SYSCALL(__NR_faccessat, dirfd, name, LINUX_W_OK) == 0)
		access |= LINUX_W_OK;
	if (LINUX_SYSCALL(__NR_faccessat, dirfd, name, LINUX_X_OK) == 0)
		access |= LINUX_X_OK;
	return access;
}

int attrlist_check(const struct xnu_attrlist* al, uint64_t options, int is_dir)
{
	int extended = (options & FSOPT_ATTR_CMN_EXTENDED) != 0;

	if (al->bitmapcount != ATTR_BIT_MAP_COUNT)
		return -EINVAL;
	// these reuse the bits of the old ATTR_CMN_NAMEDATTRCOUNT and ATTR_CMN_NAMEDATTRLIST
	if ((al->commonattr & (ATTR_CMN_GEN_COUNT | ATTR_CMN_DOCUMENT_ID)) && !extended)
		return -EINVAL;
	// the fork attributes are the common extended ones with FSOPT_ATTR_CMN_EXTENDED, and only then
	if (extended ? (al->forkattr & ~CMNEXT_KNOWN) != 0 : (al->forkattr & CMNEXT_KNOWN) != 0)
		return -EINVAL;
	if ((options & FSOPT_PACK_INVAL_ATTRS) && (!(al->commonattr & ATTR_CMN_RETURNED_ATTRS) || (al->forkattr && !extended)))
		return -EINVAL;
	// only the group that applies to the object is looked at
	if (is_dir ? (al->dirattr & ~DIR_KNOWN) != 0 : (al->fileattr & ~FILE_KNOWN) != 0)
		return -EINVAL;
	return 0;
}

// the common attributes, in the order of their bits
static void pack_common(struct packer* p, uint32_t c, const struct attrlist_object* obj)
{
	const struct linux_stat* st = obj->st;
	if ((c & ATTR_CMN_ERROR) && (!p->return_valid || p->pack_invalid))
		put32(p, CMN, ATTR_CMN_ERROR, 0);
	if (c & ATTR_CMN_NAME)
		put_ref(p, CMN, ATTR_CMN_NAME, obj->name);
	if (c & ATTR_CMN_DEVID)
		put32(p, CMN, ATTR_CMN_DEVID, (uint32_t) st->st_dev);
	if (c & ATTR_CMN_FSID)
		put64(p, CMN, ATTR_CMN_FSID, (uint32_t) st->st_dev);
	if (c & ATTR_CMN_OBJTYPE)
		put32(p, CMN, ATTR_CMN_OBJTYPE, objtype(st->st_mode));
	if (c & ATTR_CMN_OBJTAG)
		put32(p, CMN, ATTR_CMN_OBJTAG, VT_HFS);
	// fsobj_id_t: the file's number, then a generation that is always 0
	if (c & ATTR_CMN_OBJID)
		put64(p, CMN, ATTR_CMN_OBJID, (uint32_t) st->st_ino);
	if (c & ATTR_CMN_OBJPERMANENTID)
		put64(p, CMN, ATTR_CMN_OBJPERMANENTID, (uint32_t) st->st_ino);
	if (c & ATTR_CMN_PAROBJID)
		put64(p, CMN, ATTR_CMN_PAROBJID, (uint32_t) obj->parent->st_ino);
	if (c & ATTR_CMN_SCRIPT)
		put32(p, CMN, ATTR_CMN_SCRIPT, 0);
	// Linux's stat() has no birth time: the modification time stands in, as Darling's stat() does
	if (c & ATTR_CMN_CRTIME)
		put_timespec(p, CMN, ATTR_CMN_CRTIME, st->st_mtime, st->st_mtime_nsec);
	if (c & ATTR_CMN_MODTIME)
		put_timespec(p, CMN, ATTR_CMN_MODTIME, st->st_mtime, st->st_mtime_nsec);
	if (c & ATTR_CMN_CHGTIME)
		put_timespec(p, CMN, ATTR_CMN_CHGTIME, st->st_ctime, st->st_ctime_nsec);
	if (c & ATTR_CMN_ACCTIME)
		put_timespec(p, CMN, ATTR_CMN_ACCTIME, st->st_atime, st->st_atime_nsec);
	if (c & ATTR_CMN_BKUPTIME)
		put_timespec(p, CMN, ATTR_CMN_BKUPTIME, 0, 0);
	// no Finder information, as XNU reports for a file without it
	if (c & ATTR_CMN_FNDRINFO)
	{
		static const char zeros[32];
		put(p, CMN, ATTR_CMN_FNDRINFO, zeros, sizeof(zeros));
	}
	if (c & ATTR_CMN_OWNERID)
		put32(p, CMN, ATTR_CMN_OWNERID, st->st_uid);
	if (c & ATTR_CMN_GRPID)
		put32(p, CMN, ATTR_CMN_GRPID, st->st_gid);
	if (c & ATTR_CMN_ACCESSMASK)
		put32(p, CMN, ATTR_CMN_ACCESSMASK, st->st_mode & 07777);
	if (c & ATTR_CMN_FLAGS)
		put32(p, CMN, ATTR_CMN_FLAGS, 0);
	if (c & ATTR_CMN_GEN_COUNT)
		put32(p, CMN, ATTR_CMN_GEN_COUNT, 0);
	if (c & ATTR_CMN_DOCUMENT_ID)
		put32(p, CMN, ATTR_CMN_DOCUMENT_ID, 0);
	if (c & ATTR_CMN_USERACCESS)
		put32(p, CMN, ATTR_CMN_USERACCESS, user_access(obj->dirfd, obj->lookup));
	if (c & ATTR_CMN_EXTENDED_SECURITY)
		put_ref(p, CMN, ATTR_CMN_EXTENDED_SECURITY, 0);
	if (c & ATTR_CMN_UUID)
		put_none(p, 16);
	if (c & ATTR_CMN_GRPUUID)
		put_none(p, 16);
	if (c & ATTR_CMN_FILEID)
		put64(p, CMN, ATTR_CMN_FILEID, st->st_ino);
	if (c & ATTR_CMN_PARENTID)
		put64(p, CMN, ATTR_CMN_PARENTID, obj->parent->st_ino);
	if (c & ATTR_CMN_FULLPATH)
		put_ref(p, CMN, ATTR_CMN_FULLPATH, obj->fullpath);
	if (c & ATTR_CMN_ADDEDTIME)
		put_none(p, 2 * sizeof(long));
	if (c & ATTR_CMN_DATA_PROTECT_FLAGS)
		put32(p, CMN, ATTR_CMN_DATA_PROTECT_FLAGS, 0);
}

uint32_t attrlist_pack(const struct xnu_attrlist* al, uint64_t options, const struct attrlist_object* obj, char* out)
{
	const struct linux_stat* st = obj->st;
	int is_dir = (st->st_mode & LINUX_S_IFMT) == LINUX_S_IFDIR;
	struct packer p;

	start(&p, al, options, out);
	pack_common(&p, al->commonattr, obj);

	uint32_t d = is_dir ? al->dirattr : 0;
	if (d & ATTR_DIR_LINKCOUNT)
		put32(&p, DIR, ATTR_DIR_LINKCOUNT, st->st_nlink);
	if (d & ATTR_DIR_ENTRYCOUNT)
		put32(&p, DIR, ATTR_DIR_ENTRYCOUNT, entry_count(obj->dirfd, obj->lookup));
	if (d & ATTR_DIR_MOUNTSTATUS)
		put32(&p, DIR, ATTR_DIR_MOUNTSTATUS, st->st_dev != obj->parent->st_dev ? DIR_MNTSTATUS_MNTPOINT : 0);
	if (d & ATTR_DIR_ALLOCSIZE)
		put64(&p, DIR, ATTR_DIR_ALLOCSIZE, (uint64_t) st->st_blocks * 512);
	if (d & ATTR_DIR_IOBLOCKSIZE)
		put32(&p, DIR, ATTR_DIR_IOBLOCKSIZE, st->st_blksize);
	if (d & ATTR_DIR_DATALENGTH)
		put64(&p, DIR, ATTR_DIR_DATALENGTH, st->st_size);

	uint32_t f = is_dir ? 0 : al->fileattr;
	if (f & ATTR_FILE_LINKCOUNT)
		put32(&p, FILE, ATTR_FILE_LINKCOUNT, st->st_nlink);
	if (f & ATTR_FILE_TOTALSIZE)
		put64(&p, FILE, ATTR_FILE_TOTALSIZE, st->st_size);
	if (f & ATTR_FILE_ALLOCSIZE)
		put64(&p, FILE, ATTR_FILE_ALLOCSIZE, (uint64_t) st->st_blocks * 512);
	if (f & ATTR_FILE_IOBLOCKSIZE)
		put32(&p, FILE, ATTR_FILE_IOBLOCKSIZE, st->st_blksize);
	if (f & ATTR_FILE_CLUMPSIZE)
		put32(&p, FILE, ATTR_FILE_CLUMPSIZE, st->st_blksize);
	if (f & ATTR_FILE_DEVTYPE)
		put32(&p, FILE, ATTR_FILE_DEVTYPE, (uint32_t) st->st_rdev);
	if (f & ATTR_FILE_DATALENGTH)
		put64(&p, FILE, ATTR_FILE_DATALENGTH, st->st_size);
	if (f & ATTR_FILE_DATAALLOCSIZE)
		put64(&p, FILE, ATTR_FILE_DATAALLOCSIZE, (uint64_t) st->st_blocks * 512);
	// no resource fork
	if (f & ATTR_FILE_RSRCLENGTH)
		put64(&p, FILE, ATTR_FILE_RSRCLENGTH, 0);
	if (f & ATTR_FILE_RSRCALLOCSIZE)
		put64(&p, FILE, ATTR_FILE_RSRCALLOCSIZE, 0);

	uint32_t x = (options & FSOPT_ATTR_CMN_EXTENDED) ? al->forkattr : 0;
	// one file system mounted at the root: the path within it is the full one, and there are no firmlinks
	if (x & ATTR_CMNEXT_RELPATH)
		put_ref(&p, EXT, ATTR_CMNEXT_RELPATH, obj->fullpath);
	if (x & ATTR_CMNEXT_PRIVATESIZE)
		put_none(&p, sizeof(uint64_t));
	if (x & ATTR_CMNEXT_LINKID)
		put64(&p, EXT, ATTR_CMNEXT_LINKID, st->st_ino);
	if (x & ATTR_CMNEXT_NOFIRMLINKPATH)
		put_ref(&p, EXT, ATTR_CMNEXT_NOFIRMLINKPATH, obj->fullpath);
	if (x & ATTR_CMNEXT_REALDEVID)
		put32(&p, EXT, ATTR_CMNEXT_REALDEVID, (uint32_t) st->st_dev);
	if (x & ATTR_CMNEXT_REALFSID)
		put64(&p, EXT, ATTR_CMNEXT_REALFSID, (uint32_t) st->st_dev);
	if (x & ATTR_CMNEXT_CLONEID)
		put_none(&p, sizeof(uint64_t));
	if (x & ATTR_CMNEXT_EXT_FLAGS)
		put_none(&p, sizeof(uint64_t));
	if (x & ATTR_CMNEXT_RECURSIVE_GENCOUNT)
		put_none(&p, sizeof(uint64_t));
	if (x & ATTR_CMNEXT_ATTRIBUTION_TAG)
		put_none(&p, sizeof(uint64_t));
	if (x & ATTR_CMNEXT_CLONE_REFCNT)
		put_none(&p, sizeof(uint32_t));

	return finish(&p, out);
}

uint32_t attrlist_pack_error(const struct xnu_attrlist* al, const char* name, int error, char* out)
{
	struct packer p;

	// getattrlistbulk() always asks for the returned attributes and the name
	start(&p, al, 0, out);
	if (al->commonattr & ATTR_CMN_ERROR)
		put32(&p, CMN, ATTR_CMN_ERROR, error);
	put_ref(&p, CMN, ATTR_CMN_NAME, name);
	return finish(&p, out);
}

int attrlist_check_volume(const struct xnu_attrlist* al, uint64_t options)
{
	if (al->bitmapcount != ATTR_BIT_MAP_COUNT)
		return -EINVAL;
	// as XNU: with ATTR_VOL_INFO, and no attributes of a file or directory
	if (!(al->volattr & ATTR_VOL_INFO) || (al->volattr & ~VOL_KNOWN) || (al->commonattr & ~VOL_CMN_KNOWN) ||
		al->dirattr || al->fileattr || (al->forkattr && !(options & FSOPT_ATTR_CMN_EXTENDED)))
		return -EINVAL;
	if ((options & FSOPT_PACK_INVAL_ATTRS) && !(al->commonattr & ATTR_CMN_RETURNED_ATTRS))
		return -EINVAL;
	return 0;
}

uint32_t attrlist_pack_volume(const struct xnu_attrlist* al, uint64_t options, const struct attrlist_object* root,
	const struct attrlist_volume* vol, char* out)
{
	const struct bsd_statfs64* fs = vol->fs;
	uint64_t bsize = fs->f_bsize;
	struct packer p;

	start(&p, al, options, out);
	// of the volume's root, but its name is the volume's
	pack_common(&p, al->commonattr, root);

	uint32_t v = al->volattr;
	if (v & ATTR_VOL_FSTYPE)
		put32(&p, VOL, ATTR_VOL_FSTYPE, fs->f_type);
	if (v & ATTR_VOL_SIGNATURE)
		put_none(&p, sizeof(uint32_t));
	if (v & ATTR_VOL_SIZE)
		put64(&p, VOL, ATTR_VOL_SIZE, fs->f_blocks * bsize);
	if (v & ATTR_VOL_SPACEFREE)
		put64(&p, VOL, ATTR_VOL_SPACEFREE, fs->f_bfree * bsize);
	if (v & ATTR_VOL_SPACEAVAIL)
		put64(&p, VOL, ATTR_VOL_SPACEAVAIL, fs->f_bavail * bsize);
	if (v & ATTR_VOL_SPACEUSED)
		put64(&p, VOL, ATTR_VOL_SPACEUSED, (fs->f_blocks - fs->f_bfree) * bsize);
	if (v & ATTR_VOL_MINALLOCATION)
		put64(&p, VOL, ATTR_VOL_MINALLOCATION, bsize);
	if (v & ATTR_VOL_ALLOCATIONCLUMP)
		put64(&p, VOL, ATTR_VOL_ALLOCATIONCLUMP, bsize);
	if (v & ATTR_VOL_IOBLOCKSIZE)
		put32(&p, VOL, ATTR_VOL_IOBLOCKSIZE, fs->f_iosize);
	if (v & ATTR_VOL_OBJCOUNT)
		put32(&p, VOL, ATTR_VOL_OBJCOUNT, fs->f_files - fs->f_ffree);
	if (v & ATTR_VOL_FILECOUNT)
		put_none(&p, sizeof(uint32_t));
	if (v & ATTR_VOL_DIRCOUNT)
		put_none(&p, sizeof(uint32_t));
	if (v & ATTR_VOL_MAXOBJCOUNT)
		put32(&p, VOL, ATTR_VOL_MAXOBJCOUNT, fs->f_files);
	if (v & ATTR_VOL_MOUNTPOINT)
		put_ref(&p, VOL, ATTR_VOL_MOUNTPOINT, fs->f_mntonname);
	if (v & ATTR_VOL_NAME)
		put_ref(&p, VOL, ATTR_VOL_NAME, vol->name);
	if (v & ATTR_VOL_MOUNTFLAGS)
		put32(&p, VOL, ATTR_VOL_MOUNTFLAGS, fs->f_flags);
	if (v & ATTR_VOL_MOUNTEDDEVICE)
		put_ref(&p, VOL, ATTR_VOL_MOUNTEDDEVICE, fs->f_mntfromname);
	if (v & ATTR_VOL_ENCODINGSUSED)
		put64(&p, VOL, ATTR_VOL_ENCODINGSUSED, 0);
	if (v & ATTR_VOL_CAPABILITIES)
	{
		uint32_t caps[8] = {
			VOL_CAP_FMT_SYMBOLICLINKS | VOL_CAP_FMT_HARDLINKS | VOL_CAP_FMT_SPARSE_FILES | VOL_CAP_FMT_CASE_SENSITIVE |
				VOL_CAP_FMT_CASE_PRESERVING | VOL_CAP_FMT_FAST_STATFS | VOL_CAP_FMT_2TB_FILESIZE |
				VOL_CAP_FMT_64BIT_OBJECT_IDS,
			VOL_CAP_INT_ATTRLIST | VOL_CAP_INT_ADVLOCK | VOL_CAP_INT_FLOCK | VOL_CAP_INT_EXTENDED_ATTR |
				VOL_CAP_INT_RENAME_SWAP | VOL_CAP_INT_RENAME_EXCL,
			0, 0, // reserved
			VOL_CAPABILITIES_FORMAT_KNOWN, VOL_CAPABILITIES_INTERFACES_KNOWN, 0, 0
		};
		put(&p, VOL, ATTR_VOL_CAPABILITIES, caps, sizeof(caps));
	}
	if (v & ATTR_VOL_UUID)
		put_none(&p, 16);
	if (v & ATTR_VOL_MOUNTEXTFLAGS)
		put32(&p, VOL, ATTR_VOL_MOUNTEXTFLAGS, 0);
	if (v & ATTR_VOL_QUOTA_SIZE)
		put_none(&p, sizeof(uint64_t));
	if (v & ATTR_VOL_RESERVED_SIZE)
		put_none(&p, sizeof(uint64_t));
	if (v & ATTR_VOL_ATTRIBUTES)
	{
		// vol_attributes_attr_t: the attributes there's an answer for, and those the file system itself knows
		uint32_t attrs[2 * ATTR_BIT_MAP_COUNT] = { VOL_CMN_ANSWERED, VOL_ANSWERED, DIR_KNOWN, FILE_KNOWN & ~(ATTR_FILE_CLUMPSIZE), 0 };
		memcpy(attrs + ATTR_BIT_MAP_COUNT, attrs, ATTR_BIT_MAP_COUNT * sizeof(uint32_t));
		put(&p, VOL, ATTR_VOL_ATTRIBUTES, attrs, sizeof(attrs));
	}

	// these come last, though their bits don't
	if (v & ATTR_VOL_FSTYPENAME)
		put_ref(&p, VOL, ATTR_VOL_FSTYPENAME, fs->f_fstypename);
	if (v & ATTR_VOL_FSSUBTYPE)
		put32(&p, VOL, ATTR_VOL_FSSUBTYPE, fs->f_fssubtype);
	if (v & ATTR_VOL_OWNER)
		put32(&p, VOL, ATTR_VOL_OWNER, fs->f_owner);

	// ATTR_VOL_INFO only says volume attributes were asked for
	return finish(&p, out);
}
