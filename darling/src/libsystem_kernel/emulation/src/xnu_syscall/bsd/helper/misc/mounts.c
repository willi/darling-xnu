#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>

#ifndef __NR_fstatat64
#	define __NR_fstatat64 __NR_newfstatat
#endif

#define LINUX_S_IFMT 0170000
#define LINUX_S_IFDIR 0040000
#define LINUX_O_PATH 010000000
#define LINUX_STATX_MNT_ID 0x00001000U
// what Linux's fstatfs() says of descriptors that aren't files
#define LINUX_PIPEFS_MAGIC 0x50495045
#define LINUX_SOCKFS_MAGIC 0x534F434B
#define LINUX_ANON_INODE_FS_MAGIC 0x09041934

extern __SIZE_TYPE__ strlcpy(char* dst, const char* src, __SIZE_TYPE__ size);
extern __SIZE_TYPE__ strlen(const char* str);
extern void* memset(void* s, int c, __SIZE_TYPE__ n);

// a line of /proc/self/mountinfo: "ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTIONS [OPTIONAL...] - TYPE SOURCE SUPEROPTS"
struct mountinfo
{
	unsigned long long id;
	char on[1024], type[16], from[1024];
};

// the field being read; the optional fields end at a "-" one
enum { F_ID, F_PARENT, F_DEV, F_ROOT, F_ON, F_OPTIONS, F_OPTIONAL, F_TYPE, F_FROM, F_REST };

// calls each(m, ctx) for every mount, until it returns nonzero (which is returned); lines of any length are read, and
// escaped characters (\040 for a space) are decoded
static long each_mount(int (*each)(const struct mountinfo* m, void* ctx), void* ctx)
{
	struct mountinfo m;
	char buf[1024];
	int field = F_ID, len = 0, sep = 0, esc = -1, digits = 0, n;
	long rv = 0;
	char* out = 0;
	int out_size = 0;

	int fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, "/proc/self/mountinfo", LINUX_O_RDONLY | LINUX_O_CLOEXEC, 0);
	if (fd < 0)
		return errno_linux_to_bsd(fd);

	memset(&m, 0, sizeof(m));
	while (!rv && (n = LINUX_SYSCALL(__NR_read, fd, buf, sizeof(buf))) > 0)
	{
		for (int i = 0; i < n && !rv; i++)
		{
			char c = buf[i];
			if (c == ' ' || c == '\n')
			{
				// the end of a field
				if (out)
					out[len < out_size ? len : out_size - 1] = '\0';
				if (field == F_OPTIONAL && sep)
					field = F_TYPE;
				else if (field == F_OPTIONS)
					field = F_OPTIONAL;
				else if (field < F_OPTIONAL || (field >= F_TYPE && field < F_REST))
					field++;
				if (c == '\n')
				{
					if (field > F_FROM)
						rv = each(&m, ctx);
					memset(&m, 0, sizeof(m));
					field = F_ID;
				}
				len = 0;
				sep = 0;
				esc = -1;
				digits = 0;
				out = field == F_ON ? m.on : field == F_TYPE ? m.type : field == F_FROM ? m.from : 0;
				out_size = field == F_ON ? sizeof(m.on) : field == F_TYPE ? sizeof(m.type) : sizeof(m.from);
				continue;
			}
			if (field == F_ID && c >= '0' && c <= '9')
				m.id = m.id * 10 + (c - '0');
			if (field == F_OPTIONAL)
				sep = (len == 0 && c == '-');
			if (out)
			{
				// \ooo: an escaped character
				if (c == '\\' && esc < 0)
				{
					esc = 0;
					continue;
				}
				if (esc >= 0)
				{
					esc = esc * 8 + (c - '0');
					if (++digits < 3)
						continue;
					c = (char) esc;
					esc = -1;
					digits = 0;
				}
				if (len < out_size - 1)
					out[len] = c;
			}
			len++;
		}
	}
	close_internal(fd);
	return rv;
}

static long linux_fstatfs(int fd, struct bsd_statfs64* buf)
{
	struct linux_statfs64 lbuf;
	struct linux_stat st;
	int ret;

	ret = LINUX_SYSCALL(__NR_fstatat64, fd, "", &st, LINUX_AT_EMPTY_PATH);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
#ifdef __NR_fstatfs64
	ret = LINUX_SYSCALL3(__NR_fstatfs64, fd, sizeof(lbuf), &lbuf);
#else
	ret = LINUX_SYSCALL2(__NR_fstatfs, fd, &lbuf);
#endif
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	if (lbuf.f_type == LINUX_PIPEFS_MAGIC || lbuf.f_type == LINUX_SOCKFS_MAGIC ||
		lbuf.f_type == LINUX_ANON_INODE_FS_MAGIC)
		return -EINVAL;

	memset(buf, 0, sizeof(*buf));
	statfs_linux_to_bsd64(&lbuf, buf);
	// fsid_t: the device, then a file system type that is always 0
	buf->f_fsid = (unsigned int) st.st_dev;
	buf->f_iosize = lbuf.f_bsize;
	return 0;
}

static void fill_names(const struct mountinfo* m, struct bsd_statfs64* buf)
{
	struct vchroot_unexpand_args vc;

	strlcpy(vc.path, m->on, sizeof(vc.path));
	vchroot_unexpand(&vc);
	// Linux's root, outside the prefix, unexpands as /Volumes/SystemRoot/
	int len = strlen(vc.path);
	if (len > 1 && vc.path[len - 1] == '/')
		vc.path[len - 1] = '\0';
	strlcpy(buf->f_mntonname, vc.path, sizeof(buf->f_mntonname));
	strlcpy(buf->f_mntfromname, m->from, sizeof(buf->f_mntfromname));
	strlcpy(buf->f_fstypename, m->type, sizeof(buf->f_fstypename));
}

struct find_mount
{
	unsigned long long id;
	struct bsd_statfs64* buf;
};

static int find_mount(const struct mountinfo* m, void* ctx)
{
	struct find_mount* f = ctx;
	if (m->id != f->id)
		return 0;
	fill_names(m, f->buf);
	return 1;
}

long mounts_fstatfs(int fd, struct bsd_statfs64* buf)
{
	unsigned char stx[256];
	long ret = linux_fstatfs(fd, buf);

	if (ret < 0)
		return ret;

	// the mount the object is on: exact, for a removed file and under a mount over another too
	ret = LINUX_SYSCALL(__NR_statx, fd, "", LINUX_AT_EMPTY_PATH, LINUX_STATX_MNT_ID, stx);
	if (ret == 0 && (*(unsigned int*) stx & LINUX_STATX_MNT_ID))
	{
		struct find_mount f = { .id = *(unsigned long long*) (stx + 0x90), .buf = buf };
		if (each_mount(find_mount, &f) > 0)
			return 0;
	}

	// a mount this process can't see: the root's names stand in
	strlcpy(buf->f_mntonname, "/", sizeof(buf->f_mntonname));
	return 0;
}

long mounts_statfs(const char* linux_path, struct bsd_statfs64* buf)
{
	int fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, linux_path, LINUX_O_PATH | LINUX_O_CLOEXEC, 0);
	long ret;

	if (fd < 0)
		return errno_linux_to_bsd(fd);
	ret = mounts_fstatfs(fd, buf);
	close_internal(fd);
	return ret;
}

struct list_mounts
{
	struct bsd_statfs64* buf;
	long count, n;
};

static int list_mount(const struct mountinfo* m, void* ctx)
{
	struct list_mounts* l = ctx;
	struct linux_stat st;

	// a file bound over another (a container's /etc/hosts) isn't a file system to list
	if (LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, m->on, &st, 0) < 0 || (st.st_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
		return 0;
	if (l->buf)
	{
		if (l->n >= l->count)
			return 1;
		int fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, m->on, LINUX_O_PATH | LINUX_O_CLOEXEC, 0);
		if (fd < 0)
			return 0;
		long ret = linux_fstatfs(fd, &l->buf[l->n]);
		close_internal(fd);
		if (ret < 0)
			return 0;
		fill_names(m, &l->buf[l->n]);
	}
	l->n++;
	return 0;
}

long mounts_list(struct bsd_statfs64* buf, long count)
{
	struct list_mounts l = { .buf = buf, .count = count, .n = 0 };
	long ret = each_mount(list_mount, &l);
	return ret < 0 ? ret : l.n;
}

long mounts_open_root(const struct bsd_statfs64* fs)
{
	struct vchroot_expand_args vc;
	long ret;

	vc.flags = VCHROOT_FOLLOW;
	vc.dfd = LINUX_AT_FDCWD;
	strlcpy(vc.path, fs->f_mntonname[0] ? fs->f_mntonname : "/", sizeof(vc.path));
	ret = vchroot_expand(&vc);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, vc.path, LINUX_O_PATH | LINUX_O_CLOEXEC, 0);
	return ret < 0 ? errno_linux_to_bsd(ret) : ret;
}

const char* mounts_volume_name(const struct bsd_statfs64* fs)
{
	const char* last = 0;
	for (const char* c = fs->f_mntonname; *c; c++)
		if (*c == '/')
			last = c;
	return (last && last[1]) ? last + 1 : "Macintosh HD";
}
