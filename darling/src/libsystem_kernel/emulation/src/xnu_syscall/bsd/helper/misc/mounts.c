#include <darling/emulation/xnu_syscall/bsd/helper/misc/mounts.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
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

extern char* strtok_r(char* str, const char* delim, char** saveptr);
extern __SIZE_TYPE__ strlcpy(char* dst, const char* src, __SIZE_TYPE__ size);
extern __SIZE_TYPE__ strlen(const char* str);
extern int strncmp(const char* s1, const char* s2, __SIZE_TYPE__ len);
extern void* memset(void* s, int c, __SIZE_TYPE__ n);

struct mount
{
	char* from;
	char* on;
	char* type;
};

// the next line of /proc/self/mounts
static int next_mount(int fd, struct simple_readline_buf* rbuf, char* line, int size, struct mount* m)
{
	while (__simple_readline(fd, rbuf, line, size))
	{
		char* saveptr;
		m->from = strtok_r(line, " ", &saveptr);
		m->on = m->from ? strtok_r(0, " ", &saveptr) : 0;
		m->type = m->on ? strtok_r(0, " ", &saveptr) : 0;
		if (m->type)
			return 1;
	}
	return 0;
}

static long linux_statfs(const char* path, struct bsd_statfs64* buf)
{
	struct linux_statfs64 lbuf;
	struct linux_stat st;
	int ret;

#ifdef __NR_statfs64
	ret = LINUX_SYSCALL3(__NR_statfs64, path, sizeof(lbuf), &lbuf);
#else
	ret = LINUX_SYSCALL2(__NR_statfs, path, &lbuf);
#endif
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, path, &st, 0);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	memset(buf, 0, sizeof(*buf));
	statfs_linux_to_bsd64(&lbuf, buf);
	// fsid_t: the device, then a file system type that is always 0
	buf->f_fsid = (unsigned int) st.st_dev;
	buf->f_iosize = lbuf.f_bsize;
	return 0;
}

static void fill_names(const struct mount* m, struct bsd_statfs64* buf)
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

long mounts_statfs(const char* linux_path, struct bsd_statfs64* buf)
{
	struct simple_readline_buf rbuf;
	struct statfs_names
	{
		char on[1024], from[1024], type[16];
	} best;
	char line[512];
	struct mount m;
	int best_len = -1;
	long ret = linux_statfs(linux_path, buf);

	if (ret < 0)
		return ret;

	int fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, "/proc/self/mounts", LINUX_O_RDONLY | LINUX_O_CLOEXEC, 0);
	if (fd < 0)
		return errno_linux_to_bsd(fd);
	__simple_readline_init(&rbuf);

	// the longest mount point the path is in, a whole component at a time; a later mount over the same point hides
	// an earlier one
	while (next_mount(fd, &rbuf, line, sizeof(line), &m))
	{
		int len = strlen(m.on);
		if (len < best_len || strncmp(m.on, linux_path, len) != 0)
			continue;
		if (len > 1 && linux_path[len] != '/' && linux_path[len] != '\0')
			continue;
		best_len = len;
		strlcpy(best.on, m.on, sizeof(best.on));
		strlcpy(best.from, m.from, sizeof(best.from));
		strlcpy(best.type, m.type, sizeof(best.type));
	}
	close_internal(fd);

	if (best_len >= 0)
	{
		m.on = best.on;
		m.from = best.from;
		m.type = best.type;
		fill_names(&m, buf);
	}
	return 0;
}

long mounts_list(struct bsd_statfs64* buf, long count)
{
	struct simple_readline_buf rbuf;
	char line[512];
	struct mount m;
	long n = 0;

	int fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, "/proc/self/mounts", LINUX_O_RDONLY | LINUX_O_CLOEXEC, 0);
	if (fd < 0)
		return errno_linux_to_bsd(fd);
	__simple_readline_init(&rbuf);

	while (next_mount(fd, &rbuf, line, sizeof(line), &m))
	{
		struct linux_stat st;
		struct bsd_statfs64 fs;

		// a file bound over another (a container's /etc/hosts) isn't a file system to list
		if (LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, m.on, &st, 0) < 0 ||
			(st.st_mode & LINUX_S_IFMT) != LINUX_S_IFDIR)
			continue;
		if (buf)
		{
			if (n >= count)
				break;
			if (linux_statfs(m.on, &fs) < 0)
				continue;
			fill_names(&m, &fs);
			buf[n] = fs;
		}
		n++;
	}
	close_internal(fd);
	return n;
}
