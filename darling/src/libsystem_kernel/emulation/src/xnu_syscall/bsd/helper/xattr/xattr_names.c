#include <darling/emulation/xnu_syscall/bsd/helper/xattr/xattr_names.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

#define LINUX_XATTR_CREATE 1
#define LINUX_XATTR_REPLACE 2
// what Linux's *listxattr() returns at most (XATTR_LIST_MAX)
#define LINUX_XATTR_LIST_MAX 65536

#define LINUX_PROT_READ 1
#define LINUX_PROT_WRITE 2
#define LINUX_MAP_PRIVATE 0x02
#define LINUX_MAP_ANONYMOUS 0x20


static const char prefix[] = "user.";
#define PREFIX_LEN (sizeof(prefix) - 1)

static int has_prefix(const char* name)
{
	for (__SIZE_TYPE__ i = 0; i < PREFIX_LEN; i++)
		if (name[i] != prefix[i])
			return 0;
	return 1;
}

long xattr_linux_name(const char* name, char* out)
{
	__SIZE_TYPE__ len;

	if (!name)
		return -EFAULT;
	len = strlen(name);
	if (len == 0)
		return -EINVAL;
	if (len > XATTR_MAXNAMELEN)
		return -ENAMETOOLONG;
	memcpy(out, prefix, PREFIX_LEN);
	memcpy(out + PREFIX_LEN, name, len + 1);
	return 0;
}

int xattr_linux_flags(int options)
{
	return ((options & XATTR_CREATE) ? LINUX_XATTR_CREATE : 0) | ((options & XATTR_REPLACE) ? LINUX_XATTR_REPLACE : 0);
}

long xattr_errno(long linux_error)
{
	return linux_error == -LINUX_ENODATA ? -ENOATTR : errno_linux_to_bsd(linux_error);
}

long xattr_path(const char* path, int options, struct vchroot_expand_args* vc)
{
	if (!path)
		return -EFAULT;
	vc->flags = (options & XATTR_NOFOLLOW) ? 0 : VCHROOT_FOLLOW;
	vc->dfd = get_perthread_wd();
	strcpy(vc->path, path);
	long rv = vchroot_expand(vc);
	return rv < 0 ? errno_linux_to_bsd(rv) : 0;
}

long xattr_list(long (*list)(long object, char* buf, unsigned long size), long object, char* namebuf,
	unsigned long size)
{
	char small[1024];
	char* names = small;
	long len = list(object, small, sizeof(small));
	long total = 0;

	// more names than fit: in a buffer as big as Linux's lists get
	if (len == -LINUX_ERANGE)
	{
		names = (char*) LINUX_SYSCALL6(__NR_mmap, 0, LINUX_XATTR_LIST_MAX, LINUX_PROT_READ | LINUX_PROT_WRITE,
			LINUX_MAP_PRIVATE | LINUX_MAP_ANONYMOUS, -1, 0);
		if ((unsigned long) names > -4096UL)
			return errno_linux_to_bsd((long) names);
		len = list(object, names, LINUX_XATTR_LIST_MAX);
	}

	for (long off = 0; len > 0 && off < len;)
	{
		const char* name = names + off;
		__SIZE_TYPE__ n = strlen(name);

		off += n + 1;
		if (n <= PREFIX_LEN || !has_prefix(name))
			continue;
		n -= PREFIX_LEN;
		if (namebuf && size)
		{
			if (total + n + 1 > size)
			{
				total = -ERANGE;
				break;
			}
			memcpy(namebuf + total, name + PREFIX_LEN, n + 1);
		}
		total += n + 1;
	}

	if (names != small)
		LINUX_SYSCALL(__NR_munmap, names, LINUX_XATTR_LIST_MAX);
	if (len < 0)
		return errno_linux_to_bsd(len);
	return total;
}

static const char finder_info[] = "user.com.apple.FinderInfo";

void xattr_finder_info_get(int dirfd, const char* lookup, char* out)
{
	char path[64 + 256];
	long rv;

	if (dirfd == LINUX_AT_FDCWD)
		rv = LINUX_SYSCALL(__NR_getxattr, lookup, finder_info, out, XATTR_FINDERINFO_SIZE);
	else
	{
		// Linux has no getxattrat(): the entry, through its directory's descriptor
		__simple_sprintf(path, "/proc/self/fd/%d/%s", dirfd, lookup);
		rv = LINUX_SYSCALL(__NR_lgetxattr, path, finder_info, out, XATTR_FINDERINFO_SIZE);
	}
	if (rv != XATTR_FINDERINFO_SIZE)
		memset(out, 0, XATTR_FINDERINFO_SIZE);
}

long xattr_finder_info_set(const char* linux_path, int nofollow, int fd, const char* in)
{
	int empty = 1;
	long rv;

	for (int i = 0; i < XATTR_FINDERINFO_SIZE; i++)
		if (in[i])
			empty = 0;

	if (empty)
	{
		if (!linux_path)
			rv = LINUX_SYSCALL(__NR_fremovexattr, fd, finder_info);
		else if (nofollow)
			rv = LINUX_SYSCALL(__NR_lremovexattr, linux_path, finder_info);
		else
			rv = LINUX_SYSCALL(__NR_removexattr, linux_path, finder_info);
		if (rv == -LINUX_ENODATA)
			rv = 0;
	}
	else if (!linux_path)
		rv = LINUX_SYSCALL(__NR_fsetxattr, fd, finder_info, in, XATTR_FINDERINFO_SIZE, 0);
	else if (nofollow)
		rv = LINUX_SYSCALL(__NR_lsetxattr, linux_path, finder_info, in, XATTR_FINDERINFO_SIZE, 0);
	else
		rv = LINUX_SYSCALL(__NR_setxattr, linux_path, finder_info, in, XATTR_FINDERINFO_SIZE, 0);

	return rv < 0 ? errno_linux_to_bsd(rv) : 0;
}
