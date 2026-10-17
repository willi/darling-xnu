#include <darling/emulation/xnu_syscall/bsd/helper/misc/linux_path.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

extern char* strcpy(char* dst, const char* src);
extern __SIZE_TYPE__ strlen(const char* str);

#ifndef __NR_fstatat64
#	define __NR_fstatat64 __NR_newfstatat
#endif
#ifndef __NR_faccessat2
#	define __NR_faccessat2 439 // Linux 5.8, the same number on every architecture
#endif

// struct statx's offsets
#define LINUX_STX_MASK 0x00
#define LINUX_STX_ATTRIBUTES 0x08
#define LINUX_STX_ATTRIBUTES_MASK 0x38
#define LINUX_STX_DEV_MAJOR 0x88
#define LINUX_STX_DEV_MINOR 0x8C
#define LINUX_STX_MNT_ID 0x90

long linux_path_stat(int dfd, const char* path, int flags, struct linux_stat* st)
{
	int ret = LINUX_SYSCALL(__NR_fstatat64, dfd, path, st, flags);
	return ret < 0 ? errno_linux_to_bsd(ret) : 0;
}

// Whether faccessat2() answers, asked once: about "/", which exists. An error then is the kernel's or a seccomp profile's
// (ENOSYS, or EPERM), and can't be told from an answer about a file later (EPERM for an immutable one).
static int faccessat2_works = -1;

static int have_faccessat2(void)
{
	if (faccessat2_works < 0)
		faccessat2_works = LINUX_SYSCALL(__NR_faccessat2, LINUX_AT_FDCWD, "/", 0, 0) == 0;
	return faccessat2_works;
}

long linux_path_access(int dfd, const char* path, int mode, int flags)
{
	char fdpath[32];
	int ret;

	if (have_faccessat2())
		ret = LINUX_SYSCALL(__NR_faccessat2, dfd, path, mode, flags);
	else if ((flags & LINUX_AT_EMPTY_PATH) && path[0] == '\0')
	{
		__simple_sprintf(fdpath, "/proc/self/fd/%d", dfd);
		ret = LINUX_SYSCALL(__NR_faccessat, LINUX_AT_FDCWD, fdpath, mode);
	}
	else
		ret = LINUX_SYSCALL(__NR_faccessat, dfd, path, mode);
	return ret < 0 ? errno_linux_to_bsd(ret) : 0;
}

long linux_path_statx(int dfd, const char* path, int flags, unsigned int mask, struct linux_path_statx* out)
{
	unsigned char stx[256] __attribute__((aligned(8)));
	int ret = LINUX_SYSCALL(__NR_statx, dfd, path, flags, mask, stx);

	if (ret < 0)
		return errno_linux_to_bsd(ret);
	out->mask = *(unsigned int*) (stx + LINUX_STX_MASK);
	out->attributes = *(unsigned long long*) (stx + LINUX_STX_ATTRIBUTES);
	out->attributes_mask = *(unsigned long long*) (stx + LINUX_STX_ATTRIBUTES_MASK);
	out->mnt_id = (out->mask & LINUX_STATX_MNT_ID) ? *(unsigned long long*) (stx + LINUX_STX_MNT_ID) : 0;
	out->dev_major = *(unsigned int*) (stx + LINUX_STX_DEV_MAJOR);
	out->dev_minor = *(unsigned int*) (stx + LINUX_STX_DEV_MINOR);
	return 0;
}

long linux_path_parent(const char* path, char* out)
{
	__SIZE_TYPE__ len = strlen(path);

	if (len >= VCHROOT_PATH_MAX)
		return -ENAMETOOLONG;
	strcpy(out, path);
	if (vchroot_is_root(path))
		return 0;
	while (len > 1 && out[len - 1] == '/')
		len--;
	while (len > 0 && out[len - 1] != '/')
		len--;
	while (len > 1 && out[len - 1] == '/')
		len--;
	if (len == 0)
		len = 1; // "/"
	out[len] = '\0';
	return 0;
}
