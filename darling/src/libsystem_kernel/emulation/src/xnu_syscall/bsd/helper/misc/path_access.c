#include <darling/emulation/xnu_syscall/bsd/helper/misc/path_access.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>

extern char* strcpy(char* dst, const char* src);
extern __SIZE_TYPE__ strlen(const char* str);
extern int strcmp(const char* a, const char* b);

#define LINUX_AT_EACCESS 0x200
#define LINUX_ENOSYS 38
#ifndef __NR_faccessat2
#define __NR_faccessat2 439 // Linux 5.8, the same number on every architecture
#endif

int path_stat(const char* path, struct linux_stat* st, int nofollow)
{
	int flags = nofollow ? LINUX_AT_SYMLINK_NOFOLLOW : 0;
#ifdef __NR_newfstatat
	int ret = LINUX_SYSCALL(__NR_newfstatat, LINUX_AT_FDCWD, path, st, flags);
#else
	int ret = LINUX_SYSCALL(__NR_fstatat64, LINUX_AT_FDCWD, path, st, flags);
#endif
	return ret < 0 ? -errno_linux_to_bsd(ret) : 0;
}

int path_access(const char* path, int mode, int effective)
{
	int ret = -LINUX_ENOSYS;

	// faccessat() checks as the real ids; AT_EACCESS (as the effective ids) needs faccessat2(). Before
	// Linux 5.8 the real ids are checked instead: they differ only in a set-id program.
	if (effective)
		ret = LINUX_SYSCALL(__NR_faccessat2, LINUX_AT_FDCWD, path, mode, LINUX_AT_EACCESS);
	if (ret == -LINUX_ENOSYS)
		ret = LINUX_SYSCALL(__NR_faccessat, LINUX_AT_FDCWD, path, mode, 0);
	return ret < 0 ? -errno_linux_to_bsd(ret) : 0;
}

int path_parent(const char* path, char* out)
{
	struct vchroot_expand_args root;
	__SIZE_TYPE__ len = strlen(path);
	int ret;

	root.flags = VCHROOT_FOLLOW;
	root.dfd = LINUX_AT_FDCWD;
	strcpy(root.path, "/");
	ret = vchroot_expand(&root);
	if (ret < 0)
		return -errno_linux_to_bsd(ret);

	strcpy(out, path);
	if (strcmp(path, root.path) == 0)
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

#define LINUX_STATX_MNT_ID 0x00001000U
// struct statx's offsets: stx_mask, stx_mnt_id
#define LINUX_STX_MASK 0x00
#define LINUX_STX_MNT_ID 0x90

static int path_mount_id(const char* path, unsigned long long* id)
{
	unsigned char stx[256] __attribute__((aligned(8)));
	int ret = LINUX_SYSCALL(__NR_statx, LINUX_AT_FDCWD, path, 0, LINUX_STATX_MNT_ID, stx);

	if (ret < 0)
		return errno_linux_to_bsd(ret);
	if (!(*(unsigned int*) (stx + LINUX_STX_MASK) & LINUX_STATX_MNT_ID))
		return 0;
	*id = *(unsigned long long*) (stx + LINUX_STX_MNT_ID);
	return 1;
}

int path_same_mount(const char* a, const char* b)
{
	unsigned long long ida, idb;
	int ret = path_mount_id(a, &ida);

	if (ret <= 0)
		return ret < 0 ? ret : 1;
	ret = path_mount_id(b, &idb);
	if (ret <= 0)
		return ret < 0 ? ret : 1;
	return ida == idb;
}
