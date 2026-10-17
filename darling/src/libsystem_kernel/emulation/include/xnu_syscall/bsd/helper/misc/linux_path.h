#ifndef DARLING_EMULATION_LINUX_PATH_H
#define DARLING_EMULATION_LINUX_PATH_H

// What Linux says about a path that is already a Linux one (vchroot_expand()'s), relative to dfd: LINUX_AT_FDCWD, or a
// descriptor (with "" and LINUX_AT_EMPTY_PATH for the descriptor itself). Each returns 0 or a negative XNU errno, as a
// system call does.

#include <darling/emulation/conversion/stat/common.h>

// fstatat(): flags LINUX_AT_SYMLINK_NOFOLLOW, LINUX_AT_EMPTY_PATH
long linux_path_stat(int dfd, const char* path, int flags, struct linux_stat* st);

// faccessat2(): access as the real ids, or with LINUX_AT_EACCESS as the effective ones; flags also
// LINUX_AT_SYMLINK_NOFOLLOW and LINUX_AT_EMPTY_PATH. Where Linux has no faccessat2() (before 5.8, or a seccomp profile
// filters it, answering ENOSYS or EPERM), faccessat() answers, which takes no flags: as the real ids (Darling doesn't
// make the Linux real and effective ids differ), about a symbolic link's target, and about a descriptor through
// /proc/self/fd.
long linux_path_access(int dfd, const char* path, int mode, int flags);

// statx()'s answers that struct linux_stat doesn't have
struct linux_path_statx
{
	unsigned int mask; // the LINUX_STATX_* fields Linux filled in
	unsigned long long attributes; // LINUX_STATX_ATTR_*: what the file is...
	unsigned long long attributes_mask; // ...of what the file system can tell
	unsigned long long mnt_id; // with LINUX_STATX_MNT_ID
	unsigned int dev_major, dev_minor;
};
#define LINUX_STATX_MNT_ID 0x00001000U
// chattr's +i and +a
#define LINUX_STATX_ATTR_IMMUTABLE 0x00000010ULL
#define LINUX_STATX_ATTR_APPEND 0x00000020ULL

// statx(): flags LINUX_AT_SYMLINK_NOFOLLOW, LINUX_AT_EMPTY_PATH; mask the LINUX_STATX_* fields wanted
long linux_path_statx(int dfd, const char* path, int flags, unsigned int mask, struct linux_path_statx* out);

// The directory the path's last component is in, into out (room for VCHROOT_PATH_MAX). The path is absolute with its
// symbolic links resolved (vchroot_expand() with VCHROOT_FOLLOW), so this is namei()'s WANTPARENT directory. The root
// (the "/" the process sees) is its own parent, as namei() returns it for "/".
long linux_path_parent(const char* path, char* out);

#endif // DARLING_EMULATION_LINUX_PATH_H
