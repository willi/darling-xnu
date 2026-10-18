#ifndef DARLING_EMULATION_MOUNTS_H
#define DARLING_EMULATION_MOUNTS_H

#include <darling/emulation/conversion/stat/common.h>

// statfs() as XNU answers it: the numbers are Linux's for the object itself; its mount (Linux's mount ID, looked up in
// /proc/self/mountinfo) names the mount point, as a path the process sees (under the prefix, or /Volumes/SystemRoot
// outside it); and the file system's ID is the device the object is on, as ATTR_CMN_FSID and ATTR_CMN_DEVID report it.

// the file system the object open as fd is on; as XNU, EBADF for no such descriptor and EINVAL for one that isn't a
// file (a pipe, a socket)
long mounts_fstatfs(int fd, struct bsd_statfs64* buf);

// the file system an absolute Linux path is on
long mounts_statfs(const char* linux_path, struct bsd_statfs64* buf);

// the file systems mounted on a directory, into buf (count of them) when it isn't NULL; returns how many there are
long mounts_list(struct bsd_statfs64* buf, long count);

// the root directory of a file system mounts_*statfs() described, opened O_PATH; or an error
long mounts_open_root(const struct bsd_statfs64* fs);

// calls each() with the mount point (a Linux path) of every mount whose root directory is on device dev (as the 32 bits
// statfs()'s f_fsid has) and that no
// other mount covers, until it returns nonzero (which is returned); 0 when none did, or a negative XNU errno
long mounts_each_root(unsigned long long dev, int (*each)(const char* linux_mount_point, void* ctx), void* ctx);

// The Linux mount an object is on (XNU's vnode_mount()), by Linux's mount ID: a file system's device numbers don't tell,
// as an overlay reports its own for directories and its layers' for files. 1 and the ID, or 0 when Linux can't tell
// (before Linux 5.8, without STATX_MNT_ID; or without statx() at all: ENOSYS, or EPERM from a seccomp profile), or a
// negative XNU errno. dfd, path and flags are statx()'s.
long mounts_id(int dfd, const char* path, int flags, unsigned long long* id);

// whether Linux statfs()'s f_type is a file system of files (what an XNU descriptor is a vnode of), and not the one of
// pipes, of sockets or of anonymous inodes (epoll, eventfd, ...)
int mounts_fs_has_files(long f_type);

// a file system's volume name: its mount point's last component, and "Macintosh HD" for the root, where a Mac's
// iOS Simulator files are
const char* mounts_volume_name(const struct bsd_statfs64* fs);

#endif // DARLING_EMULATION_MOUNTS_H
