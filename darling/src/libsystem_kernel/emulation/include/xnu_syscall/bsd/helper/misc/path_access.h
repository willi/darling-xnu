#ifndef _PATH_ACCESS_H
#define _PATH_ACCESS_H

// What access_extended and clonefileat ask Linux about a path (a Linux path: vchroot_expand()'s) before
// they answer as XNU's vnode_authorize() would. Each returns 0 or a positive XNU errno.

#include <darling/emulation/conversion/stat/common.h>

#define LINUX_S_IFMT 0170000
#define LINUX_S_IFDIR 0040000
#define LINUX_S_IFREG 0100000
#define LINUX_S_IFLNK 0120000
#define LINUX_S_ISVTX 01000

// stat(), following a symbolic link at the end unless nofollow
int path_stat(const char* path, struct linux_stat* st, int nofollow);

// faccessat(): access as the real ids (as XNU's access() checks), or as the effective ids
int path_access(const char* path, int mode, int effective);

// The directory the path's last component is in. The path is absolute with its symbolic links resolved
// (vchroot_expand() with VCHROOT_FOLLOW), so this is namei()'s WANTPARENT directory. The root ("/" in the
// vchroot) is its own parent, as namei() returns it for "/". out has room for a vchroot path.
int path_parent(const char* path, char* out);

// Whether two paths are on the same mount (XNU's vnode_mount()), by Linux's mount IDs: 1 or 0, or a negative
// XNU errno. A file system's device numbers don't tell: an overlay reports its own for directories and its layers'
// for files. Before Linux 5.8 (no STATX_MNT_ID) it can't be told, and the answer is 1.
int path_same_mount(const char* a, const char* b);

// The Linux process's real uid, which Linux checks permissions as for access()
int linux_real_uid(void);

#endif // _PATH_ACCESS_H
