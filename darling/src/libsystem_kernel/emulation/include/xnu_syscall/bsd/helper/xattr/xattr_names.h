#ifndef DARLING_EMULATION_XATTR_NAMES_H
#define DARLING_EMULATION_XATTR_NAMES_H

#include <darling/emulation/linux_premigration/vchroot_expand.h>

// Extended attributes, as XNU names them, on Linux file systems.
//
// XNU's names have no namespace (com.apple.quarantine); Linux's must have one, and refuses any other with EOPNOTSUPP.
// An attribute is kept in Linux's user namespace (user.com.apple.quarantine), as Linux's HFS+ driver and Netatalk keep
// macOS's, and listed without the prefix; attributes in Linux's other namespaces aren't listed.

#define XATTR_NOFOLLOW 0x0001
#define XATTR_CREATE 0x0002
#define XATTR_REPLACE 0x0004

#define XATTR_MAXNAMELEN 127
// "user." and the name
#define XATTR_LINUX_NAME_MAX (5 + XATTR_MAXNAMELEN + 1)

// the Linux name of the attribute named name into out; 0, or an error as XNU's for a name it refuses
long xattr_linux_name(const char* name, char* out);

// XNU's XATTR_CREATE and XATTR_REPLACE as Linux's
int xattr_linux_flags(int options);

// a Linux error as XNU's: a missing attribute is ENOATTR
long xattr_errno(long linux_error);

// path, as the process sees it, as a Linux path into vc; with XATTR_NOFOLLOW, a symlink isn't followed
long xattr_path(const char* path, int options, struct vchroot_expand_args* vc);

// lists the names of an object's attributes as XNU does (into namebuf, or only their size when it's NULL or size is
// 0); list is a Linux *listxattr() on the object
long xattr_list(long (*list)(long object, char* buf, unsigned long size), long object, char* namebuf,
	unsigned long size);

// Finder information, which XNU keeps as the com.apple.FinderInfo attribute: getattrlist() and setattrlist()'s
// ATTR_CMN_FNDRINFO read and write it, as getxattr() and setxattr() do
#define XATTR_FINDERINFO_SIZE 32

// an object's, into out: zeros when it has none. The object is lookup in dirfd (LINUX_AT_FDCWD: lookup is a Linux path,
// which is followed; otherwise a name, which isn't)
void xattr_finder_info_get(int dirfd, const char* lookup, char* out);

// sets an object's (all zeros: removes it, as XNU does), by Linux path (followed unless nofollow) or, with no path, by
// file descriptor
long xattr_finder_info_set(const char* linux_path, int nofollow, int fd, const char* in);

#endif // DARLING_EMULATION_XATTR_NAMES_H
