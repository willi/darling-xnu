#ifndef DARLING_EMULATION_ATTRLIST_PACK_H
#define DARLING_EMULATION_ATTRLIST_PACK_H

#include <stdint.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/conversion/xattr/getattrlist.h>

// The attributes of one file system object, packed as XNU's getattrlist() and getattrlistbulk() pack them
// (bsd/vfs/vfs_attrlist.c): a uint32_t length, the attribute_set_t of what was returned when that was asked for, the
// fixed-size attributes in the order of their bits (common, then directory or file, then common extended), then the
// variable-size data their attrreference_t's point to, each padded to 4 bytes.
//
// As XNU, any bit its tables know is accepted. An attribute a Linux file system has no answer for is left out, and out
// of the returned set, when the caller asked which were returned (ATTR_CMN_RETURNED_ATTRS); otherwise, or with
// FSOPT_PACK_INVAL_ATTRS, zeros take its place.

#define ATTR_BIT_MAP_COUNT 5

#define ATTR_CMN_NAME 0x00000001
#define ATTR_CMN_ERROR 0x20000000
#define ATTR_CMN_RETURNED_ATTRS 0x80000000

#define ATTR_VOL_CAPABILITIES 0x00020000
#define ATTR_VOL_INFO 0x80000000

#define FSOPT_NOFOLLOW 0x00000001
#define FSOPT_REPORT_FULLSIZE 0x00000004
#define FSOPT_PACK_INVAL_ATTRS 0x00000008
#define FSOPT_ATTR_CMN_EXTENDED 0x00000020

// the most an object packs into: the fixed-size attributes (under 600 bytes), its name, and three paths of up to
// MAXPATHLEN
#define ATTRLIST_PACK_MAX 4096

struct attrlist_object
{
	const struct linux_stat* st;
	// the directory the object is in (itself for a file system's root)
	const struct linux_stat* parent;
	// the object for faccessat() and openat() (ATTR_CMN_USERACCESS and ATTR_DIR_ENTRYCOUNT)
	int dirfd;
	const char* lookup;
	// ATTR_CMN_NAME
	const char* name;
	// as the process sees it, or NULL for no answer: ATTR_CMN_FULLPATH and the common extended paths
	const char* fullpath;
};

// 0 when XNU would accept the attributes asked of an object (a directory or not), else -EINVAL
int attrlist_check(const struct xnu_attrlist* al, uint64_t options, int is_dir);

// packs into out (ATTRLIST_PACK_MAX bytes) and returns the size, which is also the packed length
uint32_t attrlist_pack(const struct xnu_attrlist* al, uint64_t options, const struct attrlist_object* obj, char* out);

// a volume: what statfs() says of it, and its name
struct attrlist_volume
{
	const struct bsd_statfs64* fs;
	const char* name;
};

// 0 when XNU would accept the volume attributes asked for, else -EINVAL
int attrlist_check_volume(const struct xnu_attrlist* al, uint64_t options);

// the volume's attributes, and the common attributes of its root (whose name should be the volume's)
uint32_t attrlist_pack_volume(const struct xnu_attrlist* al, uint64_t options, const struct attrlist_object* root,
	const struct attrlist_volume* vol, char* out);

// what getattrlistbulk() packs for an entry it couldn't look at: its name and, when that was asked for, the error
uint32_t attrlist_pack_error(const struct xnu_attrlist* al, const char* name, int error, char* out);

#endif // DARLING_EMULATION_ATTRLIST_PACK_H
