#ifndef DARLING_EMULATION_FILEID_H
#define DARLING_EMULATION_FILEID_H

// A file system object's path by its volume and object ID (ATTR_CMN_FSID's first word, mounts_volume(); and st_ino):
// what fsgetpath() answers (impl/misc/fsgetpath.c).

// The path of (dev, objid) as the process sees it (under the prefix, or /Volumes/SystemRoot outside it), into out (size
// bytes) unless out is NULL: its length counting the NUL; or -ENOTSUP for a volume no mount is of, -ENOENT for an
// object the volume doesn't have, -ENOSPC for a path longer than size (XNU errnos). mount_id is a hint: the Linux mount
// the ID was handed out for (mounts_fsid()'s second word), or 0.
long fileid_find(unsigned long long dev, unsigned long long mount_id, unsigned long long objid, char* out,
	unsigned long size);

// whether fileid_find() finds the objects of the volume the object open as fd is on (VOL_CAP_FMT_PATH_FROM_ID):
// whether they report the device of a mount, where its search starts
int fileid_volume_searchable(int fd);

#endif // DARLING_EMULATION_FILEID_H
