#ifndef DARLING_EMULATION_MOUNTS_H
#define DARLING_EMULATION_MOUNTS_H

#include <darling/emulation/conversion/stat/common.h>

// statfs() as XNU answers it, from Linux's /proc/self/mounts: a mount point is a path as the process sees it (under
// the prefix, or /Volumes/SystemRoot outside it), and the file system's ID is the device the object is on, as
// ATTR_CMN_FSID and ATTR_CMN_DEVID report it.

// the file system an absolute Linux path is on
long mounts_statfs(const char* linux_path, struct bsd_statfs64* buf);

// the file systems mounted on a directory, into buf (count of them) when it isn't NULL; returns how many there are
long mounts_list(struct bsd_statfs64* buf, long count);

#endif // DARLING_EMULATION_MOUNTS_H
