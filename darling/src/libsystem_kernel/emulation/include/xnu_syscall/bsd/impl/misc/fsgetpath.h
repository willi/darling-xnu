#ifndef LINUX_FSGETPATH_H
#define LINUX_FSGETPATH_H

long sys_fsgetpath(char* buf, unsigned long size, void* fsid, unsigned long long objid);
long sys_fsgetpath_ext(char* buf, unsigned long size, void* fsid, unsigned long long objid, unsigned int options);

// whether fsgetpath() finds the objects of the volume the object open as fd is on (VOL_CAP_FMT_PATH_FROM_ID): whether
// they report the device of a mount, where its search starts
int fsgetpath_volume_searchable(int fd);

#endif // LINUX_FSGETPATH_H
