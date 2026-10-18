#ifndef LINUX_FSGETPATH_H
#define LINUX_FSGETPATH_H

long sys_fsgetpath(char* buf, unsigned long size, void* fsid, unsigned long long objid);
long sys_fsgetpath_ext(char* buf, unsigned long size, void* fsid, unsigned long long objid, unsigned int options);

#endif // LINUX_FSGETPATH_H
