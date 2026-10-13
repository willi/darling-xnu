#ifndef LINUX_MKNODAT_H
#define LINUX_MKNODAT_H

long sys_mknodat(int fd, const char* path, int mode, int dev);

#endif // LINUX_MKNODAT_H
