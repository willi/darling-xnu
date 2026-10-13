#ifndef LINUX_MKFIFOAT_H
#define LINUX_MKFIFOAT_H

long sys_mkfifoat(int fd, const char* path, unsigned int mode);

#endif // LINUX_MKFIFOAT_H
