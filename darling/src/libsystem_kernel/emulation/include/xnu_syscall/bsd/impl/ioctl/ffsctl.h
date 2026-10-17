#ifndef EMU_FFSCTL_H
#define EMU_FFSCTL_H

long sys_ffsctl(int fd, unsigned long cmd, void* data, unsigned int options);
long sys_fsctl(const char* path, unsigned long cmd, void* data, unsigned int options);

#endif // EMU_FFSCTL_H
