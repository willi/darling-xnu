#ifndef LINUX_OPENAT_H
#define LINUX_OPENAT_H

long sys_openat(int fd, const char* filename, int flags, unsigned int mode);
long sys_openat_nocancel(int fd, const char* filename, int flags, unsigned int mode);
// both, and open's: cp, the cancelable call's, whose open a cancel interrupts (a FIFO's waits for its peer)
long openat_body(int fd, const char* filename, int flags, unsigned int mode, int cp);

#endif // LINUX_OPENAT_H
