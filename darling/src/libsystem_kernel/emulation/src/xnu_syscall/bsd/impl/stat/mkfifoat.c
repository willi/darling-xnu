#include <darling/emulation/xnu_syscall/bsd/impl/stat/mkfifoat.h>

#include <darling/emulation/xnu_syscall/bsd/impl/unistd/mknodat.h>

#define LINUX_S_IFIFO 0010000

long sys_mkfifoat(int fd, const char* path, unsigned int mode)
{
	return sys_mknodat(fd, path, mode | LINUX_S_IFIFO, 0);
}
