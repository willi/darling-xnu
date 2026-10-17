#include <darling/emulation/xnu_syscall/bsd/impl/stat/mkfifoat.h>

#include <darling/emulation/conversion/stat/common.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/mknodat.h>


long sys_mkfifoat(int fd, const char* path, unsigned int mode)
{
	// like XNU: only the permission bits of mode are used
	return sys_mknodat(fd, path, (mode & 07777) | LINUX_S_IFIFO, 0);
}
