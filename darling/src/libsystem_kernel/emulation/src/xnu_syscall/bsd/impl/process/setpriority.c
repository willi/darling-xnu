#include <darling/emulation/xnu_syscall/bsd/impl/process/setpriority.h>

#include <darling/emulation/conversion/errno.h>

// errors as XNU's (B61)
int sys_setpriority(int which, int who, int prio) {
	int ret = LINUX_SYSCALL(__NR_setpriority, which, who, prio);
	return ret < 0 ? errno_linux_to_bsd(ret) : ret;
}
