#include <darling/emulation/xnu_syscall/bsd/impl/process/setpriority.h>

#include <darling/emulation/conversion/errno.h>

// errors as XNU's (B61); long, as the syscall table's functions return: an int's error came back zero-extended, which
// the stub took for success (B62)
long sys_setpriority(int which, int who, int prio) {
	long ret = LINUX_SYSCALL(__NR_setpriority, which, who, prio);
	return ret < 0 ? errno_linux_to_bsd(ret) : ret;
}
