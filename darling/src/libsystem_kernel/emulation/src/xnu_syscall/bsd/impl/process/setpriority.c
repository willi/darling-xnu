#include <darling/emulation/xnu_syscall/bsd/impl/process/setpriority.h>

#include <darling/emulation/conversion/errno.h>

// errors as XNU's (B61); long, as the syscall table's functions return: with int, the upper half of an error the
// stub sign-tests is whatever the compiler left in rax (it happened to be right)
long sys_setpriority(int which, int who, int prio) {
	long ret = LINUX_SYSCALL(__NR_setpriority, which, who, prio);
	return ret < 0 ? errno_linux_to_bsd(ret) : ret;
}
