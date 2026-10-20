#include <darling/emulation/xnu_syscall/bsd/impl/process/getpriority.h>

#include <darling/emulation/conversion/errno.h>

// Linux's answer, 20 - nice (1 to 40), or an error as XNU's (B61). Not XNU's nice value, which can be negative and
// so would read as an error: getpriority()'s stub (gen/bsdsyscalls/_getpriority.S) turns it into the nice value (B62).
long sys_getpriority(int which, id_t who) {
	long ret = LINUX_SYSCALL(__NR_getpriority, which, who);
	return ret < 0 ? errno_linux_to_bsd(ret) : ret;
}
