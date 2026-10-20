#include <darling/emulation/xnu_syscall/bsd/impl/process/getpriority.h>

#include <darling/emulation/conversion/errno.h>

// Errors as XNU's (B61). The value is still Linux's: 20 - nice, 1 to 40, not XNU's nice value.
int sys_getpriority(int which, id_t who) {
	int ret = LINUX_SYSCALL(__NR_getpriority, which, who);
	return ret < 0 ? errno_linux_to_bsd(ret) : ret;
}
