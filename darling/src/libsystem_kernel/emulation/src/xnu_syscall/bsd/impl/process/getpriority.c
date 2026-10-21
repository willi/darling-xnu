#include <darling/emulation/xnu_syscall/bsd/impl/process/getpriority.h>

#include <darling/emulation/conversion/errno.h>

// Linux's answer, 20 - nice (1 to 40), or an error as XNU's (B61). Not XNU's nice value, which can be negative and
// so would read as an error: getpriority()'s x86_64 stub (libsyscall/custom/__getpriority.S) turns every success
// into 20 - it (B62). So whatever this answers for any `which` must be 20 - XNU's answer: PRIO_DARWIN_* (XNU's 0 or
// 1) included, should they be implemented. syscall(SYS_getpriority) skips the stub and still reads 20 - nice; nothing
// calls it, and a negative nice can't come back that way.
long sys_getpriority(int which, id_t who) {
	long ret = LINUX_SYSCALL(__NR_getpriority, which, who);
	return ret < 0 ? errno_linux_to_bsd(ret) : ret;
}
