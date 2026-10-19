#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigwait.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigaction.h>

static long sigwait_body(sigset_t* set, int* sig, int cp);

long sys_sigwait(sigset_t* set, int* sig)
{
	CANCELATION_POINT();
	return sigwait_body(set, sig, 1);
}

long sys_sigwait_nocancel(sigset_t* set, int* sig)
{
	return sigwait_body(set, sig, 0);
}

static long sigwait_body(sigset_t* set, int* sig, int cp)
{
	linux_sigset_t set_linux;
	int ret;
	struct linux_siginfo si;

	sigset_bsd_to_linux(set, &set_linux);

	ret = LINUX_SYSCALL_MAYBE_CP(cp, __NR_rt_sigtimedwait, &set_linux, &si, NULL, 8);

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else if (sig)
		*sig = signum_linux_to_bsd(si.si_signo);

	return ret;
}
