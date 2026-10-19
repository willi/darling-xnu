#include <darling/emulation/xnu_syscall/bsd/impl/process/wait4.h>

#include <sys/signal.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/process/wait4.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/linux_premigration/signal/sigexc.h>
#include <darling/emulation/xnu_syscall/bsd/impl/misc/ptrace.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

extern int getpid(void);

static long wait4_body(int pid, int* status, int options, void* rusage, int cp);

long sys_wait4(int pid, int* status, int options, void* rusage)
{
	CANCELATION_POINT();
	return wait4_body(pid, status, options, rusage, 1);
}

long sys_wait4_nocancel(int pid, int* status, int options, void* rusage)
{
	return wait4_body(pid, status, options, rusage, 0);
}

static long wait4_body(int pid, int* status, int options, void* rusage, int cp)
{
	int ret, linux_options;
	int mystatus;

	// We always need status even if the caller doesn't
	if (status == NULL)
		status = &mystatus;

	linux_options = waitopts_bsd_to_linux(options);

restart:
	ret = LINUX_SYSCALL_MAYBE_CP(cp, __NR_wait4, pid, status, linux_options, rusage);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	if ((*status & 0x7f) != 0x7f) // process terminated
	{
		int signum;

		signum = *status & 0x7f;
		*status &= ~0x7f;
		*status |= signum_linux_to_bsd(signum);
	}
	else if (*status == 0xffff) // Linux: __W_CONTINUED
		*status = 0x7f | (0x13 << 8);
	else if ((*status & 0x7f) == 0x7f) // process stopped
	{
		int signal = *status >> 8;
		signal = signum_linux_to_bsd(signal);
		*status = (*status & 0x7f) | (signal << 8);
	}

	return ret;
}
