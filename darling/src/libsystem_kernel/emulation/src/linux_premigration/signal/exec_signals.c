#include <darling/emulation/linux_premigration/signal/exec_signals.h>

#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigaction.h>

extern void sig_restorer(void);

#define LINUX_SIG_DFL ((linux_sig_handler*) 0)
#define LINUX_SIG_IGN ((linux_sig_handler*) 1)

static inline bool in_set(linux_sigset_t set, int sig)
{
	return (set >> (sig - 1)) & 1;
}

bool sig_linux_owned(int sig)
{
	return sig == LINUX_SIGKILL || sig == LINUX_SIGSTOP || sig == LINUX_SIGCHLD || sig == LINUX_SIGTTIN
		|| sig == LINUX_SIGTTOU;
}

bool sig_default_ignore_conflated(int sig)
{
	return sig == LINUX_SIGWINCH || sig == LINUX_SIGURG;
}

void exec_signals_reset_caught(linux_sigset_t sigdefault)
{
	struct bsd___sigaction dfl = { .sa_sigaction = XNU_SIG_DFL };

	for (int sig = 1; sig < 32; sig++)
	{
		if (sig == LINUX_SIGKILL || sig == LINUX_SIGSTOP)
			continue;
		bsd_sig_handler* h = sig_handlers[sig];
		// through sys_sigaction(), which gives a sig_linux_owned() one to Linux too
		if (in_set(sigdefault, sig) || (h != XNU_SIG_DFL && h != XNU_SIG_IGN))
			sys_sigaction(signum_linux_to_bsd(sig), &dfl, NULL);
	}
}

static void set_linux(struct exec_signals_saved* saved, int sig, linux_sig_handler* h)
{
	struct linux_sigaction sa = { .sa_sigaction = h, .sa_flags = LINUX_SA_RESTORER, .sa_restorer = sig_restorer };

	if (LINUX_SYSCALL(__NR_rt_sigaction, sig, &sa, &saved->old[sig], sizeof(sa.sa_mask)) == 0)
		saved->changed |= 1u << sig;
}

void exec_signals_prepare(struct exec_signals_saved* saved, linux_sigset_t sigdefault)
{
	saved->changed = 0;
	for (int sig = 1; sig < 32; sig++)
	{
		if (sig == LINUX_SIGKILL || sig == LINUX_SIGSTOP)
			continue;
		if (sig_linux_owned(sig))
		{
			// Linux's disposition is the app's already; SETSIGDEF undoes an ignored one
			struct linux_sigaction cur;
			if (in_set(sigdefault, sig) && LINUX_SYSCALL(__NR_rt_sigaction, sig, NULL, &cur, sizeof(cur.sa_mask)) == 0
					&& cur.sa_sigaction == LINUX_SIG_IGN)
				set_linux(saved, sig, LINUX_SIG_DFL);
			continue;
		}
		// Linux resets sigexc_handler at the exec: a SETSIGDEF signal gets its default, and so does a default-ignored one
		if (in_set(sigdefault, sig) || sig_default_ignore_conflated(sig))
			continue;
		if (sig_handlers[sig] == XNU_SIG_IGN)
			set_linux(saved, sig, LINUX_SIG_IGN);
	}
}

void exec_signals_failed(const struct exec_signals_saved* saved)
{
	for (int sig = 1; sig < 32; sig++)
	{
		if (saved->changed & (1u << sig))
			LINUX_SYSCALL(__NR_rt_sigaction, sig, &saved->old[sig], NULL, sizeof(saved->old[sig].sa_mask));
	}
}

bool exec_signals_import(int sig)
{
	struct linux_sigaction old;

	if (LINUX_SYSCALL(__NR_rt_sigaction, sig, NULL, &old, sizeof(old.sa_mask)) != 0 || old.sa_sigaction != LINUX_SIG_IGN)
		return false;
	sig_handlers[sig] = XNU_SIG_IGN;
#ifdef VARIANT_DYLD
	return true;
#else
	return sig_linux_owned(sig);
#endif
}
