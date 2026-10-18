#ifndef _DARLING_EMULATION_SIGSAFE_LOCK_H_
#define _DARLING_EMULATION_SIGSAFE_LOCK_H_

#include <libsimple/lock.h>

#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

// Blocks every signal on this thread (SIGKILL and SIGSTOP excepted); returns the mask to restore. A hardware fault
// while they are blocked kills the process. rt_sigprocmask() can't fail with these arguments.
static inline unsigned long long signals_block_all(void)
{
	unsigned long long all = ~0ull, old;

	LINUX_SYSCALL(__NR_rt_sigprocmask, 0 /* LINUX_SIG_BLOCK */, &all, &old, sizeof(all));
	return old;
}

static inline void signals_restore(unsigned long long old)
{
	LINUX_SYSCALL(__NR_rt_sigprocmask, 2 /* LINUX_SIG_SETMASK */, &old, NULL, sizeof(old));
}

// A lock for tables the system call paths share, which a signal handler may reach too (its read(), write() or
// close() on a socket): signals are blocked while it's held, so a handler can't deadlock on its own thread's lock.
// Returns the signal mask to restore.
static inline unsigned long long sigsafe_lock(libsimple_lock_t* lock)
{
	unsigned long long old = signals_block_all();

	libsimple_lock_lock(lock);
	return old;
}

static inline void sigsafe_unlock(libsimple_lock_t* lock, unsigned long long old)
{
	libsimple_lock_unlock(lock);
	signals_restore(old);
}

#endif // _DARLING_EMULATION_SIGSAFE_LOCK_H_
