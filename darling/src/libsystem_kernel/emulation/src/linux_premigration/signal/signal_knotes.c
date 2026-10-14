#include <darling/emulation/linux_premigration/signal/signal_knotes.h>

#include <stddef.h>
#include <stdint.h>
#include <libsimple/lock.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

extern void* memset(void* dest, int v, __SIZE_TYPE__ len);

#define SIGNAL_KNOTES_MAX 256

// A slot is the signal number in the upper half and the descriptor in the lower one, or 0 when it's free, so that a
// handler reads both at once: read apart, a slot freed and reused meanwhile could pair one knote's signal with
// another's descriptor.
static uint64_t signal_knotes[SIGNAL_KNOTES_MAX];
// serializes opening and closing
static libsimple_lock_t signal_knotes_lock = LIBSIMPLE_LOCK_INITIALIZER;
// signal handlers that may be about to write to a registered eventfd
static int signal_knotes_posting;

static inline uint64_t slot_make(int signum, int fd)
{
	return ((uint64_t) signum << 32) | (uint32_t) fd;
}

// With every signal blocked, a signal handler on this thread can't run while it holds the lock or is posting (and
// wait on itself in signal_knote_close()).
static void block_signals(linux_sigset_t* old)
{
	linux_sigset_t all = ~0ULL;
	LINUX_SYSCALL(__NR_rt_sigprocmask, 0 /* LINUX_SIG_BLOCK */, &all, old, sizeof(linux_sigset_t));
}

static void restore_signals(const linux_sigset_t* old)
{
	LINUX_SYSCALL(__NR_rt_sigprocmask, 2 /* LINUX_SIG_SETMASK */, old, NULL, sizeof(linux_sigset_t));
}

int signal_knote_open(int signum)
{
	linux_sigset_t old;
	int fd, i, ret;

	if (signum <= 0 || signum >= 32)
		return -LINUX_EINVAL;

	fd = LINUX_SYSCALL(__NR_eventfd2, 0, LINUX_O_NONBLOCK | LINUX_O_CLOEXEC);
	if (fd < 0)
		return fd;
	// the program can't close it from under the handlers, and a fork's child closes it (it counts the parent's signals)
	ret = guard_table_add(fd, guard_flag_prevent_close | guard_flag_close_on_fork, NULL);
	if (ret < 0)
	{
		LINUX_SYSCALL1(__NR_close, fd);
		return -LINUX_ENOMEM;
	}

	block_signals(&old);
	libsimple_lock_lock(&signal_knotes_lock);
	for (i = 0; i < SIGNAL_KNOTES_MAX; i++)
	{
		if (signal_knotes[i] == 0)
		{
			__atomic_store_n(&signal_knotes[i], slot_make(signum, fd), __ATOMIC_SEQ_CST);
			break;
		}
	}
	libsimple_lock_unlock(&signal_knotes_lock);
	restore_signals(&old);

	if (i == SIGNAL_KNOTES_MAX)
	{
		guard_table_remove(fd);
		LINUX_SYSCALL1(__NR_close, fd);
		return -LINUX_ENOMEM;
	}
	return fd;
}

void signal_knote_close(int fd)
{
	linux_sigset_t old;
	int i;

	block_signals(&old);
	libsimple_lock_lock(&signal_knotes_lock);
	for (i = 0; i < SIGNAL_KNOTES_MAX; i++)
	{
		uint64_t slot = signal_knotes[i];
		if (slot != 0 && (int) (uint32_t) slot == fd)
		{
			__atomic_store_n(&signal_knotes[i], 0, __ATOMIC_SEQ_CST);
			break;
		}
	}
	libsimple_lock_unlock(&signal_knotes_lock);
	restore_signals(&old);

	// A handler that read the slot before it was freed may still write to the descriptor. Sequentially consistent with
	// the handler's increment and load: either it sees the slot freed, or this sees it posting.
	while (__atomic_load_n(&signal_knotes_posting, __ATOMIC_SEQ_CST) != 0)
		LINUX_SYSCALL0(__NR_sched_yield);

	guard_table_remove(fd);
	LINUX_SYSCALL1(__NR_close, fd);
}

void signal_knotes_post(int signum)
{
	static const uint64_t one = 1;
	linux_sigset_t old;
	int i;

	if (signum <= 0 || signum >= 32)
		return;

	block_signals(&old);
	__atomic_add_fetch(&signal_knotes_posting, 1, __ATOMIC_SEQ_CST);
	for (i = 0; i < SIGNAL_KNOTES_MAX; i++)
	{
		uint64_t slot = __atomic_load_n(&signal_knotes[i], __ATOMIC_SEQ_CST);
		if (slot != 0 && (int) (slot >> 32) == signum)
			LINUX_SYSCALL(__NR_write, (int) (uint32_t) slot, &one, sizeof(one));
	}
	__atomic_sub_fetch(&signal_knotes_posting, 1, __ATOMIC_SEQ_CST);
	restore_signals(&old);
}

void signal_knotes_atfork_child(void)
{
	memset(signal_knotes, 0, sizeof(signal_knotes));
	signal_knotes_posting = 0;
	libsimple_lock_init(&signal_knotes_lock);
}
