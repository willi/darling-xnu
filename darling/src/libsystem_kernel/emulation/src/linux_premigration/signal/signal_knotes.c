#include <darling/emulation/linux_premigration/signal/signal_knotes.h>

#include <stdint.h>
#include <libsimple/lock.h>

#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>

extern void* memset(void* dest, int v, __SIZE_TYPE__ len);

#define SIGNAL_KNOTES_MAX 256

struct signal_knote
{
	int signum; // 0 for a free slot
	int fd;
};

static struct signal_knote signal_knotes[SIGNAL_KNOTES_MAX];
// serializes registering and unregistering
static libsimple_lock_t signal_knotes_lock = LIBSIMPLE_LOCK_INITIALIZER;
// signal handlers that may be about to write to a registered eventfd
static int signal_knotes_posting;

int __darling_signal_knote_register(int signum, int eventfd)
{
	int i;

	if (signum <= 0 || signum >= 32 || eventfd < 0)
		return -LINUX_EINVAL;

	libsimple_lock_lock(&signal_knotes_lock);
	for (i = 0; i < SIGNAL_KNOTES_MAX; i++)
	{
		if (signal_knotes[i].signum != 0)
			continue;

		// the descriptor before the signal number, which a handler reads first
		signal_knotes[i].fd = eventfd;
		__atomic_store_n(&signal_knotes[i].signum, signum, __ATOMIC_RELEASE);
		break;
	}
	libsimple_lock_unlock(&signal_knotes_lock);

	return (i < SIGNAL_KNOTES_MAX) ? 0 : -LINUX_ENOSPC;
}

void __darling_signal_knote_unregister(int eventfd)
{
	int i;

	libsimple_lock_lock(&signal_knotes_lock);
	for (i = 0; i < SIGNAL_KNOTES_MAX; i++)
	{
		if (signal_knotes[i].signum != 0 && signal_knotes[i].fd == eventfd)
		{
			__atomic_store_n(&signal_knotes[i].signum, 0, __ATOMIC_RELEASE);
			break;
		}
	}
	libsimple_lock_unlock(&signal_knotes_lock);

	// a handler that saw the slot before it was freed may still write to the descriptor, which the caller closes next
	while (__atomic_load_n(&signal_knotes_posting, __ATOMIC_ACQUIRE) != 0)
		LINUX_SYSCALL0(__NR_sched_yield);
}

void signal_knotes_post(int signum)
{
	static const uint64_t one = 1;
	int i;

	__atomic_add_fetch(&signal_knotes_posting, 1, __ATOMIC_ACQ_REL);
	for (i = 0; i < SIGNAL_KNOTES_MAX; i++)
	{
		if (__atomic_load_n(&signal_knotes[i].signum, __ATOMIC_ACQUIRE) == signum)
			LINUX_SYSCALL(__NR_write, signal_knotes[i].fd, &one, sizeof(one));
	}
	__atomic_sub_fetch(&signal_knotes_posting, 1, __ATOMIC_RELEASE);
}

void signal_knotes_atfork_child(void)
{
	memset(signal_knotes, 0, sizeof(signal_knotes));
	signal_knotes_posting = 0;
	libsimple_lock_init(&signal_knotes_lock);
}
