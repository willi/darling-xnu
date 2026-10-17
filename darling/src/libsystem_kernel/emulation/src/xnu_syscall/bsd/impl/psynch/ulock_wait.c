#include <darling/emulation/xnu_syscall/bsd/impl/psynch/ulock_wait.h>

#include <sys/errno.h>
#include <stdbool.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/sigsafe_lock.h>

struct timespec
{
	long tv_sec;
	long tv_nsec;
};

// XNU's ulock_wait() returns how many other threads still wait on the address. futex(FUTEX_WAIT) doesn't say, so the
// waiters are counted here, per address. Userspace relies on the count both ways: os_unfair_lock keeps its waiters
// bit while it isn't 0, and libdispatch crashes on anything but 0 when it waits for a thread event (backboardd's main
// queue) that only it waits on.
#define ULOCK_WAITERS_MAX 512

struct ulock_waiters
{
	void* addr;
	uint32_t count;
};

static libsimple_lock_t ulock_waiters_lock = LIBSIMPLE_LOCK_INITIALIZER;
static struct ulock_waiters ulock_waiters[ULOCK_WAITERS_MAX];
static unsigned int ulock_waiters_used;

// A signal handler that waits on a lock would deadlock on the table lock its thread holds: sigsafe_lock.h
static uint64_t ulock_waiters_lock_lock(void)
{
	return sigsafe_lock(&ulock_waiters_lock);
}

static void ulock_waiters_lock_unlock(uint64_t old)
{
	sigsafe_unlock(&ulock_waiters_lock, old);
}

// Counts a waiter on `addr`; false if the table is full, and then it isn't counted.
static bool ulock_waiter_add(void* addr)
{
	bool added = true;
	unsigned int i;
	uint64_t mask = ulock_waiters_lock_lock();

	for (i = 0; i < ulock_waiters_used && ulock_waiters[i].addr != addr; i++);
	if (i < ulock_waiters_used)
		ulock_waiters[i].count++;
	else if (ulock_waiters_used < ULOCK_WAITERS_MAX)
		ulock_waiters[ulock_waiters_used++] = (struct ulock_waiters) { addr, 1 };
	else
		added = false;
	ulock_waiters_lock_unlock(mask);
	return added;
}

// Uncounts a waiter on `addr`; returns how many are left.
static uint32_t ulock_waiter_remove(void* addr)
{
	uint32_t left = 0;
	unsigned int i;
	uint64_t mask = ulock_waiters_lock_lock();

	for (i = 0; i < ulock_waiters_used && ulock_waiters[i].addr != addr; i++);
	if (i < ulock_waiters_used)
	{
		left = --ulock_waiters[i].count;
		if (left == 0)
			ulock_waiters[i] = ulock_waiters[--ulock_waiters_used];
	}
	ulock_waiters_lock_unlock(mask);
	return left;
}

void ulock_atfork_child(void)
{
	// the parent's other threads, and so their waits, don't exist in the child
	libsimple_lock_init(&ulock_waiters_lock);
	ulock_waiters_used = 0;
}

// timeout is in us
long sys_ulock_wait(uint32_t operation, void* addr, uint64_t value, uint32_t timeout)
{
	int ret, op;
	struct timespec ts;
	bool no_errno = operation & XNU_ULF_NO_ERRNO;


	// char dbg[100];
	// __simple_sprintf(dbg, "ulock_wait on %p for %d ns", addr, timeout / 1000);
	// lkm_call(0x1028, dbg);

	if (timeout > 0)
	{
		ts.tv_sec = timeout / (1000*1000);
		ts.tv_nsec = (timeout % (1000*1000)) * 1000;
	}

	op = operation & XNU_UL_OPCODE_MASK;
	if (op == XNU_UL_COMPARE_AND_WAIT || op == XNU_UL_UNFAIR_LOCK)
	{
		bool counted = ulock_waiter_add(addr);

		ret = LINUX_SYSCALL(__NR_futex, addr, FUTEX_WAIT | FUTEX_PRIVATE_FLAG,
			value, (timeout != 0) ? & ts : NULL);

		uint32_t left = counted ? ulock_waiter_remove(addr) : 0;

		// as XNU does, a wait that ended (or found the value changed) returns how many other threads still wait. With
		// the table full, say there are some: userspace then takes the slow path, which is always safe for a lock.
		if (ret == 0 || ret == -LINUX_EAGAIN)
			ret = counted ? (int) left : 1;
	}
	else
		return no_errno ? -(EINVAL | 0x800) : -EINVAL;

	if (ret < 0)
	{
		ret = errno_linux_to_bsd(ret);
		if (no_errno)
			ret &= ~0x800;
	}

	return ret;
}
