#include <darling/emulation/xnu_syscall/bsd/impl/process/fork.h>
#include <darling/emulation/xnu_syscall/bsd/impl/psynch/ulock_wait.h>

#include <_libkernel_init.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchdir.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/common/sigsafe_lock.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/other/mach/lkm.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/workq_kernreturn.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_id.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_workq.h>
#include <darling/emulation/linux_premigration/signal/signal_knotes.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/socktables.h>
#include <darling/emulation/xnu_syscall/mach/impl/purgeable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/misc/fileid_cache.h>

#include <darlingserver/rpc.h>

extern _libkernel_functions_t _libkernel_functions;
extern void kqueue_atfork(void);

libsimple_lock_t fork_special_ports_lock = LIBSIMPLE_LOCK_INITIALIZER;

#ifndef VARIANT_DYLD
// For tests (darling-tests/fork_special_ports, which sets it through dlsym()): while it's set, a fork child stops
// itself before it has an RPC socket of its own or has checked in, so that a test can signal the child or its
// parent, or kill the child, while the parent's fork() waits. Only this process has it: the child clears its copy,
// so its own forks don't stop, and exec drops it.
VISIBLE int __darling_fork_stop_child;
#endif

// clone() also returns a pidfd for the child (Linux 5.2)
#define LINUX_CLONE_PIDFD 0x00001000

// In the parent: returns once darlingserver has registered the child, whose task then has the special ports
// this process had when it forked; the caller may change them as soon as fork() returns (launchd resets its
// bootstrap port). The wait is for this child: `pidfd` (or -1) tells it from an earlier process with its PID,
// and shows it dying before it checks in. The caller closes it.
static void wait_for_child_checkin(int child, int pidfd)
{
	int result;

	do
		result = dserver_rpc_fork_wait_for_child(child, pidfd);
	while (result == -LINUX_EINTR);

	// -ESRCH: the child died before it checked in
	if (result < 0 && result != -LINUX_ESRCH)
	{
		__simple_printf("fork: waiting for the child's darlingserver checkin failed: %d\n", result);
		__simple_abort();
	}
}

long sys_fork(void)
{
	long ret;

	libsimple_lock_lock(&fork_special_ports_lock);
	ret = sys_fork_special_ports_locked();
	// the child's copy came along locked
	libsimple_lock_unlock(&fork_special_ports_lock);
	return ret;
}

long sys_fork_special_ports_locked(void)
{
	int ret;
	int pidfd = -1;
	int wdfd = get_perthread_wd();
	unsigned long long signal_mask;

	// The child starts with its signals blocked, until it has checked in on an RPC socket of its own. Until it has
	// replaced it, it has its parent's socket: a signal handler's calls (interrupt_enter first) would go out on that
	// socket, so the parent, waiting there for its fork_wait_for_child reply, could read the child's replies, and
	// darlingserver would register the child before its checkin. Signals sent meanwhile stay pending; a hardware
	// fault meanwhile kills the child, with no Mach exception or crash report. The parent's are blocked from before
	// mldr's fork handlers (which hold its socket table's lock) until after them.
	signal_mask = signals_block_all();
	__darling_fork_prepare();

	// The pidfd comes from clone() itself: opened once it returns, it could miss a child that was already reaped,
	// or refer to another process that got its PID. Without pidfds (Linux before 5.3, where mldr gives each
	// process a lifetime pipe instead), darlingserver goes by the PID.
	ret = -LINUX_ENOSYS;
	if (__dserver_get_process_lifetime_pipe() == -1)
		ret = LINUX_SYSCALL(__NR_clone, LINUX_CLONE_PIDFD | LINUX_SIGCHLD, 0, &pidfd, 0, 0);
	// no descriptor for the pidfd: fork without one
	if (ret == -LINUX_ENOSYS || ret == -LINUX_EMFILE || ret == -LINUX_ENFILE)
	{
		pidfd = -1;
#ifdef SYS_fork
		ret = LINUX_SYSCALL(__NR_fork);
#else
		ret = LINUX_SYSCALL(__NR_clone, LINUX_SIGCHLD, 0);
#endif
	}
	if (ret != 0)
	{
		__darling_fork_parent();
		signals_restore(signal_mask);
	}
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else if (ret == 0)
	{
		// in the child
		__darling_fork_child();
		// before any signal handler, which may unmap memory and take the table's lock
		purgeable_atfork_child();
		fileid_cache_atfork_child();

#ifndef VARIANT_DYLD
		// for tests: see __darling_fork_stop_child
		if (__darling_fork_stop_child)
		{
			__darling_fork_stop_child = 0;
			LINUX_SYSCALL(__NR_kill, LINUX_SYSCALL0(__NR_getpid), LINUX_SIGSTOP);
		}

		// before guard_table_postfork_child closes the parent's knote eventfds, whose numbers the new RPC socket may
		// take: a signal handler would write to it
		signal_knotes_atfork_child();

		// the socket tables' locks, before any signal handler can take them (socktables.h)
		socket_tables_atfork_child();
#endif

		// the old RPC FD will be closed in `guard_table_postfork_child`;
		// we don't need to close it ourselves.
		// that should also take care of closing descriptors for any other threads.
		guard_table_postfork_child();

		// create a new dserver RPC socket
		__dserver_per_thread_socket_refresh();
		int newReadFd = __dserver_process_lifetime_pipe_refresh();

		// guard it
		guard_entry_options_t options;
		options.close = __dserver_close_socket;
		guard_table_add(__dserver_per_thread_socket(), guard_flag_prevent_close | guard_flag_close_on_fork, &options);

		// only guard the lifetime pipe if it's used.
		if (newReadFd != -1)
		{
			options.close = __dserver_close_process_lifetime_pipe;
			guard_table_add(__dserver_get_process_lifetime_pipe(), guard_flag_prevent_close | guard_flag_close_on_fork, &options);
		}

		int dummy_stack_variable;
		if (dserver_rpc_checkin(true, &dummy_stack_variable, newReadFd) < 0) {
			// we can't do ANYTHING if darlingserver fails to acknowledge us
			__simple_printf("Failed to checkin with darlingserver after fork\n");
			__simple_abort();
		}
		if (wdfd >= 0)
			sys_fchdir(wdfd);

		__dserver_close_process_lifetime_pipe(newReadFd);

#ifndef VARIANT_DYLD
		// None of the parent's workqueue threads or kqueues exist in the child. This runs before any libSystem
		// fork handler, so before malloc is usable again: none of these may allocate or free memory.
		workq_atfork_child();
		workq_kevent_atfork_child();
		workloop_atfork_child();
		kqueue_atfork();
		ulock_atfork_child();
#endif

		// registered, on our own socket: a signal handler may run now
		signals_restore(signal_mask);
	}
	else if (ret > 0)
	{
		wait_for_child_checkin(ret, pidfd);
		if (pidfd >= 0)
			LINUX_SYSCALL(__NR_close, pidfd);
	}

	return ret;
}
