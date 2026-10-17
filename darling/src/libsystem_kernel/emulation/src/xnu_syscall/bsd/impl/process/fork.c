#include <darling/emulation/xnu_syscall/bsd/impl/process/fork.h>
#include <darling/emulation/xnu_syscall/bsd/impl/psynch/ulock_wait.h>

#include <_libkernel_init.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/signal/duct_signals.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/fchdir.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/common/simple.h>
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

#include <darlingserver/rpc.h>

extern _libkernel_functions_t _libkernel_functions;
extern int _mach_fork_parent(void);
extern void kqueue_atfork(void);

libsimple_lock_t fork_special_ports_lock = LIBSIMPLE_LOCK_INITIALIZER;

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
	int wdfd = get_perthread_wd();

	__darling_fork_prepare();
#ifdef SYS_fork
	ret = LINUX_SYSCALL(__NR_fork);
#else
	ret = LINUX_SYSCALL(__NR_clone, LINUX_SIGCHLD, 0);
#endif
	if (ret != 0)
		__darling_fork_parent();
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else if (ret == 0)
	{
		// in the child
		__darling_fork_child();

#ifndef VARIANT_DYLD
		// before guard_table_postfork_child closes the parent's knote eventfds, whose numbers the new RPC socket may
		// take: a signal meanwhile would write to it
		signal_knotes_atfork_child();

		// the socket tables' locks, before a signal handler can take them (socktables.h)
		socket_tables_atfork_child();
#endif

		// the old RPC FD will be closed in `guard_table_postfork_child`;
		// we don't need to close it ourselves.
		// that should also take care of closing descriptors for any other threads.
		guard_table_postfork_child();
		purgeable_atfork_child();

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
	}
#ifndef VARIANT_DYLD
	else if (ret > 0)
	{
		// wait for the child's darlingserver checkin
		_mach_fork_parent();
	}
#endif

	return ret;
}
