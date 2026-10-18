#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_create.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/bsdthread_register.h>
#include <darling/emulation/linux_premigration/elfcalls_wrapper.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/machdep/impl/tls.h>
#include <darling/emulation/xnu_syscall/mach/impl/mach_traps.h>
#include <darling/emulation/xnu_syscall/bsd/impl/mman/mman.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/signal/sigexc.h>

#include <darlingserver/rpc.h>

extern void *memset(void *s, int c, size_t n);

#define PTHREAD_START_CUSTOM    0x01000000
#define PTHREAD_START_SETSCHED  0x02000000
#define PTHREAD_START_DETACHED  0x04000000
#define PTHREAD_START_POLICY_BITSHIFT 16
#define PTHREAD_START_POLICY_MASK 0xff
#define PTHREAD_START_IMPORTANCE_MASK 0xffff

static bool _uses_threads = false;

void dserver_rpc_socket_guard(int fd) {
	guard_entry_options_t options;
	options.close = __dserver_close_socket;
	guard_table_add(fd, guard_flag_prevent_close | guard_flag_close_on_fork, &options);
}

static void rpc_unguard(int fd) {
	guard_table_remove(fd);
}

const struct darling_thread_create_callbacks darling_thread_callbacks = {
	.size = sizeof(struct darling_thread_create_callbacks),
	.thread_self_trap = &thread_self_trap_impl,
	.thread_set_tsd_base = &sys_thread_set_tsd_base,
	.rpc_guard = dserver_rpc_socket_guard,
	.rpc_unguard = rpc_unguard,
	.signal_stack_setup = sigexc_thread_setup,
	.signal_stack_teardown = sigexc_thread_teardown,
};

long sys_bsdthread_create(void* thread_start, void* arg,
		void* stack, void* pthread, uint32_t flags)
{
#ifndef VARIANT_DYLD // dyld doesn't create threads
	_uses_threads = true;

	void* created = __darling_thread_create(((uintptr_t)stack), pthread_obj_size,
			pthread_entry_point_wrapper, thread_start, arg, (uintptr_t) stack, flags,
			&darling_thread_callbacks, pthread);

	// mldr couldn't start the thread. XNU's bsdthread_create fails with ENOMEM when thread_create does
	// (libpthread's kern/kern_support.c), and libpthread's pthread_create then returns EAGAIN.
	return (created != NULL) ? (long) created : -ENOMEM;
#else
	return -ENOSYS;
#endif
}

bool uses_threads(void)
{
	return _uses_threads;
}
