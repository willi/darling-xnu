#ifndef _SIGEXC_H
#define _SIGEXC_H

#include <stdbool.h>

#include "rtsig.h"
#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigaction.h>

// SIGNAL_SIGEXC_SUSPEND, SIGNAL_S2C and SIGNAL_PTHREAD_CANCEL, Darling's own real-time signals, are rtsig.h's
// (Darling's src/startup/rtsig.c), which darlingserver, the one that sends them, includes too.

// the three: unblocked once the handlers are in (sigexc_setup), blocked across an exec (execve.c)
#define DARLING_PRIVATE_SIGSET \
	((1ull << (SIGNAL_SIGEXC_SUSPEND-1)) | (1ull << (SIGNAL_S2C-1)) | (1ull << (SIGNAL_PTHREAD_CANCEL-1)))

void sigexc_setup(void);

// for PT_SIGEXC to handle this operation synchronously
void darling_sigexc_self(void);
void sigexc_handler(int linux_signum, struct linux_siginfo* info, struct linux_ucontext* ctxt);

// the hooks mldr calls on a thread it starts (elfcalls.h: signal_stack_setup, signal_stack_teardown)
int sigexc_thread_setup(void** stack);
void sigexc_thread_teardown(void* stack);

#endif // _SIGEXC_H
