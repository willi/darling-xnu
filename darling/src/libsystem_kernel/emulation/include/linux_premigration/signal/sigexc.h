#ifndef _SIGEXC_H
#define _SIGEXC_H

#include <stdbool.h>

#include "rtsig.h"
#include <darling/emulation/xnu_syscall/bsd/impl/signal/sigaction.h>

// NOTE: Keep these definitions up to date with lkm/darling/binfmt.c!
// Uses one of the below magic values to toggle the debugging state
#define SIGNAL_SIGEXC_SUSPEND	LINUX_SIGRTMIN
#define SIGNAL_S2C (LINUX_SIGRTMIN + 1)

void sigexc_setup(void);

// for PT_SIGEXC to handle this operation synchronously
void darling_sigexc_self(void);
void sigexc_handler(int linux_signum, struct linux_siginfo* info, struct linux_ucontext* ctxt);

// the hooks mldr calls on a thread it starts (elfcalls.h: signal_stack_setup, signal_stack_teardown)
int sigexc_thread_setup(void** stack);
void sigexc_thread_teardown(void* stack);

#endif // _SIGEXC_H
