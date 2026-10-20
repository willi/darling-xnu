#ifndef _BSDTHREAD_CANCELLABLE_H
#define _BSDTHREAD_CANCELLABLE_H

// The parts above __ASSEMBLER__ are for linux-syscall.S and sig_restorer.S too, so each constant has one copy.

// A thread's cancellation state: XNU's uthread flags (bsd/sys/user.h 347-349), in the thread's own TSD slot
// (__PTK_DARLING_CANCEL) instead of the kernel, so that a cancellation point reads them without asking darlingserver.
// The thread and its cancel signal's handler (sigexc.c) are their only writers, and each write is one instruction, so
// a handler that lands in the middle of the thread's own update loses nothing. A new thread's TSD is zero.
#define DARLING_UT_CANCEL        0x8  // marked: pthread_markcancel, not yet acted on
#define DARLING_UT_CANCELED      0x10 // acted on: the thread is exiting
#define DARLING_UT_CANCELDISABLE 0x20

// __PTK_DARLING_CANCEL (common/tsd.h; pthread_canceled.c checks it), not included here: libpthread's tsd_private.h
// brings string.h's fortified macros into every file that has a cancellation point
#define __DARLING_CANCEL_KEY 204
// the slot's offset from %gs, which the assembly reads: __DARLING_CANCEL_KEY * sizeof(void*) (pthread_canceled.c)
#define __DARLING_CANCEL_GS_OFFSET 1632
// the bits XNU's test for a cancellation to act on looks at, and their value when it acts (__darling_cancel_pending)
#define __DARLING_CANCEL_TEST (DARLING_UT_CANCELDISABLE | DARLING_UT_CANCEL | DARLING_UT_CANCELED)
#define __DARLING_CANCEL_ACT DARLING_UT_CANCEL

#ifndef __ASSEMBLER__

#include <sys/errno.h>

#define __darling_cancel_slot (*(unsigned long*)(__DARLING_CANCEL_KEY * sizeof(void*)))

static inline unsigned long __darling_cancel_flags(void)
{
	unsigned long flags;
	__asm__ volatile("mov %%gs:%1, %0" : "=r" (flags) : "m" (__darling_cancel_slot));
	return flags;
}

static inline void __darling_cancel_flags_set(unsigned long bits)
{
	__asm__ volatile("or %1, %%gs:%0" : "+m" (__darling_cancel_slot) : "r" (bits));
}

static inline void __darling_cancel_flags_clear(unsigned long bits)
{
	__asm__ volatile("and %1, %%gs:%0" : "+m" (__darling_cancel_slot) : "r" (~bits));
}

// replaces the flags with new_flags if they are still old_flags
static inline int __darling_cancel_flags_swap(unsigned long old_flags, unsigned long new_flags)
{
	unsigned char swapped;
	__asm__ volatile("cmpxchg %3, %%gs:%1; sete %0"
		: "=q" (swapped), "+m" (__darling_cancel_slot), "+a" (old_flags)
		: "r" (new_flags)
		: "memory", "cc");
	return swapped;
}

// XNU's test for a cancellation to act on (bsd/kern/kern_sig.c 977 and 1046): marked, not yet acted on, not disabled
static inline int __darling_cancel_pending(unsigned long flags)
{
	return (flags & __DARLING_CANCEL_TEST) == __DARLING_CANCEL_ACT;
}

// XNU's __pthread_testcancel(1) before a cancelable syscall (kern_sig.c 969-987): EINTR, leaving the cancellation for
// the caller's cerror to act on (libpthread's _pthread_exit_if_canceled, through __pthread_canceled(0)).
#define CANCELATION_POINT() \
	if (__darling_cancel_pending(__darling_cancel_flags())) \
		return -EINTR;

#endif // __ASSEMBLER__

#endif // _BSDTHREAD_CANCELLABLE_H
