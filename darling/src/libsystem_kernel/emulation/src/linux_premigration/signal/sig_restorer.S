.text
.globl _sig_restorer
.private_extern _sig_restorer

#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

#ifdef __x86_64__

// The ucontext's rip, from the frame's start: offsetof(struct linux_ucontext, uc_mcontext.gregs.rip) (sigexc.c)
#define UC_RIP	168

// Every handler libsystem_kernel installs returns here, with %rsp at its frame's ucontext, which rt_sigreturn
// resumes. A thread with a cancellation to act on (cancelable.h) that resumes in a cancelable syscall's blocking call
// (linux-syscall.S's [___darling_cp_begin, ___darling_cp_end)) resumes at ___darling_cp_cancel instead, and leaves the
// syscall with EINTR. That is how the cancel signal's handler interrupts the call (sigexc.c, cancel_handler), and how
// a cancel that came while another handler ran does: its pc was in that handler, and the syscall that handler
// interrupted, rewound to its instruction by SA_RESTART, would block again past the test at ___darling_cp_begin.
// rt_sigreturn restores every register, so these are free.
_sig_restorer:
	movq	%gs:__DARLING_CANCEL_GS_OFFSET, %r11
	andq	$__DARLING_CANCEL_TEST, %r11
	cmpq	$__DARLING_CANCEL_ACT, %r11
	jne	1f
	movq	UC_RIP(%rsp), %r11
	leaq	___darling_cp_begin(%rip), %rax
	cmpq	%rax, %r11
	jb	1f
	leaq	___darling_cp_end(%rip), %rax
	cmpq	%rax, %r11
	jae	1f
	leaq	___darling_cp_cancel(%rip), %rax
	movq	%rax, UC_RIP(%rsp)
1:
	movl $15, %eax
	syscall

#elif defined(__i386__)

_sig_restorer:
	movl $173, %eax
	int $0x80
#endif
