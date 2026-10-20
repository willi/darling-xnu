.text
.globl _linux_syscall
.private_extern _linux_syscall

_linux_syscall:

#if defined(__x86_64__)

	movl	8(%rsp), %eax
	movq	%rcx, %r10
	syscall
	ret

#elif defined(__i386__)

	// With 32in64, we cannot use sysenter, because our process doesn't have a 32-bit VDSO mapped
	// and sysenter needs that for returning to user space.

	// eax, ecx and edx are caller saved, the rest is calee saved
	push	%ebx
	push	%esi
	push	%edi
	push	%ebp

	mov		20(%esp), %ebx
	mov		24(%esp), %ecx
	mov		28(%esp), %edx
	mov		32(%esp), %esi
	mov		36(%esp), %edi
	mov		40(%esp), %ebp
	mov		44(%esp), %eax

	int		$0x80

	pop		%ebp
	pop		%edi
	pop		%esi
	pop		%ebx
	ret

#elif 0 //defined(__i386__)

	push	%ebp
	push	%ebx
	push	%esi
	push	%edi
	call	1f
1:
	pop		%ebp
	addl	$(2f-1b), %ebp
	push	%ebp
	push	%ecx
	push	%edx
	movl	28+28(%esp), %eax
	movl	4+28(%esp), %ebx
	movl	8+28(%esp), %ecx
	movl	12+28(%esp), %edx
	movl	16+28(%esp), %esi
	movl	20+28(%esp), %edi
	push	%ebp
	movl	24+28(%esp), %ebp
	movl	%ebp, -4(%esp)
	movl	%esp, %ebp
	sysenter
2:
	pop %edi
	pop %esi
	pop %ebx
	pop %ebp
	ret

#else

#	error Missing assembly!

#endif

// linux_syscall for a cancelable syscall's blocking call (bsdthread/cancelable.h): the same, with XNU's test for a
// cancellation to act on (bsd/kern/kern_sig.c 977) in the range [___darling_cp_begin, ___darling_cp_end), which ends
// right after the syscall instruction. The cancel signal's handler (sigexc.c) moves a thread it finds in that range to
// ___darling_cp_cancel, which returns -EINTR: whether the thread is before the syscall or blocked in it (the kernel
// rewinds an interrupted syscall to its instruction, to restart it: the handler is SA_RESTART). A finished syscall is
// past the range, and its result stands.
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#define LINUX_EINTR	4

#if defined(__x86_64__)

.globl _linux_syscall_cp
.private_extern _linux_syscall_cp
.globl ___darling_cp_begin
.private_extern ___darling_cp_begin
.globl ___darling_cp_end
.private_extern ___darling_cp_end
.globl ___darling_cp_cancel
.private_extern ___darling_cp_cancel

_linux_syscall_cp:
	movl	8(%rsp), %eax
	movq	%rcx, %r10
___darling_cp_begin:
	movq	%gs:__DARLING_CANCEL_GS_OFFSET, %r11
	andq	$__DARLING_CANCEL_TEST, %r11
	cmpq	$__DARLING_CANCEL_ACT, %r11
	je	___darling_cp_cancel
	syscall
___darling_cp_end:
	ret
___darling_cp_cancel:
	movq	$-LINUX_EINTR, %rax
	ret

#elif defined(__i386__)

// only the test before the syscall (CANCELATION_POINT); a blocked syscall isn't interrupted
.globl _linux_syscall_cp
.private_extern _linux_syscall_cp
_linux_syscall_cp:
	jmp	_linux_syscall

#endif
