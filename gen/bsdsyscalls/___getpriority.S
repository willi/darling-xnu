// getpriority(2)'s stub. Darling (B62), x86_64: the emulation answers Linux's value, 20 - nice (1 to 40), for which
// no error can be mistaken. XNU's nice (-20 to 20) can be negative, and a negative answer is an error here. The
// stub turns it into the nice value after the error test, so an error is still -1 with errno set.
// create-syscalls.pl copies this to gen/bsdsyscalls/___getpriority.S and adds the _getpriority alias.
// i386 keeps the generated stub: Darling's i386 syscall path never sets CF, so no i386 stub sees an error, and
// converting there would turn an error into a nice value.

#define __SYSCALL_32BIT_ARG_BYTES 8
#include "SYS.h"

#ifndef SYS_getpriority
#error "SYS_getpriority not defined. The header files libsyscall is building against do not match syscalls.master."
#endif

#if defined(__arm64__)
MI_ENTRY_POINT(___getpriority)
SYSCALL_NONAME(getpriority, 2, cerror_nocancel)
ret
#elif defined(DARLING) && defined(__x86_64__)
LEAF(___getpriority, 0)
	UNIX_SYSCALL_NONAME(getpriority, 2, cerror_nocancel)
	negl	%eax
	addl	$20, %eax
	ret
#else
#if defined(__arm64__) || defined(__i386__) || defined(__x86_64__) || defined(__ppc__)
__SYSCALL2(___getpriority, getpriority, 2, cerror_nocancel)
#endif
#endif
#if defined(__arm64__)
	.globl	_getpriority
	.set	_getpriority, ___getpriority
#endif

#if defined(__i386__)
	.globl	_getpriority
	.set	_getpriority, ___getpriority
#endif

#if defined(__x86_64__)
	.globl	_getpriority
	.set	_getpriority, ___getpriority
#endif

#if defined(__ppc__)
	.globl	_getpriority
	.set	_getpriority, ___getpriority
#endif

