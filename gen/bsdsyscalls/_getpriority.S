#define __SYSCALL_32BIT_ARG_BYTES 8
#include "SYS.h"

#ifndef SYS_getpriority
#error "SYS_getpriority not defined. The header files libsyscall is building against do not match syscalls.master."
#endif

#if defined(__arm64__)
MI_ENTRY_POINT(_getpriority)
SYSCALL_NONAME(getpriority, 2, cerror_nocancel)
ret
#elif defined(DARLING) && (defined(__x86_64__) || defined(__i386__))
// Darling (B62): the emulation answers Linux's value, 20 - nice (1 to 40), which no error can be taken for: XNU's
// nice (-20 to 20) can be negative, and a negative answer is an error here. This turns it into the nice value.
LEAF(_getpriority, 0)
	UNIX_SYSCALL_NONAME(getpriority, 2, cerror_nocancel)
	movl	$20, %ecx
	subl	%eax, %ecx
	movl	%ecx, %eax
	ret
#else
#if defined(__arm64__) || defined(__i386__) || defined(__x86_64__) || defined(__ppc__)
__SYSCALL2(_getpriority, getpriority, 2, cerror_nocancel)
#endif

#endif

