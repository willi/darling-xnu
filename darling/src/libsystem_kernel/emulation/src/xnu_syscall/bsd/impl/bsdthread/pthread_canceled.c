#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/pthread_canceled.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/tsd.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>

_Static_assert(__DARLING_CANCEL_KEY == __PTK_DARLING_CANCEL, "cancelable.h's slot");
#if defined(__x86_64__)
// the assembly reads the flags at %gs:__DARLING_CANCEL_GS_OFFSET; i386's has no cancelable entry of its own
_Static_assert(__PTK_DARLING_CANCEL * sizeof(void*) == __DARLING_CANCEL_GS_OFFSET, "the slot's offset from %gs");
#endif

// XNU's __pthread_canceled (xnu-7195.141.2 bsd/kern/kern_sig.c 1027-1055; xnu-12377.1.9 970), on the thread's own
// flags: no darlingserver call
long sys_pthread_canceled(int action)
{
	switch (action) {
	case 1:
		__darling_cancel_flags_clear(DARLING_UT_CANCELDISABLE);
		return 0;
	case 2:
		__darling_cancel_flags_set(DARLING_UT_CANCELDISABLE);
		return 0;
	case 0:
	default:
		for (;;) {
			unsigned long flags = __darling_cancel_flags();
			if (!__darling_cancel_pending(flags))
				return -EINVAL;
			if (__darling_cancel_flags_swap(flags, (flags & ~DARLING_UT_CANCEL) | DARLING_UT_CANCELED))
				return 0;
		}
	}
}
