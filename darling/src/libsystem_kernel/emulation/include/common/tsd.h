#ifndef _DARLING_EMULATION_TSD_H_
#define _DARLING_EMULATION_TSD_H_

#include <pthread/tsd_private.h>

#define __PTK_DARLING_XTRACE_TLS          __PTK_DARLING_KEY0
#define __PTK_DARLING_PERTHREAD_WD_IS_SET __PTK_DARLING_KEY1
#define __PTK_DARLING_PERTHREAD_WD_FD     __PTK_DARLING_KEY2
// the workloop a workqueue thread services (kqueue/kevent_id.c)
#define __PTK_DARLING_WORKLOOP            __PTK_DARLING_KEY3
// the thread's cancellation flags, XNU's uthread ones (bsdthread/cancelable.h)
#define __PTK_DARLING_CANCEL              __PTK_DARLING_KEY4
// the id of the work interval the thread is in, 0 for none (misc/work_interval_ctl.c)
#define __PTK_DARLING_WORK_INTERVAL       __PTK_DARLING_KEY5
// other __PTK_DARLING_KEYs are currently unused

#endif // _DARLING_EMULATION_TSD_H_
