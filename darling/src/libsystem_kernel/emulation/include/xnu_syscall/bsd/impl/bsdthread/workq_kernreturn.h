#ifndef WORKQ_KERNRETURN_H
#define WORKQ_KERNRETURN_H

#include <stdbool.h>
#include <stdint.h>

#define PRIVATE 1
#include <sys/event.h>

// The process's workqueue threads, which libpthread's _start_wqthread runs libdispatch on, and which come back to
// the kernel through workq_kernreturn(). This is the thread pool; the kqueues that need threads (the kevent
// workqueue in kqueue/kevent_workq.c, workloops in kqueue/kevent_id.c) decide what the threads do.

// what XNU hands a kevent workqueue thread at most at once
#define WQ_KEVENT_LIST_LEN 16

// _start_wqthread's flags
#define WQ_FLAG_THREAD_PRIO_SCHED    0x00008000
#define WQ_FLAG_THREAD_PRIO_QOS      0x00004000
#define WQ_FLAG_THREAD_PRIO_MASK     0x00000fff
#define WQ_FLAG_THREAD_OVERCOMMIT    0x00010000
#define WQ_FLAG_THREAD_REUSE         0x00020000
#define WQ_FLAG_THREAD_NEWSPI        0x00040000
#define WQ_FLAG_THREAD_KEVENT        0x00080000
#define WQ_FLAG_THREAD_EVENT_MANAGER 0x00100000
#define WQ_FLAG_THREAD_TSD_BASE_SET  0x00200000
#define WQ_FLAG_THREAD_WORKLOOP      0x00400000
#define WQ_FLAG_THREAD_OUTSIDEQOS    0x00800000

// the event count that makes _start_wqthread terminate the thread
#define WORKQ_EXIT_THREAD_NKEVENT (-1)

long sys_workq_kernreturn(int options, void* item, int affinity, int prio);

// What a workqueue thread enters libdispatch with.
struct workq_batch
{
	struct kevent_qos_s* events; // for a workloop, right after its id
	int nevents;
	int flags; // WQ_FLAG_THREAD_*
};

// Runs on the thread that answers a request, right before it enters libdispatch: fills in `batch`, or returns
// false if there turned out to be nothing to do, in which case the thread goes back to the pool. It may block
// for as long as it likes (the kevent workqueue's event manager waits for its first batch in it).
typedef bool (*workq_prepare_f)(void* context, struct workq_batch* batch);

// Wakes up a parked thread, or starts a new one, to call `prepare` and enter libdispatch. These threads don't
// count against the limit of WQOPS_QUEUE_REQTHREADS threads, so a request never blocks. If no thread can start, the
// request waits for the next one that does: a thread that parks, or one started for a later request.
void workq_thread_request(workq_prepare_f prepare, void* context);

// From a workqueue thread that has been in libdispatch: enters it again with `batch`.
void __attribute__((noreturn)) workq_thread_enter(const struct workq_batch* batch);

// From a thread that answered workq_thread_request(): returns it to the pool.
void __attribute__((noreturn)) workq_thread_return(void);

// The WQ_FLAG_THREAD_* that run a thread at `priority` (a pthread_priority_t).
int workq_thread_flags(unsigned long priority);

// The child of a fork has none of the parent's threads.
void workq_atfork_child(void);

int sem_down(int* sem, int timeout);
void sem_up(int* sem);

#endif // WORKQ_KERNRETURN_H
