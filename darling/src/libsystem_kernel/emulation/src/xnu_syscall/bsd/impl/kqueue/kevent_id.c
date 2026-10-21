#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_id.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <libsimple/lock.h>
#include <pthread/tsd_private.h>

#define __PTHREAD_EXPOSE_INTERNALS__ 1
#include <pthread/priority_private.h>
#include <pthread/workqueue_syscalls.h>
#include <mach/policy.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/common/tsd.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/ext/futex.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/workq_kernreturn.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/fcntl.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_deferdelete.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kqueue.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/wl_instr.h>
#include <darling/emulation/conversion/common_at.h>
#include <darling/emulation/conversion/fcntl/open.h>
#include <stdarg.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>

#ifndef VARIANT_DYLD
// XNU's workloops (kevent_id() and EVFILT_WORKLOOP), which Apple's libdispatch builds every serial queue on.
//
// A workloop is a kqueue identified by an id (libdispatch uses the queue's address). It holds:
// - one thread request knote: while it is active, the workloop wants a workqueue thread to service it.
// - sync knotes, one per thread blocked in dispatch_sync() on the queue (NOTE_WL_SYNC_WAIT) until another
//   thread hands the queue over to it (NOTE_WL_SYNC_WAKE).
// - ordinary knotes (Mach ports, timers, ...), whose events go to the workloop's servicer thread rather than to
//   the process's kevent workqueue. They live on a libkqueue kqueue of the workloop's own (libkqueue tells
//   knotes apart by ident and filter alone), which a poller thread watches for readability.
// While a thread other than the servicer owns the workloop (it holds the queue's drain lock, which libdispatch
// tells us with NOTE_WL_DISCOVER_OWNER), no servicer is started; one starts once the owner ends its ownership.
//
// As in XNU, the servicer collects its events itself when it starts, is bound to its workloop until it parks, and
// keeps servicing the workloop when it parks while there are events and no owner.
//
// The semantics follow XNU's filt_wl* functions in bsd/kern/kern_event.c, without the QoS overrides and
// turnstiles, which only matter for priorities.

extern void* calloc(__SIZE_TYPE__ count, __SIZE_TYPE__ size);
extern void free(void* ptr);

#define WORKLOOP_BUCKETS 64

#define LINUX_EPOLL_CLOEXEC 02000000
#define LINUX_EPOLL_CTL_ADD 1
#define LINUX_EPOLL_CTL_DEL 2
#define LINUX_EPOLL_CTL_MOD 3
#define LINUX_EPOLLIN 0x001
#define LINUX_EPOLLONESHOT (1u << 30)

struct linux_epoll_event
{
	uint32_t events;
	uint64_t data;
}
#ifdef __x86_64__
__attribute__((packed))
#endif
;

struct wl_knote
{
	struct wl_knote* next;
	uint64_t ident;
	uint32_t sfflags; // NOTE_WL_* the knote was attached with, with the updates it was last touched with
	int32_t qos;
	uint64_t udata;
	uint64_t ext[4];
	int woken; // futex; set once NOTE_WL_SYNC_WAKE is in sfflags
	bool waiting; // a thread is blocked on `woken`
	bool dropped; // deleted while a thread was blocked on it; that thread frees it
};

struct workloop
{
	struct workloop* next; // in its bucket; under workloops_lock
	uint64_t id;
	// kevent_id() calls in progress, the servicer and the poller each hold one; it only drops to zero under
	// workloops_lock, and the workloop is freed then if it is idle
	int refs;
	// guards the rest
	libsimple_lock_t lock;

	struct wl_knote* knotes;
	struct wl_knote* thread_request; // one of `knotes`
	bool thread_request_active; // touched since its last delivery

	uint32_t owner; // port name of the owning thread without its low 2 bits, or 0
	uint32_t servicer; // same for the servicer thread, once it runs
	bool serviced; // a servicer was requested, or is running
	bool created; // made by KQ_WORKLOOP_CREATE, which holds a reference until KQ_WORKLOOP_DESTROY

	int kq; // ordinary knotes; -1 until there is one
	bool kq_armed; // the poller reports `kq` becoming readable
	bool kq_fired; // `kq` became readable and wasn't polled since
	struct kevent_deferdelete dd; // tracks `kq`'s knotes

	// the last owner changes, for wli logging
	struct wl_hist
	{
		uint64_t t_us;
		uint32_t old_owner, new_owner, by;
		uint32_t fflags;
		uint16_t flags;
		int16_t op;
	} hist[8];
	uint32_t hist_n;

	// libpthread finds the workloop's id right before the events it hands to libdispatch
	uint64_t servicer_id;
	struct kevent_qos_s servicer_events[WQ_KEVENT_LIST_LEN];
};

_Static_assert(offsetof(struct workloop, servicer_events) == offsetof(struct workloop, servicer_id) + sizeof(uint64_t),
		"libpthread expects the workloop id right before the events");

// Lock order: a workloop's lock, then workloops_lock.
static libsimple_lock_t workloops_lock = LIBSIMPLE_LOCK_INITIALIZER;
static struct workloop* workloops[WORKLOOP_BUCKETS];
// the epoll instance the poller thread waits on; under workloops_lock
static int poller_fd = -1;

static bool wl_servicer_prepare(void* context, struct workq_batch* batch);

// libdispatch stores thread port names without their low 2 bits (it uses them as flags)
static uint32_t wl_port_mask(uint64_t name)
{
	return (uint32_t)name & ~3u;
}

static uint32_t wl_self(void)
{
	return wl_port_mask((uintptr_t)_pthread_getspecific_direct(_PTHREAD_TSD_SLOT_MACH_THREAD_SELF));
}

// ---- wli: see wl_instr.h

static int wli_state = -1; // -1 unknown, 0 off, 1 on

static uint64_t wli_clock_us(int clock)
{
	struct { long sec, nsec; } ts = { 0, 0 };
	LINUX_SYSCALL(__NR_clock_gettime, clock, &ts);
	return (uint64_t) ts.sec * 1000000ull + (uint64_t) ts.nsec / 1000;
}

uint64_t wli_mono_us(void)
{
	return wli_clock_us(1 /* CLOCK_MONOTONIC */);
}

bool wli_enabled(void)
{
	int state = __atomic_load_n(&wli_state, __ATOMIC_RELAXED);
	if (state < 0)
	{
		int fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, WLI_DIR, LINUX_O_RDONLY | LINUX_O_DIRECTORY | LINUX_O_CLOEXEC, 0);
		state = fd >= 0;
		if (fd >= 0)
			LINUX_SYSCALL1(__NR_close, fd);
		__atomic_store_n(&wli_state, state, __ATOMIC_RELAXED);
		// a marker per process, so a run can tell this library is the one loaded
		if (state)
			wli_log("wli-on kevent_id=%p", (void*) &wli_state);
	}
	return state;
}

// one record: realtime us, Linux pid and tid, the thread's port name, then the text
void wli_log(const char* format, ...)
{
	char path[64], buf[1024];
	va_list vl;
	int n, fd;

	if (!wli_enabled())
		return;
	n = __simple_snprintf(buf, sizeof(buf), "t=%llu pid=%d tid=%d port=%x ", (unsigned long long) wli_clock_us(0),
		(int) LINUX_SYSCALL0(__NR_getpid), (int) LINUX_SYSCALL0(__NR_gettid), wl_self());
	va_start(vl, format);
	n += __simple_vsnprintf(buf + n, sizeof(buf) - n - 1, format, vl);
	va_end(vl);
	if (n > (int) sizeof(buf) - 2)
		n = sizeof(buf) - 2;
	buf[n++] = '\n';

	__simple_snprintf(path, sizeof(path), WLI_DIR "/%d.log", (int) LINUX_SYSCALL0(__NR_getpid));
	fd = LINUX_SYSCALL(__NR_openat, LINUX_AT_FDCWD, path, LINUX_O_WRONLY | LINUX_O_CREAT | LINUX_O_APPEND | LINUX_O_CLOEXEC, 0644);
	if (fd < 0)
		return;
	LINUX_SYSCALL3(__NR_write, fd, buf, n);
	LINUX_SYSCALL1(__NR_close, fd);
}

struct workloop;
static void wli_state_log(struct workloop* wl, const char* what, uint64_t ident, uint64_t elapsed_us);

static struct workloop** wl_bucket(uint64_t id)
{
	return &workloops[((id >> 4) ^ (id >> 12)) % WORKLOOP_BUCKETS];
}

enum wl_get_mode
{
	WL_EXISTING, // NULL if there is none
	WL_CREATE, // created if there is none
	WL_NEW, // created; NULL if there already is one
};

// Returns the workloop with `id` with a reference, as `mode` says.
static struct workloop* wl_get(uint64_t id, enum wl_get_mode mode)
{
	struct workloop* wl;

	libsimple_lock_lock(&workloops_lock);

	for (wl = *wl_bucket(id); wl != NULL; wl = wl->next)
	{
		if (wl->id == id)
			break;
	}

	if (wl != NULL && mode == WL_NEW)
	{
		libsimple_lock_unlock(&workloops_lock);
		return NULL;
	}

	if (wl == NULL && mode != WL_EXISTING)
	{
		wl = calloc(1, sizeof(*wl));
		if (wl != NULL)
		{
			struct workloop** bucket = wl_bucket(id);

			wl->id = wl->servicer_id = id;
			wl->kq = -1;
			wl->next = *bucket;
			*bucket = wl;
		}
	}

	if (wl != NULL)
		__atomic_add_fetch(&wl->refs, 1, __ATOMIC_RELAXED);

	libsimple_lock_unlock(&workloops_lock);
	return wl;
}

// For a holder of a reference that already has the lock.
static void wl_retain(struct workloop* wl)
{
	__atomic_add_fetch(&wl->refs, 1, __ATOMIC_RELAXED);
}

// Drops a reference; frees `wl` with the last one if nothing refers to it anymore, as XNU does.
static void wl_put(struct workloop* wl)
{
	struct workloop** link;
	bool idle;

	libsimple_lock_lock(&workloops_lock);

	// with no reference left, nothing can change the workloop without taking workloops_lock first
	idle = __atomic_sub_fetch(&wl->refs, 1, __ATOMIC_ACQ_REL) == 0 && !wl->serviced && !wl->owner
		&& wl->knotes == NULL && kevent_dd_count(&wl->dd) == 0;
	if (idle)
	{
		for (link = wl_bucket(wl->id); *link != wl; link = &(*link)->next);
		*link = wl->next;

		if (wl->kq >= 0)
			LINUX_SYSCALL(__NR_epoll_ctl, poller_fd, LINUX_EPOLL_CTL_DEL, wl->kq, NULL);
	}

	libsimple_lock_unlock(&workloops_lock);

	if (idle)
	{
		if (wl->kq >= 0)
			sys_close_nocancel(wl->kq);
		kevent_dd_destroy(&wl->dd);
		free(wl);
	}
}

// The poller thread: reports workloops' kqueues becoming readable, so that they get a servicer. It is a thread of
// its own so that this doesn't wait for the event manager or any servicer.
static void wl_kq_fired(uint64_t id);

static bool wl_poller_prepare(void* context, struct workq_batch* batch)
{
	struct linux_epoll_event events[WQ_KEVENT_LIST_LEN];
	int i, n;

	for (;;)
	{
		n = LINUX_SYSCALL(__NR_epoll_pwait, poller_fd, events, WQ_KEVENT_LIST_LEN, -1, NULL, 8);
		if (n < 0)
		{
			n = errno_linux_to_bsd(n);
			if (n == -EINTR)
				continue;
			__simple_printf("workloop: waiting for kqueues failed: %d\n", n);
			__simple_abort();
		}

		for (i = 0; i < n; i++)
			wl_kq_fired(events[i].data);
	}
}

// Starts or stops reporting `wl`'s kqueue becoming readable, once (it is re-armed with LINUX_EPOLL_CTL_MOD).
// Returns 0 or an error number.
static int wl_watch_kq(struct workloop* wl, int op)
{
	struct linux_epoll_event event = { .events = LINUX_EPOLLIN | LINUX_EPOLLONESHOT, .data = wl->id };
	bool start_poller = false;
	int rv = 0;

	libsimple_lock_lock(&workloops_lock);
	if (poller_fd < 0)
	{
		rv = LINUX_SYSCALL(__NR_epoll_create1, LINUX_EPOLL_CLOEXEC);
		if (rv >= 0)
		{
			poller_fd = rv;
			start_poller = true;
		}
	}
	if (poller_fd >= 0)
		rv = LINUX_SYSCALL(__NR_epoll_ctl, poller_fd, op, wl->kq, &event);
	libsimple_lock_unlock(&workloops_lock);

	if (start_poller)
		workq_thread_request(wl_poller_prepare, NULL);

	return (rv < 0) ? -errno_linux_to_bsd(rv) : 0;
}

static void wl_arm_kq(struct workloop* wl)
{
	if (wl->kq >= 0 && !wl->kq_armed && wl_watch_kq(wl, LINUX_EPOLL_CTL_MOD) == 0)
		wl->kq_armed = true;
}

// Collects the events for a servicer of `wl`: the thread request, unless another thread owns the workloop, and
// whatever the ordinary knotes fired. As in XNU, delivering the thread request consumes it until it is touched.
static int wl_collect_events(struct workloop* wl, struct kevent_qos_s* events, int nevents)
{
	int n = 0, rv;

	if (nevents > 0 && wl->thread_request != NULL && wl->thread_request_active && !wl->owner)
	{
		struct wl_knote* kn = wl->thread_request;

		events[n++] = (struct kevent_qos_s) {
			.ident = kn->ident,
			.filter = EVFILT_WORKLOOP,
			.flags = EV_ADD | EV_ENABLE | EV_CLEAR,
			.qos = kn->qos,
			.udata = kn->udata,
			.fflags = kn->sfflags,
			.ext = { kn->ext[0], kn->ext[1], kn->ext[2], kn->ext[3] },
		};
		wl->thread_request_active = false;
	}

	if (n < nevents)
	{
		if (wl->kq >= 0)
			wl->kq_fired = false;
		rv = kevent_dd_collect(&wl->dd, wl->kq, events + n, nevents - n);
		if (rv > 0)
			n += rv;
	}

	return n;
}

static int wl_servicer_flags(const struct kevent_qos_s* events)
{
	unsigned long priority = _pthread_priority_make_from_thread_qos(THREAD_QOS_DEFAULT, 0, 0);

	if (events[0].filter == EVFILT_WORKLOOP && _pthread_priority_thread_qos(events[0].qos) != THREAD_QOS_UNSPECIFIED)
		priority = events[0].qos;
	return workq_thread_flags(priority) | WQ_FLAG_THREAD_KEVENT | WQ_FLAG_THREAD_WORKLOOP;
}

// Decides whether `wl` needs a servicer thread now; if so, it takes a reference for it, and the caller passes
// `wl` to workq_thread_request(wl_servicer_prepare) after unlocking.
static bool wl_request_thread(struct workloop* wl)
{
	if (wl->serviced || wl->owner)
		return false;
	if (!(wl->thread_request != NULL && wl->thread_request_active) && !wl->kq_fired && !kevent_dd_pending(&wl->dd))
		return false;

	wl->serviced = true;
	wl->servicer = 0;
	wl_retain(wl);
	return true;
}

// Logs `wl`'s state and its last owner changes; under wl->lock.
static void wli_state_log(struct workloop* wl, const char* what, uint64_t ident, uint64_t elapsed_us)
{
	uint32_t i, n = wl->hist_n < 8 ? wl->hist_n : 8;

	wli_log("%s wl=%llx ident=%llx el_ms=%llu owner=%x servicer=%x serviced=%d treq=%d active=%d kq=%d armed=%d "
		"fired=%d pending=%d hist=%u", what, (unsigned long long) wl->id, (unsigned long long) ident,
		(unsigned long long) (elapsed_us / 1000), wl->owner, wl->servicer, wl->serviced, wl->thread_request != NULL,
		wl->thread_request_active, wl->kq, wl->kq_armed, wl->kq_fired, wl->kq >= 0 && kevent_dd_pending(&wl->dd),
		wl->hist_n);
	for (i = 0; i < n; i++)
	{
		const struct wl_hist* h = &wl->hist[(wl->hist_n - n + i) % 8];
		wli_log("  owner-change wl=%llx t=%llu old=%x new=%x by=%x fflags=%x flags=%x op=%d", (unsigned long long) wl->id,
			(unsigned long long) h->t_us, h->old_owner, h->new_owner, h->by, h->fflags, h->flags, h->op);
	}
}

// On the thread answering a servicer request for `context`, before it enters libdispatch.
static bool wl_servicer_prepare(void* context, struct workq_batch* batch)
{
	struct workloop* wl = context;
	int n = 0;

	libsimple_lock_lock(&wl->lock);

	// As XNU's kqueue_threadreq_bind(): the servicer is never the owner. If this thread is recorded as the owner (a
	// stale record: it owned the queue once and is now a pool thread picking up the workloop), forget it rather than
	// take the workloop for owned, which would drop the request and refuse every servicer until that record goes.
	if (wl->owner && wl->owner == wl_self())
	{
		if (wli_enabled())
			wli_state_log(wl, "prepare-cleared-owner-is-self", 0, 0);
		wl->owner = 0;
	}

	// another thread may have taken ownership since the request
	if (!wl->owner)
		n = wl_collect_events(wl, wl->servicer_events, WQ_KEVENT_LIST_LEN);

	if (n == 0)
	{
		// C1: XNU clears an owner that is the binding thread (kqueue_threadreq_bind()); this drops the request
		if (wl->owner && wli_enabled())
			wli_state_log(wl, wl->owner == wl_self() ? "prepare-refused-owner-is-self" : "prepare-refused-owned", 0, 0);
		wl->serviced = false;
		wl_arm_kq(wl);
		libsimple_lock_unlock(&wl->lock);
		wl_put(wl);
		return false;
	}

	wl->servicer = wl_self();
	libsimple_lock_unlock(&wl->lock);

	// Like XNU's uu_kqr_bound, this binds the thread to the workloop until it parks.
	_pthread_setspecific_direct(__PTK_DARLING_WORKLOOP, wl);

	*batch = (struct workq_batch) {
		.events = wl->servicer_events,
		.nevents = n,
		.flags = wl_servicer_flags(wl->servicer_events),
	};
	return true;
}

static void wl_kq_fired(uint64_t id)
{
	// the workloop may be gone, or even have been replaced by another with the same id; that only costs a poll
	struct workloop* wl = wl_get(id, WL_EXISTING);
	bool start_servicer = false;

	if (wl == NULL)
		return;

	libsimple_lock_lock(&wl->lock);
	if (wl->kq >= 0)
	{
		wl->kq_armed = false;
		wl->kq_fired = true;
		start_servicer = wl_request_thread(wl);
	}
	libsimple_lock_unlock(&wl->lock);

	if (start_servicer)
		workq_thread_request(wl_servicer_prepare, wl);
	wl_put(wl);
}

static struct wl_knote* wl_knote_find(struct workloop* wl, uint64_t ident)
{
	struct wl_knote* kn;

	for (kn = wl->knotes; kn != NULL; kn = kn->next)
	{
		if (kn->ident == ident)
			return kn;
	}
	return NULL;
}

static void wl_knote_wake(struct wl_knote* kn)
{
	__atomic_store_n(&kn->woken, 1, __ATOMIC_RELEASE);
	if (kn->waiting)
		__linux_futex(&kn->woken, FUTEX_WAKE, __INT_MAX__, NULL, NULL, 0);
}

static void wl_knote_drop(struct workloop* wl, struct wl_knote* kn)
{
	struct wl_knote** link;

	for (link = &wl->knotes; *link != kn; link = &(*link)->next);
	*link = kn->next;

	if (kn == wl->thread_request)
	{
		wl->thread_request = NULL;
		wl->thread_request_active = false;
	}

	if (kn->waiting)
		kn->dropped = true;
	else
		free(kn);
}

// Blocks the calling thread on a NOTE_WL_SYNC_WAIT knote until it is woken or deleted.
static void wl_sync_wait(struct workloop* wl, struct wl_knote* kn)
{
	// whoever is to wake this thread up may need a servicer first
	bool start_servicer = wl_request_thread(wl);

	kn->waiting = true;
	libsimple_lock_unlock(&wl->lock);

	if (start_servicer)
		workq_thread_request(wl_servicer_prepare, wl);

	uint64_t t0 = 0, next_us = 1000000;
	bool wli = wli_enabled();

	if (wli)
		t0 = wli_mono_us();
	while (!__atomic_load_n(&kn->woken, __ATOMIC_ACQUIRE))
	{
		if (!wli)
		{
			__linux_futex(&kn->woken, FUTEX_WAIT, 0, NULL, NULL, 0);
			continue;
		}
		// with wli, wake every second to log the state of a wait that goes on (at 1, 4, 16, 64 s)
		struct timespec ts = { 1, 0 };
		__linux_futex(&kn->woken, FUTEX_WAIT, 0, &ts, NULL, 0);
		if (!__atomic_load_n(&kn->woken, __ATOMIC_ACQUIRE) && wli_mono_us() - t0 >= next_us)
		{
			libsimple_lock_lock(&wl->lock);
			wli_state_log(wl, start_servicer ? "sync-wait-ongoing servicer-requested" : "sync-wait-ongoing", kn->ident,
				wli_mono_us() - t0);
			libsimple_lock_unlock(&wl->lock);
			next_us *= 4;
		}
	}

	libsimple_lock_lock(&wl->lock);
	if (wli && wli_mono_us() - t0 >= 500000)
		wli_state_log(wl, "sync-wait-done", kn->ident, wli_mono_us() - t0);
	kn->waiting = false;
	if (kn->dropped)
		free(kn);
}

enum wl_op { WL_ATTACH, WL_TOUCH, WL_DROP };

// the debounce value at ext[EV_EXTIDX_WL_ADDR]: 8-byte aligned
typedef uint64_t wl_value_t __attribute__((aligned(8)));

// filt_wlupdate(): checks the debounce value at ext[EV_EXTIDX_WL_ADDR], and updates the owner and sync knotes.
static int wl_update(struct workloop* wl, struct wl_knote* kn, struct kevent_qos_s* kev, enum wl_op op)
{
	uint64_t addr = kev->ext[EV_EXTIDX_WL_ADDR];
	uint64_t mask = kev->ext[EV_EXTIDX_WL_MASK];
	uint64_t expected = kev->ext[EV_EXTIDX_WL_VALUE];
	uint32_t new_owner = wl->owner;
	bool needs_wake = false;
	int error = 0;

	if (addr != 0)
	{
		// copyin_atomic64() fails an address that isn't 8-byte aligned. Aligned, the load is a single one on i386 too
		// (whose ABI aligns a uint64_t to 4, so the plain type would make it a libatomic call).
		if (addr & 7)
			return EINVAL;
#if UINTPTR_MAX < UINT64_MAX
		// and a 32-bit process's copyin of an address beyond its address space fails with EFAULT
		if (addr > UINTPTR_MAX)
			return EFAULT;
#endif
		uint64_t value = __atomic_load_n((wl_value_t*) (uintptr_t) addr, __ATOMIC_RELAXED);

		kev->ext[EV_EXTIDX_WL_VALUE] = value;
		if ((value & mask) != (expected & mask))
			error = ESTALE;
		else if ((kev->fflags & NOTE_WL_DISCOVER_OWNER) && wl_port_mask(value) != 0)
			new_owner = wl_port_mask(value);
	}

	if ((kev->fflags & NOTE_WL_END_OWNERSHIP) && new_owner == wl_self())
		new_owner = 0;

	if (error == 0)
	{
		if (op == WL_TOUCH)
		{
			kn->sfflags = (kn->sfflags & ~NOTE_WL_UPDATES_MASK) | kev->fflags;
			needs_wake = (kev->fflags & NOTE_WL_SYNC_WAKE) != 0;
		}
		else if (op == WL_DROP && (kn->sfflags & (NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE)) == NOTE_WL_SYNC_WAIT)
		{
			// deleting a waiter that wasn't woken up wakes it up
			kn->sfflags |= NOTE_WL_SYNC_WAKE;
			needs_wake = true;
		}
	}

	// the servicer is never tracked as the owner
	if (wl->servicer != 0 && new_owner == wl->servicer)
		new_owner = 0;
	if (new_owner != wl->owner && wli_enabled())
	{
		struct wl_hist* h = &wl->hist[wl->hist_n++ % 8];
		*h = (struct wl_hist) {
			.t_us = wli_mono_us(),
			.old_owner = wl->owner,
			.new_owner = new_owner,
			.by = wl_self(),
			.fflags = kev->fflags,
			.flags = kev->flags,
			.op = op,
		};
	}
	wl->owner = new_owner;

	if (needs_wake)
		wl_knote_wake(kn);

	return error;
}

// filt_wlvalidate_kev_flags()
static int wl_validate(struct wl_knote* kn, const struct kevent_qos_s* kev)
{
	uint32_t new_commands = kev->fflags & NOTE_WL_COMMANDS_MASK;
	uint32_t saved_commands = kn->sfflags & NOTE_WL_COMMANDS_MASK;

	if ((kev->fflags & NOTE_WL_DISCOVER_OWNER) && (kev->flags & EV_DELETE))
		return EINVAL;

	if (kev->fflags & NOTE_WL_UPDATE_QOS)
	{
		if ((kev->flags & EV_DELETE) || saved_commands != NOTE_WL_THREAD_REQUEST)
			return EINVAL;
		if (_pthread_priority_thread_qos(kev->qos) == THREAD_QOS_UNSPECIFIED)
			return ERANGE;
	}

	switch (new_commands)
	{
		case NOTE_WL_THREAD_REQUEST:
			return saved_commands == NOTE_WL_THREAD_REQUEST ? 0 : EINVAL;
		case NOTE_WL_SYNC_WAIT:
			if (kev->fflags & NOTE_WL_END_OWNERSHIP)
				return EINVAL;
			// fallthrough
		case NOTE_WL_SYNC_WAKE:
			if (!(saved_commands & (NOTE_WL_SYNC_WAIT | NOTE_WL_SYNC_WAKE)))
				return EINVAL;
			return (kev->flags & (EV_ENABLE | EV_DELETE)) == EV_ENABLE ? EINVAL : 0;
		case NOTE_WL_SYNC_IPC:
			if (saved_commands != NOTE_WL_SYNC_IPC)
				return EINVAL;
			return (kev->flags & (EV_ENABLE | EV_DELETE)) == EV_ENABLE ? EINVAL : 0;
		default:
			return EINVAL;
	}
}

// filt_wlattach()
static int wl_attach(struct workloop* wl, struct kevent_qos_s* kev)
{
	uint32_t command = kev->fflags & NOTE_WL_COMMANDS_MASK;
	struct wl_knote* kn;
	int error = 0;

	switch (command)
	{
		case NOTE_WL_THREAD_REQUEST:
			if (kev->ident != wl->id)
				return EINVAL;
			if (_pthread_priority_thread_qos(kev->qos) == THREAD_QOS_UNSPECIFIED)
				return ERANGE;
			break;
		case NOTE_WL_SYNC_WAIT:
		case NOTE_WL_SYNC_WAKE:
			if (kev->ident == wl->id || !(kev->flags & EV_DISABLE) || (kev->fflags & NOTE_WL_END_OWNERSHIP))
				return EINVAL;
			break;
		case NOTE_WL_SYNC_IPC:
			// sync IPC handoffs only boost priorities
			if (!(kev->flags & EV_DISABLE) || (kev->fflags & (NOTE_WL_UPDATE_QOS | NOTE_WL_DISCOVER_OWNER)))
				return EINVAL;
			break;
		default:
			return EINVAL;
	}

	if (command != NOTE_WL_SYNC_IPC)
		error = wl_update(wl, NULL, kev, WL_ATTACH);
	if (error)
		return (error == ESTALE && (kev->fflags & NOTE_WL_IGNORE_ESTALE)) ? 0 : error;

	kn = calloc(1, sizeof(*kn));
	if (kn == NULL)
		return ENOMEM;

	kn->ident = kev->ident;
	kn->sfflags = kev->fflags;
	kn->qos = kev->qos;
	kn->udata = kev->udata;
	__builtin_memcpy(kn->ext, kev->ext, sizeof(kn->ext));
	kn->woken = (kev->fflags & NOTE_WL_SYNC_WAKE) != 0;
	kn->next = wl->knotes;
	wl->knotes = kn;

	if (command == NOTE_WL_THREAD_REQUEST)
	{
		// attaching the thread request fires it
		wl->thread_request = kn;
		wl->thread_request_active = true;
	}
	else if (command == NOTE_WL_SYNC_WAIT)
		wl_sync_wait(wl, kn);

	return 0;
}

// kevent_register() for EVFILT_WORKLOOP
static int wl_register(struct workloop* wl, struct kevent_qos_s* kev)
{
	uint16_t requested = kev->flags;
	uint32_t command = kev->fflags & NOTE_WL_COMMANDS_MASK;
	struct wl_knote* kn = wl_knote_find(wl, kev->ident);
	enum wl_op op;
	int error;

	// deletion and disabling take precedence
	if (kev->flags & EV_DELETE)
		kev->flags &= ~EV_ADD;
	if (kev->flags & EV_DISABLE)
		kev->flags &= ~EV_ENABLE;

	if (kn == NULL)
	{
		if (kev->flags & EV_ADD)
			return wl_attach(wl, kev);
		// workloops take EV_ADD|EV_DELETE as a deletion that doesn't mind the knote being gone
		return ((requested & (EV_ADD | EV_DELETE)) == (EV_ADD | EV_DELETE)) ? 0 : ENOENT;
	}

	op = (kev->flags & EV_DELETE) ? WL_DROP : WL_TOUCH;
	error = wl_validate(kn, kev);
	if (error == 0 && command != NOTE_WL_SYNC_IPC)
		error = wl_update(wl, kn, kev, op);
	if (error)
		return (error == ESTALE && (kev->fflags & NOTE_WL_IGNORE_ESTALE)) ? 0 : error;

	if (op == WL_DROP)
	{
		wl_knote_drop(wl, kn);
		return 0;
	}

	kn->udata = kev->udata;
	__builtin_memcpy(kn->ext, kev->ext, sizeof(kn->ext));

	if (command == NOTE_WL_THREAD_REQUEST)
	{
		// touching the thread request fires it
		if (kev->fflags & NOTE_WL_UPDATE_QOS)
			kn->qos = kev->qos;
		wl->thread_request_active = true;
	}
	else if (command == NOTE_WL_SYNC_WAIT && !(kn->sfflags & NOTE_WL_SYNC_WAKE))
		wl_sync_wait(wl, kn);

	return 0;
}

// Applies a change to an ordinary knote (anything but EVFILT_WORKLOOP) of `wl`.
static int wl_register_normal(struct workloop* wl, struct kevent_qos_s* kev)
{
	if (wl->kq < 0)
	{
		long kq;
		int error;

		if (!(kev->flags & EV_ADD))
			return ENOENT;

		kq = sys_kqueue();
		if (kq < 0)
			return -kq;
		sys_fcntl_nocancel(kq, F_SETFD, FD_CLOEXEC);

		wl->kq = kq;
		error = wl_watch_kq(wl, LINUX_EPOLL_CTL_ADD);
		if (error)
		{
			wl->kq = -1;
			sys_close_nocancel(kq);
			return error;
		}
		wl->kq_armed = true;
	}

	return kevent_dd_register(&wl->dd, wl->kq, kev);
}

// Applies `changelist` to `wl` in order, reporting failed changes in `errors` (at most `nerrors` of them).
static int wl_apply_changes(struct workloop* wl, const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* errors, int nerrors)
{
	int i, n = 0;

	for (i = 0; i < nchanges; i++)
	{
		struct kevent_qos_s kev = changelist[i];
		int error = (kev.filter == EVFILT_WORKLOOP) ? wl_register(wl, &kev) : wl_register_normal(wl, &kev);

		if (error && n < nerrors)
		{
			kev.flags |= EV_ERROR;
			kev.data = error;
			errors[n++] = kev;
		}
	}

	return n;
}

long sys_kevent_id(uint64_t id, const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents,
		void* data_out, unsigned long* data_available, unsigned int flags)
{
	struct workloop* wl;
	bool start_servicer;
	int n;

	if (!(flags & KEVENT_FLAG_WORKLOOP) || nchanges < 0 || nevents < 0)
		return -EINVAL;

	wl = wl_get(id, (flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST) ? WL_EXISTING : WL_CREATE);
	if (wl == NULL)
		return (flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST) ? -ENOENT : -ENOMEM;

	libsimple_lock_lock(&wl->lock);

	n = wl_apply_changes(wl, changelist, nchanges, eventlist, nevents);

	// Without KEVENT_FLAG_ERROR_EVENTS, the servicer is polling for more events. Like XNU, report errors
	// instead if there were any. (Mach messages are received into libkqueue's buffers, not into `data_out`.)
	if (!(flags & KEVENT_FLAG_ERROR_EVENTS) && n == 0)
		n = wl_collect_events(wl, eventlist, nevents);

	start_servicer = wl_request_thread(wl);

	libsimple_lock_unlock(&wl->lock);

	if (start_servicer)
		workq_thread_request(wl_servicer_prepare, wl);
	wl_put(wl);

	return n;
}

void workloop_servicer_return(const struct kevent_qos_s* changelist, int nchanges)
{
	struct workloop* wl = _pthread_getspecific_direct(__PTK_DARLING_WORKLOOP);
	struct kevent_qos_s* changes = NULL;
	struct workq_batch batch;
	int n;

	if (wl == NULL)
	{
		__simple_printf("workloop: WQOPS_THREAD_WORKLOOP_RETURN from a thread that services no workloop\n");
		__simple_abort();
	}

	// the changes are usually in `wl->servicer_events`, which the errors overwrite
	if (nchanges > 0)
	{
		changes = __builtin_alloca(nchanges * sizeof(*changes));
		__builtin_memcpy(changes, changelist, nchanges * sizeof(*changes));
	}

	libsimple_lock_lock(&wl->lock);

	// As on XNU's parking path, changes that fail are the servicer's next batch, ahead of any event: libdispatch
	// recovers from some (_dispatch_kevent_workloop_poke_drain()) and crashes on the others. Otherwise, the
	// servicer keeps servicing the workloop while that has events and no owner.
	n = wl_apply_changes(wl, changes, nchanges, wl->servicer_events, WQ_KEVENT_LIST_LEN);
	if (n == 0 && !wl->owner)
		n = wl_collect_events(wl, wl->servicer_events, WQ_KEVENT_LIST_LEN);

	if (n > 0)
	{
		batch = (struct workq_batch) {
			.events = wl->servicer_events,
			.nevents = n,
			.flags = wl_servicer_flags(wl->servicer_events),
		};
		libsimple_lock_unlock(&wl->lock);
		workq_thread_enter(&batch);
	}

	wl->serviced = false;
	wl->servicer = 0;
	wl_arm_kq(wl);

	libsimple_lock_unlock(&wl->lock);

	_pthread_setspecific_direct(__PTK_DARLING_WORKLOOP, NULL);
	wl_put(wl);

	workq_thread_return();
}

void workloop_atfork_child(void)
{
	// The child has none of the parent's threads, and libkqueue closes the parent's kqueues in it; its
	// libdispatch starts over with no workloops. The parent's are leaked rather than freed: this runs before
	// libSystem makes malloc usable again in the child.
	workloops_lock = (libsimple_lock_t) LIBSIMPLE_LOCK_INITIALIZER;
	__builtin_memset(workloops, 0, sizeof(workloops));
	if (poller_fd >= 0)
		LINUX_SYSCALL1(__NR_close, poller_fd);
	poller_fd = -1;
}

// libdispatch creates workloops with scheduling parameters (BaseBoard's fixed-priority ones, say) this way; without it,
// it drains them on a pthread root queue instead, where their timer sources crash (backboardd). Darling's servicer
// threads can't take the parameters, so they're only checked, as XNU does.
long sys_kqueue_workloop_ctl(uint64_t cmd, uint64_t options, const void* addr, unsigned long sz)
{
	struct kqueue_workloop_params params = { 0 };
	struct workloop* wl;
	bool created;

	if (sz < sizeof(params.kqwlp_version))
		return -EINVAL;
	__builtin_memcpy(&params, addr, sz < sizeof(params) ? sz : sizeof(params));
	if (params.kqwlp_version != (int) sz)
		return -EINVAL;

	switch (cmd)
	{
		case KQ_WORKLOOP_CREATE:
			if (!params.kqwlp_flags)
				return -EINVAL;
			if ((params.kqwlp_flags & KQ_WORKLOOP_CREATE_SCHED_PRI)
				&& (params.kqwlp_sched_pri < 1 || params.kqwlp_sched_pri > 63 /* MAXPRI_USER */))
				return -EINVAL;
			if ((params.kqwlp_flags & KQ_WORKLOOP_CREATE_SCHED_POL)
				&& params.kqwlp_sched_pol != POLICY_TIMESHARE && params.kqwlp_sched_pol != POLICY_RR
				&& params.kqwlp_sched_pol != POLICY_FIFO)
				return -EINVAL;
			if ((params.kqwlp_flags & KQ_WORKLOOP_CREATE_CPU_PERCENT)
				&& (params.kqwlp_cpu_percent <= 0 || params.kqwlp_cpu_percent > 100
					|| params.kqwlp_cpu_refillms <= 0 || params.kqwlp_cpu_refillms > 0x00ffffff))
				return -EINVAL;

			wl = wl_get(params.kqwlp_id, WL_NEW);
			if (wl == NULL)
				return -EEXIST; // (or out of memory, which XNU would panic on)

			// keep wl_get()'s reference for KQ_WORKLOOP_DESTROY
			libsimple_lock_lock(&wl->lock);
			wl->created = true;
			libsimple_lock_unlock(&wl->lock);
			return 0;

		case KQ_WORKLOOP_DESTROY:
			wl = wl_get(params.kqwlp_id, WL_EXISTING);
			if (wl == NULL)
				return -ENOENT;

			libsimple_lock_lock(&wl->lock);
			created = wl->created;
			wl->created = false;
			libsimple_lock_unlock(&wl->lock);

			if (created)
				wl_put(wl); // KQ_WORKLOOP_CREATE's reference
			wl_put(wl);
			return created ? 0 : -EINVAL;

		default:
			return -EINVAL;
	}
}

#else
long sys_kevent_id(uint64_t id, const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents,
		void* data_out, unsigned long* data_available, unsigned int flags)
{
	return -ENOSYS;
}

long sys_kqueue_workloop_ctl(uint64_t cmd, uint64_t options, const void* addr, unsigned long sz)
{
	return -ENOSYS;
}

void workloop_atfork_child(void)
{
}
#endif
