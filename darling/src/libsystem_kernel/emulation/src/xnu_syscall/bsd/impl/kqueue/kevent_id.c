#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_id.h>

#include <stddef.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <libsimple/lock.h>
#include <pthread/tsd_private.h>

#define __PTHREAD_EXPOSE_INTERNALS__ 1
#include <pthread/priority_private.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/ext/futex.h>
#include <darling/emulation/xnu_syscall/bsd/impl/bsdthread/workq_kernreturn.h>
#include <darling/emulation/xnu_syscall/bsd/impl/fcntl/fcntl.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent64.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_qos.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kqueue.h>
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
//   knotes apart by ident and filter alone), which the kevent workqueue watches for readability.
// While a thread other than the servicer owns the workloop (it holds the queue's drain lock, which libdispatch
// tells us with NOTE_WL_DISCOVER_OWNER), no servicer is started; one starts once the owner ends its ownership.
//
// The semantics follow XNU's filt_wl* functions in bsd/kern/kern_event.c, without the QoS overrides and
// turnstiles, which only matter for priorities.

extern void* calloc(__SIZE_TYPE__ count, __SIZE_TYPE__ size);
extern void* realloc(void* ptr, __SIZE_TYPE__ size);
extern void free(void* ptr);

// tags the udata of a workloop's kqueue on the kevent workqueue; the rest is the workloop's id
#define WORKLOOP_KQ_TAG 0x776c000000000000ull
#define WORKLOOP_KQ_TAG_MASK 0xffff000000000000ull

#define WORKLOOP_BUCKETS 64

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

struct wl_normal_knote
{
	uint64_t ident;
	int16_t filter;
};

struct workloop
{
	struct workloop* next;
	uint64_t id;
	int busy; // kevent_id() calls in progress

	struct wl_knote* knotes;
	struct wl_knote* thread_request; // one of `knotes`
	bool thread_request_active; // touched since its last delivery

	uint32_t owner; // port name of the owning thread without its low 2 bits, or 0
	uint32_t servicer; // same for the servicer thread, once it runs
	bool serviced; // a servicer was requested, or is running

	int kq; // ordinary knotes; -1 until there is one
	bool kq_armed; // the kevent workqueue reports `kq` becoming readable
	bool kq_fired; // `kq` became readable while no servicer could start
	struct wl_normal_knote* normal;
	int nnormal, normal_capacity;

	// libpthread finds the workloop's id right before the events it hands to libdispatch
	uint64_t servicer_id;
	struct kevent_qos_s servicer_events[WQ_KEVENT_LIST_LEN];
};

_Static_assert(offsetof(struct workloop, servicer_events) == offsetof(struct workloop, servicer_id) + sizeof(uint64_t),
		"libpthread expects the workloop id right before the events");

// a servicer thread to start once the lock is dropped
struct wl_dispatch
{
	struct kevent_qos_s* events;
	int nevents;
	unsigned long priority;
};

static libsimple_lock_t workloop_lock = LIBSIMPLE_LOCK_INITIALIZER;
static struct workloop* workloops[WORKLOOP_BUCKETS];

static const struct timespec polling_timeout = {};

// libdispatch stores thread port names without their low 2 bits (it uses them as flags)
static uint32_t wl_port_mask(uint64_t name)
{
	return (uint32_t)name & ~3u;
}

static uint32_t wl_self(void)
{
	return wl_port_mask((uintptr_t)_pthread_getspecific_direct(_PTHREAD_TSD_SLOT_MACH_THREAD_SELF));
}

static struct workloop** wl_bucket(uint64_t id)
{
	return &workloops[((id >> 4) ^ (id >> 12)) % WORKLOOP_BUCKETS];
}

static struct workloop* wl_find(uint64_t id)
{
	struct workloop* wl;

	for (wl = *wl_bucket(id); wl != NULL; wl = wl->next)
	{
		if (wl->id == id)
			return wl;
	}
	return NULL;
}

static struct workloop* wl_create(uint64_t id)
{
	struct workloop** bucket = wl_bucket(id);
	struct workloop* wl = calloc(1, sizeof(*wl));

	if (wl == NULL)
		return NULL;

	wl->id = wl->servicer_id = id;
	wl->kq = -1;
	wl->next = *bucket;
	*bucket = wl;
	return wl;
}

static struct workloop* wl_from_events(const void* events)
{
	return (struct workloop*) ((char*) events - offsetof(struct workloop, servicer_events));
}

// Frees `wl` once nothing refers to it anymore, as XNU does with a workloop's last reference.
static void wl_release(struct workloop* wl)
{
	struct workloop** link;

	if (wl->busy || wl->serviced || wl->owner || wl->knotes != NULL || wl->nnormal > 0)
		return;

	if (wl->kq >= 0)
	{
		workq_kevent_watch_fd(wl->kq, WORKLOOP_KQ_TAG | wl->id, EV_DELETE);
		sys_close(wl->kq);
	}

	for (link = wl_bucket(wl->id); *link != wl; link = &(*link)->next);
	*link = wl->next;

	free(wl->normal);
	free(wl);
}

static void wl_arm_kq(struct workloop* wl)
{
	if (wl->kq >= 0 && !wl->kq_armed)
	{
		workq_kevent_watch_fd(wl->kq, WORKLOOP_KQ_TAG | wl->id, EV_ENABLE);
		wl->kq_armed = true;
	}
}

// libkqueue does not say how many knotes a kqueue holds; the workloop keeps track to know when it is unused.
static void wl_remember_normal(struct workloop* wl, uint64_t ident, int16_t filter)
{
	int i;

	for (i = 0; i < wl->nnormal; i++)
	{
		if (wl->normal[i].ident == ident && wl->normal[i].filter == filter)
			return;
	}

	if (wl->nnormal == wl->normal_capacity)
	{
		int capacity = wl->normal_capacity ? wl->normal_capacity * 2 : 4;
		struct wl_normal_knote* normal = realloc(wl->normal, capacity * sizeof(*normal));

		if (normal == NULL)
			return;
		wl->normal = normal;
		wl->normal_capacity = capacity;
	}

	wl->normal[wl->nnormal++] = (struct wl_normal_knote) { .ident = ident, .filter = filter };
}

static void wl_forget_normal(struct workloop* wl, uint64_t ident, int16_t filter)
{
	int i;

	for (i = 0; i < wl->nnormal; i++)
	{
		if (wl->normal[i].ident == ident && wl->normal[i].filter == filter)
		{
			wl->normal[i] = wl->normal[--wl->nnormal];
			return;
		}
	}
}

// Collects the events for a servicer of `wl`: the thread request, unless another thread owns the workloop, and
// whatever the ordinary knotes fired. As in XNU, delivering the thread request consumes it until it is touched.
static int wl_collect_events(struct workloop* wl, struct kevent_qos_s* events, int nevents)
{
	int n = 0;

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

	if (wl->kq >= 0 && n < nevents)
	{
		struct kevent64_s* events64 = (struct kevent64_s*) __builtin_alloca((nevents - n) * sizeof(struct kevent64_s));
		int i, rv;

		rv = sys_kevent64(wl->kq, NULL, 0, events64, nevents - n, 0, &polling_timeout);
		for (i = 0; i < rv; i++)
		{
			if (events64[i].flags & EV_ONESHOT)
				wl_forget_normal(wl, events64[i].ident, events64[i].filter);
			kevent_64_to_qos(&events64[i], &events[n++]);
		}
	}

	return n;
}

static unsigned long wl_servicer_priority(const struct kevent_qos_s* events)
{
	if (events[0].filter == EVFILT_WORKLOOP && _pthread_priority_thread_qos(events[0].qos) != THREAD_QOS_UNSPECIFIED)
		return events[0].qos;
	return _pthread_priority_make_from_thread_qos(THREAD_QOS_DEFAULT, 0, 0);
}

// Decides whether `wl` needs a servicer thread now; if so, the caller starts it with `dispatch` after unlocking.
static bool wl_request_thread(struct workloop* wl, struct wl_dispatch* dispatch)
{
	if (wl->serviced || wl->owner)
		return false;
	if (!(wl->thread_request != NULL && wl->thread_request_active) && !wl->kq_fired)
		return false;

	wl->kq_fired = false;
	dispatch->nevents = wl_collect_events(wl, wl->servicer_events, WQ_KEVENT_LIST_LEN);
	if (dispatch->nevents == 0)
	{
		wl_arm_kq(wl);
		return false;
	}

	wl->serviced = true;
	wl->servicer = 0;
	dispatch->events = wl->servicer_events;
	dispatch->priority = wl_servicer_priority(wl->servicer_events);
	return true;
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
	struct wl_dispatch dispatch;
	// whoever is to wake this thread up may need a servicer first
	bool start_servicer = wl_request_thread(wl, &dispatch);

	kn->waiting = true;
	libsimple_lock_unlock(&workloop_lock);

	if (start_servicer)
		workq_workloop_thread_request(dispatch.events, dispatch.nevents, dispatch.priority);

	while (!__atomic_load_n(&kn->woken, __ATOMIC_ACQUIRE))
		__linux_futex(&kn->woken, FUTEX_WAIT, 0, NULL, NULL, 0);

	libsimple_lock_lock(&workloop_lock);
	kn->waiting = false;
	if (kn->dropped)
		free(kn);
}

enum wl_op { WL_ATTACH, WL_TOUCH, WL_DROP };

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
		uint64_t value = __atomic_load_n((uint64_t*) addr, __ATOMIC_RELAXED);

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
	struct kevent64_s change, error;
	long rv;

	if (wl->kq < 0)
	{
		int kq;

		if (!(kev->flags & EV_ADD))
			return ENOENT;

		kq = sys_kqueue();
		if (kq < 0)
			return -kq;
		sys_fcntl(kq, F_SETFD, FD_CLOEXEC);

		rv = workq_kevent_watch_fd(kq, WORKLOOP_KQ_TAG | wl->id, EV_ADD);
		if (rv < 0)
		{
			sys_close(kq);
			return -rv;
		}
		wl->kq = kq;
		wl->kq_armed = true;
	}

	kevent_qos_to_64(kev, &change);
	rv = sys_kevent64(wl->kq, &change, 1, &error, 1, KEVENT_FLAG_ERROR_EVENTS, NULL);
	if (rv < 0)
		return -rv;
	if (rv > 0 && (error.flags & EV_ERROR) && error.data != 0)
		return error.data;

	if (kev->flags & EV_DELETE)
		wl_forget_normal(wl, kev->ident, kev->filter);
	else if (kev->flags & EV_ADD)
		wl_remember_normal(wl, kev->ident, kev->filter);
	return 0;
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
	struct wl_dispatch dispatch;
	bool start_servicer;
	int n;

	if (!(flags & KEVENT_FLAG_WORKLOOP) || nchanges < 0 || nevents < 0)
		return -EINVAL;

	libsimple_lock_lock(&workloop_lock);

	wl = wl_find(id);
	if (wl == NULL)
	{
		if (flags & KEVENT_FLAG_DYNAMIC_KQ_MUST_EXIST)
		{
			libsimple_lock_unlock(&workloop_lock);
			return -ENOENT;
		}

		wl = wl_create(id);
		if (wl == NULL)
		{
			libsimple_lock_unlock(&workloop_lock);
			return -ENOMEM;
		}
	}

	wl->busy++;
	n = wl_apply_changes(wl, changelist, nchanges, eventlist, nevents);

	// Without KEVENT_FLAG_ERROR_EVENTS, the servicer is polling for more events. Like XNU, report errors
	// instead if there were any. (Mach messages are received into libkqueue's buffers, not into `data_out`.)
	if (!(flags & KEVENT_FLAG_ERROR_EVENTS) && n == 0)
		n = wl_collect_events(wl, eventlist, nevents);

	start_servicer = wl_request_thread(wl, &dispatch);
	wl->busy--;
	wl_release(wl);

	libsimple_lock_unlock(&workloop_lock);

	if (start_servicer)
		workq_workloop_thread_request(dispatch.events, dispatch.nevents, dispatch.priority);

	return n;
}

bool workloop_is_kq_event(int16_t filter, uint64_t udata)
{
	return filter == EVFILT_READ && (udata & WORKLOOP_KQ_TAG_MASK) == WORKLOOP_KQ_TAG;
}

void workloop_kq_fired(uint64_t udata)
{
	struct workloop* wl;
	struct wl_dispatch dispatch;
	bool start_servicer = false;

	libsimple_lock_lock(&workloop_lock);

	// the workloop may be gone, or even have been replaced by another with the same id; that only costs a poll
	wl = wl_find(udata & ~WORKLOOP_KQ_TAG_MASK);
	if (wl != NULL)
	{
		// the kqueue is watched with EV_DISPATCH
		wl->kq_armed = false;
		wl->kq_fired = true;
		start_servicer = wl_request_thread(wl, &dispatch);
	}

	libsimple_lock_unlock(&workloop_lock);

	if (start_servicer)
		workq_workloop_thread_request(dispatch.events, dispatch.nevents, dispatch.priority);
}

void workloop_servicer_started(void* events, int thread_port)
{
	struct workloop* wl = wl_from_events(events);

	libsimple_lock_lock(&workloop_lock);
	wl->servicer = wl_port_mask(thread_port);
	if (wl->owner == wl->servicer)
		wl->owner = 0;
	libsimple_lock_unlock(&workloop_lock);
}

void workloop_servicer_return(const struct kevent_qos_s* changelist, int nchanges)
{
	struct workloop* wl = wl_from_events(changelist);
	int n;

	libsimple_lock_lock(&workloop_lock);

	wl_apply_changes(wl, changelist, nchanges, NULL, 0);

	// As in XNU, a parking servicer keeps servicing its workloop while that has events and no owner.
	n = wl->owner ? 0 : wl_collect_events(wl, wl->servicer_events, WQ_KEVENT_LIST_LEN);
	if (n > 0)
	{
		unsigned long priority = wl_servicer_priority(wl->servicer_events);

		libsimple_lock_unlock(&workloop_lock);
		workq_workloop_thread_continue(wl->servicer_events, n, priority);
	}

	wl->serviced = false;
	wl->servicer = 0;
	wl->kq_fired = false;
	wl_arm_kq(wl);
	wl_release(wl);

	libsimple_lock_unlock(&workloop_lock);

	workq_workloop_thread_park();
}

void workloop_atfork_child(void)
{
	// The child has none of the parent's threads or kqueues; its libdispatch starts over with no workloops.
	// The parent's are leaked rather than freed, as they may be in an inconsistent state.
	workloop_lock = (libsimple_lock_t) LIBSIMPLE_LOCK_INITIALIZER;
	__builtin_memset(workloops, 0, sizeof(workloops));
}
#else
long sys_kevent_id(uint64_t id, const struct kevent_qos_s* changelist, int nchanges,
		struct kevent_qos_s* eventlist, int nevents,
		void* data_out, unsigned long* data_available, unsigned int flags)
{
	return -ENOSYS;
}
#endif
