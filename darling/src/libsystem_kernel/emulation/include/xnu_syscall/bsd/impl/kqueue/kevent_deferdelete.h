#ifndef LINUX_KEVENT_DEFERDELETE_H
#define LINUX_KEVENT_DEFERDELETE_H

#include <stdbool.h>
#include <stdint.h>

#define PRIVATE 1
#include <sys/event.h>

// A libkqueue kqueue with XNU's deferred deletes of EV_DISPATCH2 (EV_DISPATCH|EV_UDATA_SPECIFIC) knotes, which
// libkqueue lacks.
//
// Once XNU has delivered an event for such a knote (which disables it), an EV_DELETE without EV_ENABLE doesn't
// delete it: it fails with EINPROGRESS, and the knote lives on until it is re-enabled, which delivers one last
// event with EV_DELETE|EV_ONESHOT instead. libdispatch relies on this when it cancels a source or Mach channel
// while another thread is handling the source's event: the knote's udata stays valid until libdispatch has seen
// that last event. libkqueue deletes such knotes at once.
//
// Tracking the knotes also tells how many the kqueue holds, which libkqueue doesn't.
//
// The owner applies changes and collects events through these functions only, under one lock of its own, so that
// no event is delivered between deciding what a change does and applying it.

struct kevent_dd_knote;

struct kevent_deferdelete
{
	struct kevent_dd_knote* knotes;
	int nknotes, knotes_capacity;
	// the last events of re-enabled deferred deletes, which the next collection delivers
	struct kevent_qos_s* acks;
	int nacks, acks_capacity;
};

// Applies a change to `kq`; returns 0 or an error number (EINPROGRESS for a deferred delete).
int kevent_dd_register(struct kevent_deferdelete* dd, int kq, const struct kevent_qos_s* kev);

// Collects up to `max` events without blocking: the queued last events first, then what `kq` (if >= 0) has fired.
// Returns their count, or a negative error number.
int kevent_dd_collect(struct kevent_deferdelete* dd, int kq, struct kevent_qos_s* events, int max);

// Whether the next collection has events even if `kq` has none.
bool kevent_dd_pending(const struct kevent_deferdelete* dd);

// The number of knotes on the kqueue, including those that only wait for their deletion.
int kevent_dd_count(const struct kevent_deferdelete* dd);

void kevent_dd_destroy(struct kevent_deferdelete* dd);

#endif // LINUX_KEVENT_DEFERDELETE_H
