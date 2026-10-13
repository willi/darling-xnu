#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_deferdelete.h>

#include <sys/errno.h>
#include <sys/time.h>

#include <darling/emulation/common/simple.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent64.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_qos.h>

// Follows kevent_register() and knote_process() in XNU's bsd/kern/kern_event.c.

extern void* realloc(void* ptr, __SIZE_TYPE__ size);
extern void free(void* ptr);

struct kevent_dd_knote
{
	uint64_t ident;
	int16_t filter;
	uint16_t flags; // what it was added with
	uint64_t udata;
	bool disabled; // fired (which disables an EV_DISPATCH knote), or disabled with EV_DISABLE
	bool deferred; // an EV_DELETE waits for the knote to be re-enabled
	bool dropped; // it fired with EV_ONESHOT; XNU keeps it until it is deleted (libkqueue may not)
};

enum dd_action
{
	DD_APPLY, // apply the change to the kqueue
	DD_EINPROGRESS, // don't apply it: it fails with EINPROGRESS
	DD_SUCCEED, // don't apply it: it succeeds
	DD_DELETE, // delete the knote instead, whether or not libkqueue still has it
};

static const struct timespec polling_timeout = {};

static bool dd_is_dispatch2(const struct kevent_dd_knote* kn)
{
	return (kn->flags & EV_DISPATCH2) == EV_DISPATCH2;
}

static struct kevent_dd_knote* dd_find(struct kevent_deferdelete* dd, uint64_t ident, int16_t filter)
{
	int i;

	// libkqueue tells knotes apart by ident and filter alone
	for (i = 0; i < dd->nknotes; i++)
	{
		if (dd->knotes[i].ident == ident && dd->knotes[i].filter == filter)
			return &dd->knotes[i];
	}
	return NULL;
}

static void dd_remove(struct kevent_deferdelete* dd, struct kevent_dd_knote* kn)
{
	*kn = dd->knotes[--dd->nknotes];
}

static struct kevent_dd_knote* dd_add(struct kevent_deferdelete* dd, uint64_t ident, int16_t filter)
{
	if (dd->nknotes == dd->knotes_capacity)
	{
		int capacity = dd->knotes_capacity ? dd->knotes_capacity * 2 : 8;
		struct kevent_dd_knote* knotes = realloc(dd->knotes, capacity * sizeof(*knotes));

		// without memory, the knote behaves as libkqueue has it
		if (knotes == NULL)
			return NULL;
		dd->knotes = knotes;
		dd->knotes_capacity = capacity;
	}

	dd->knotes[dd->nknotes] = (struct kevent_dd_knote) { .ident = ident, .filter = filter };
	return &dd->knotes[dd->nknotes++];
}

// knote_process() delivers this for a re-enabled deferred delete, then drops the knote
static void dd_queue_ack(struct kevent_deferdelete* dd, const struct kevent_dd_knote* kn)
{
	if (dd->nacks == dd->acks_capacity)
	{
		int capacity = dd->acks_capacity ? dd->acks_capacity * 2 : 4;
		struct kevent_qos_s* acks = realloc(dd->acks, capacity * sizeof(*acks));

		if (acks == NULL)
		{
			__simple_printf("kevent: out of memory for a deferred delete\n");
			__simple_abort();
		}
		dd->acks = acks;
		dd->acks_capacity = capacity;
	}

	dd->acks[dd->nacks++] = (struct kevent_qos_s) {
		.ident = kn->ident,
		.filter = kn->filter,
		.flags = EV_DISPATCH2 | EV_ONESHOT | EV_DELETE,
		.udata = kn->udata,
	};
}

static enum dd_action dd_decide(struct kevent_deferdelete* dd, const struct kevent_qos_s* kev)
{
	struct kevent_dd_knote* kn = dd_find(dd, kev->ident, kev->filter);

	if (kn == NULL || !dd_is_dispatch2(kn))
		return DD_APPLY;

	if (kev->flags & EV_DELETE)
	{
		if (!(kev->flags & EV_ENABLE) && kn->disabled)
		{
			kn->deferred = true;
			return DD_EINPROGRESS;
		}
		if (kn->dropped)
		{
			dd_remove(dd, kn);
			return DD_DELETE;
		}
		return DD_APPLY;
	}

	// a knote waiting to be deleted has delivered its last event and isn't touched anymore; enabling it
	// delivers its deletion
	if (kn->deferred || kn->dropped)
	{
		if (kev->flags & EV_ENABLE)
		{
			dd_queue_ack(dd, kn);
			dd_remove(dd, kn);
			return DD_DELETE;
		}
		return DD_SUCCEED;
	}

	return DD_APPLY;
}

static void dd_applied(struct kevent_deferdelete* dd, const struct kevent_qos_s* kev)
{
	struct kevent_dd_knote* kn = dd_find(dd, kev->ident, kev->filter);

	if (kev->flags & EV_DELETE)
	{
		if (kn != NULL)
			dd_remove(dd, kn);
		return;
	}

	if (kn == NULL)
	{
		if (!(kev->flags & EV_ADD))
			return;
		kn = dd_add(dd, kev->ident, kev->filter);
		if (kn == NULL)
			return;
	}

	if (kev->flags & EV_ADD)
		kn->flags = kev->flags;
	kn->udata = kev->udata;
	if (kev->flags & EV_DISABLE)
		kn->disabled = true;
	else if (kev->flags & EV_ENABLE)
		kn->disabled = false;
}

static void dd_delivered(struct kevent_deferdelete* dd, const struct kevent_qos_s* ev)
{
	struct kevent_dd_knote* kn = dd_find(dd, ev->ident, ev->filter);

	if (kn == NULL)
		return;

	if (!dd_is_dispatch2(kn))
	{
		if ((kn->flags | ev->flags) & EV_ONESHOT)
			dd_remove(dd, kn);
		return;
	}

	kn->disabled = true;
	if ((kn->flags | ev->flags) & EV_ONESHOT)
		kn->dropped = true;
}

static int dd_apply(int kq, const struct kevent_qos_s* kev)
{
	struct kevent64_s change, error;
	long rv;

	kevent_qos_to_64(kev, &change);
	rv = sys_kevent64(kq, &change, 1, &error, 1, KEVENT_FLAG_ERROR_EVENTS, NULL);
	if (rv < 0)
		return -rv;
	if (rv > 0 && (error.flags & EV_ERROR) && error.data != 0)
		return error.data;
	return 0;
}

int kevent_dd_register(struct kevent_deferdelete* dd, int kq, const struct kevent_qos_s* kev)
{
	struct kevent_qos_s delete;
	int error;

	switch (dd_decide(dd, kev))
	{
		case DD_EINPROGRESS:
			return EINPROGRESS;
		case DD_SUCCEED:
			return 0;
		case DD_DELETE:
			delete = *kev;
			delete.flags = EV_DELETE;
			error = dd_apply(kq, &delete);
			return (error == ENOENT) ? 0 : error;
		case DD_APPLY:
		default:
			error = dd_apply(kq, kev);
			if (error == 0)
				dd_applied(dd, kev);
			return error;
	}
}

int kevent_dd_collect(struct kevent_deferdelete* dd, int kq, struct kevent_qos_s* events, int max)
{
	int i, n, rv;
	struct kevent64_s* events64;

	n = (dd->nacks < max) ? dd->nacks : max;
	for (i = 0; i < n; i++)
		events[i] = dd->acks[i];
	for (i = n; i < dd->nacks; i++)
		dd->acks[i - n] = dd->acks[i];
	dd->nacks -= n;

	if (kq < 0 || n == max)
		return n;

	events64 = (struct kevent64_s*) __builtin_alloca((max - n) * sizeof(struct kevent64_s));
	rv = sys_kevent64(kq, NULL, 0, events64, max - n, 0, &polling_timeout);
	if (rv < 0)
		return (n > 0) ? n : rv;

	for (i = 0; i < rv; i++)
	{
		kevent_64_to_qos(&events64[i], &events[n]);
		dd_delivered(dd, &events[n]);
		n++;
	}
	return n;
}

bool kevent_dd_pending(const struct kevent_deferdelete* dd)
{
	return dd->nacks > 0;
}

int kevent_dd_count(const struct kevent_deferdelete* dd)
{
	return dd->nknotes;
}

void kevent_dd_destroy(struct kevent_deferdelete* dd)
{
	free(dd->knotes);
	free(dd->acks);
	*dd = (struct kevent_deferdelete) {};
}
