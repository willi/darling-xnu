#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_qos.h>

#include <stddef.h>
#include <sys/errno.h>
#include <sys/fcntl.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent64.h>
#include <darling/emulation/xnu_syscall/bsd/impl/kqueue/kevent_workq.h>

static const struct timespec polling_timeout = {};

long sys_kevent_qos(int	kq, const struct kevent_qos_s *changelist, int nchanges,
			struct	kevent_qos_s *eventlist, int nevents,
			void* data_out, unsigned long* data_available, unsigned int flags)
{
	int rv;
	struct kevent64_s* changelist64 = NULL;
	struct kevent64_s* eventlist64 = NULL;

	if ((kq == -1) != !!(flags & KEVENT_FLAG_WORKQ))
		return -EINVAL;

	if (flags & KEVENT_FLAG_WORKQ)
		return workq_kevent_register(changelist, nchanges, eventlist, nevents);

	if (changelist != NULL && nchanges > 0)
	{
		int i;

		changelist64 = (struct kevent64_s*) __builtin_alloca(nchanges * sizeof(struct kevent64_s));
		for (i = 0; i < nchanges; i++)
			kevent_qos_to_64(&changelist[i], &changelist64[i]);
	}
	if (eventlist != NULL && nevents > 0)
		eventlist64 = (struct kevent64_s*) __builtin_alloca(nevents * sizeof(struct kevent64_s));

	rv = sys_kevent64(kq, changelist64, nchanges, eventlist64, nevents, flags, (flags & KEVENT_FLAG_IMMEDIATE) ? &polling_timeout : NULL);

	if (rv > 0)
	{
		int i;

		for (i = 0; i < rv; i++)
			kevent_64_to_qos(&eventlist64[i], &eventlist[i]);
	}

	return rv;
}


void kevent_qos_to_64(const struct kevent_qos_s *ev, struct kevent64_s* ev64)
{
	ev64->ident = ev->ident;
	ev64->filter = ev->filter;
	ev64->flags = ev->flags;
	ev64->fflags = ev->fflags;
	ev64->data = ev->data;
	ev64->udata = ev->udata;
	ev64->ext[0] = ev->ext[0];
	ev64->ext[1] = ev->ext[1];
}

void kevent_64_to_qos(const struct kevent64_s* ev64, struct kevent_qos_s *ev)
{
	ev->ident = ev64->ident;
	ev->filter = ev64->filter;
	ev->flags = ev64->flags;
	ev->qos = 0;
	ev->fflags = ev64->fflags;
	ev->data = ev64->data;
	ev->udata = ev64->udata;
	ev->ext[0] = ev64->ext[0];
	ev->ext[1] = ev64->ext[1];
	ev->ext[2] = ev->ext[3] = 0;
}
