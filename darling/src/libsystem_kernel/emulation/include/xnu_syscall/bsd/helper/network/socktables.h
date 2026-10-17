#ifndef NETWORK_SOCKTABLES_H
#define NETWORK_SOCKTABLES_H

#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/nosigpipe.h>

// The tables the network helpers keep, and the descriptor events they follow. Each is checked through its gate, so a
// process without one pays a load.
// - route.h: routing sockets, per descriptor number;
// - sostate.h: held errors and EVFILT_SOCK's watches, per socket (its cookie): a copy of a descriptor needs nothing;
// - nosigpipe.h: SO_NOSIGPIPE, per descriptor number.
// libkqueue's own hooks (for-libkqueue.h's kqueue_closed_fd(), kqueue_dup()) are called beside these.

// Descriptor fd is about to be closed (its socket is still there to be looked up).
static inline void socket_tables_close(int fd)
{
	// before the number can be reused for another routing socket
	if (ROUTE_SOCKET_ACTIVE())
		route_socket_close(fd);
	if (SOCKET_ENTRIES_USED())
		socket_errors_close(fd);
	if (NOSIGPIPE_ACTIVE())
		socket_nosigpipe_close(fd);
}

// dup2() is about to replace descriptor fd: what socket_tables_replaced() needs to know of it, looked up before.
static inline unsigned long long socket_tables_replacing(int fd)
{
	return SOCKET_ENTRIES_USED() ? socket_errors_cookie(fd) : 0;
}

// dup2() replaced descriptor fd, of which replacing is socket_tables_replacing()'s answer. Only once it has: a dup2()
// that fails leaves fd as it was.
static inline void socket_tables_replaced(int fd, unsigned long long replacing)
{
	if (ROUTE_SOCKET_ACTIVE())
		route_socket_close(fd);
	socket_errors_forget(replacing);
	if (NOSIGPIPE_ACTIVE())
		socket_nosigpipe_close(fd);
}

// Descriptor copy is now a copy of fd (dup, dup2, F_DUPFD).
static inline void socket_tables_dup(int fd, int copy)
{
	if (ROUTE_SOCKET_ACTIVE())
		route_socket_dup(fd, copy);
	if (NOSIGPIPE_ACTIVE())
		socket_nosigpipe_dup(fd, copy);
}

// In the child of a fork, before it runs anything else: a parent thread may have held the tables' locks, and a signal
// handler (whose read() or write() takes them) may run as soon as the child checks in with darlingserver.
static inline void socket_tables_atfork_child(void)
{
	route_atfork_child();
	socket_errors_atfork_child();
	socket_nosigpipe_atfork_child();
}

// A send on fd (write, writev, sendto, sendmsg) failed with ret (a negative BSD errno): XNU's sosendcheck() result
// (sostate.h), then sendit()'s SIGPIPE (nosigpipe.h), in that order. msg_nosignal, linux_raised: socket_send_done()'s.
static inline long socket_send_failed(int fd, long ret, int msg_nosignal, int linux_raised)
{
	return socket_send_done(fd, socket_error_send(fd, ret), msg_nosignal, linux_raised);
}

#endif // NETWORK_SOCKTABLES_H
