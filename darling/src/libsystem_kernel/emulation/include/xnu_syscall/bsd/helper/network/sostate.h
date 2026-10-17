#ifndef NETWORK_SOSTATE_H
#define NETWORK_SOSTATE_H

#include <sys/errno.h>

#include <darling/emulation/linux_premigration/ext/for-libkqueue.h>

// A socket's state as XNU keeps it in so_state and so_error (bsd/sys/socketvar.h), derived from the Linux socket, for
// EVFILT_SOCK (libkqueue's src/linux/socket.c, which follows XNU's filt_sockev_common) and the socket filters' error
// reports; and the socket error paths made XNU's.
//
// so_error needs care. XNU's EVFILT_SOCK reports a pending error (EV_EOF, with the error as data) without clearing
// it, and the program then takes it. Linux has no way to look at a socket's error without clearing it. So for a TCP
// socket Linux has closed, whose error is the reason (a reset, a refused connect, a timeout), the first look takes it
// from Linux and holds it here until a consumer takes it, as XNU's would. A closed TCP socket stays hung up after
// that (POLLHUP), so poll, select, EVFILT_READ/WRITE and blocking calls still find it at once. Other sockets'
// errors (a datagram socket's ICMP errors) stay in Linux, where blocking calls and poll find them: EVFILT_SOCK
// doesn't report them, which XNU's would (its udp_notify() posts no hint, but filt_sockev_common reports so_error).
//
// XNU's consumers of so_error, and what they become here:
// - getsockopt(SO_ERROR) (sogetoptlock), which clears it: the held error if Linux has none of its own.
// - soreceive() (read, readv, recvfrom, recvmsg): with no data, the error before end of file or EWOULDBLOCK, cleared
//   unless MSG_PEEK. Linux returns its own errors there too; a TCP socket's EPIPE (Linux's error for a reset in
//   CLOSE_WAIT) is XNU's ECONNRESET.
// - sosendcheck() (write, writev, sendto, sendmsg): a disconnected socket fails with EPIPE first (SS_CANTSENDMORE),
//   leaving so_error. Linux returns the error to the first send instead and clears it: on a closed TCP socket that
//   becomes EPIPE, with the error held for the consumers above (nosigpipe.h raises SIGPIPE as XNU does).
// - connect() on a socket whose nonblocking connect failed, and accept() on the listening socket: not hooked;
//   Linux's own answers (the error, or ECONNABORTED) stand.
//
// A socket holds one error, the newest, as XNU's does: an error Linux returns on its own replaces the held one. Up to
// SOCKET_ENTRIES_MAX sockets are remembered at once (by their SO_COOKIE, sockutil.h, which needs Linux 4.13); beyond
// that, the oldest is forgotten. Closing a descriptor forgets its socket, also for copies of the descriptor that
// stay open (dup), which then find no held error.
//
// Known limits, all from the table being the process's own (XNU's so_error belongs to the socket):
// - fork: the child starts with a copy of the parent's held errors, so both can take the same one;
// - exec: the new image finds no held errors (Linux cleared them);
// - a descriptor passed over SCM_RIGHTS arrives without its held error.

#define SOCKET_ENTRIES_MAX 128

// The state of socket fd (for-libkqueue.h's struct). Returns 0, or a negative BSD errno: ENOTSOCK if fd isn't a socket.
int socket_state(int fd, struct socket_state_4libkqueue* state);

// EVFILT_SOCK knotes attached (for-libkqueue.h's _socket_watch_4libkqueue).
void socket_watch(int delta);

// Non-zero while there is something for the error paths below to do; each checks before calling.
extern volatile int socket_errors_held;    // sockets holding an error
extern volatile int socket_errors_taking;  // threads between taking an error from Linux and holding it
extern volatile int socket_entries_used;   // sockets remembered (a held error, or errors counted for EVFILT_SOCK)
extern volatile int socket_watchers;       // EVFILT_SOCK knotes

#define SOCKET_ERRORS_HELD() (socket_errors_held != 0 || socket_errors_taking != 0)

// getsockopt(SO_ERROR) on fd got the BSD errno error (0 if none) from Linux, which cleared it there: returns the error
// XNU's would, and clears the one held here.
#define SOCKET_ERROR_OPT_HOOKED(error) (SOCKET_ERRORS_HELD() || ((error) != 0 && ((error) == EPIPE || socket_watchers != 0)))
int socket_error_take(int fd, int error);

// A read from socket fd (read, readv, recvfrom, recvmsg) returned ret (bytes, 0 at end of file, or a negative BSD
// errno), and ret <= 0: returns what XNU's would.
#define SOCKET_READ_HOOKED(ret) (SOCKET_ERRORS_HELD() || (ret) == -EPIPE || ((ret) < 0 && socket_watchers != 0))
long socket_error_read(int fd, long ret, int peek);

// A send on socket fd (write, writev, sendto, sendmsg) failed with ret (a negative BSD errno): returns XNU's result.
// Raises no signal (nosigpipe.h does).
long socket_error_send(int fd, long ret);

// Descriptor fd is being closed, or dup2() is about to replace it.
#define SOCKET_ENTRIES_USED() (socket_entries_used != 0)
void socket_errors_close(int fd);

// libkqueue's (a weak no-op without it): socket fd's state may have changed in a way Linux wakes no one for (a
// datagram socket connected or disconnected, a shutdown): its EVFILT_SOCK knotes look again, as XNU's soevent()
// would have them do.
void kqueue_socket_changed(int fd);

// In the child of a fork, before it runs anything else.
void socket_errors_atfork_child(void);

#endif // NETWORK_SOSTATE_H
