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
// from Linux and holds it here until a consumer takes it, as XNU's would. The first look may be EVFILT_SOCK's, or
// EVFILT_READ's or EVFILT_WRITE's at end of file (in any process using kqueue on sockets), or a failed send's. A
// closed TCP socket stays hung up after that (POLLHUP), so poll, select, EVFILT_READ/WRITE and blocking calls still
// find it at once. Other sockets' errors (a datagram socket's ICMP errors) stay in Linux, where blocking calls and
// poll find them: EVFILT_SOCK doesn't report them, which XNU's would (its udp_notify() posts no hint, but
// filt_sockev_common reports so_error).
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
// A socket holds one error, the newest, as XNU's does: an error Linux returns on its own replaces the held one.
//
// A reset after the peer's FIN (in CLOSE_WAIT) is EPIPE in Linux (XNU's ECONNRESET). Linux's recv() returns end
// of file before it, leaving it (taken at end of file here: always by recvfrom and recvmsg, by read and readv while
// EVFILT_SOCK knotes exist), and its send() returns and clears it, as the EPIPE of a
// socket shut down for sending. A watched socket tells the two apart: it remembers its shutdown(), and its state when
// the watch began. On another socket, a send that gets there first loses the error: recv() then finds end of file,
// and SO_ERROR none.
//
// EVFILT_SOCK's hints (NOTE_CONNRESET, NOTE_TIMEOUT) are XNU's TCP's, posted when the error happens; a knote may look
// only after the program took the error. So while a knote watches a socket (_socket_watch_4libkqueue), the consumers
// above count its errors by the hint they raise, and the knote raises a hint when the socket's count moved past the one it saw.
//
// The sockets remembered are those holding an error or watched by a knote: up to SOCKET_ENTRIES_MAX at once (by their
// SO_COOKIE, sockutil.h, which needs Linux 4.13). Beyond that, the oldest is forgotten, one that is only watched
// before one holding an error (whose error would be lost). Closing a descriptor forgets its socket's held error, also
// for copies of the descriptor that stay open (dup), which then find none; the socket stays remembered while watched.
//
// Known limits, all from the table being the process's own (XNU's so_error belongs to the socket):
// - fork: the child starts with a copy of the parent's held errors, so both can take the same one; it has no knotes;
// - exec: the new image finds no held errors (Linux cleared them);
// - a descriptor passed over SCM_RIGHTS arrives without its held error.
//
// Other known limits:
// - a send takes a closed TCP socket's error from Linux before it can hold it: a recv() in between finds end of file
//   (a knote that looked in between is woken to look again);
// - a reset in LAST_ACK or CLOSING: XNU's tcp_input() closes the socket without an error, Linux sets ECONNRESET,
//   which is reported (NOTE_CONNRESET, and the error);
// - a shutdown() through another process's copy of a watched socket isn't remembered.

#define SOCKET_ENTRIES_MAX 128

// for-libkqueue.h's _socket_state_4libkqueue, _socket_error_4libkqueue and _socket_watch_4libkqueue
int socket_state(int fd, struct socket_state_4libkqueue* state);
int socket_error(int fd, int linux_error);
void socket_watch(int fd, int delta);

// Non-zero while there is something for the error paths below to do; each checks before calling.
extern volatile int socket_errors_held;    // sockets holding an error
extern volatile int socket_errors_taking;  // threads between taking an error from Linux and holding it
extern volatile int socket_entries_used;   // sockets remembered (a held error, or watched)
extern volatile int socket_watchers;       // EVFILT_SOCK knotes

// taking first: a reader that finds no error in Linux and none taking finds the one taken held
#define SOCKET_ERRORS_HELD() (__atomic_load_n(&socket_errors_taking, __ATOMIC_SEQ_CST) != 0 || \
	__atomic_load_n(&socket_errors_held, __ATOMIC_SEQ_CST) != 0)

// getsockopt(SO_ERROR) on fd got the BSD errno error (0 if none) from Linux, which cleared it there: returns the error
// XNU's would, and clears the one held here.
#define SOCKET_ERROR_OPT_HOOKED(error) (SOCKET_ERRORS_HELD() || ((error) != 0 && ((error) == EPIPE || socket_watchers != 0)))
int socket_error_take(int fd, int error);

// A read from fd (read, readv, recvfrom, recvmsg) returned ret (bytes, 0 at end of file, or a negative BSD errno),
// and ret <= 0: returns what XNU's would. eof: look for a TCP socket's error at end of file (one system call), which
// recvfrom and recvmsg always do, and read and readv while EVFILT_SOCK knotes exist (their end of file is mostly a
// file's).
#define SOCKET_READ_HOOKED(ret) (SOCKET_ERRORS_HELD() || ((ret) <= 0 && socket_watchers != 0))
#define SOCKET_RECV_HOOKED(ret) ((ret) == 0 || SOCKET_READ_HOOKED(ret))
long socket_error_read(int fd, long ret, int peek, int eof);

// A send on socket fd (write, writev, sendto, sendmsg) failed with ret (a negative BSD errno): returns XNU's result.
// Raises no signal (socktables.h's socket_send_failed() goes on to nosigpipe.h, which does).
long socket_error_send(int fd, long ret);

// Descriptor fd is about to be closed: socket_errors_close(). dup2() is about to replace it: socket_errors_cookie()
// before, socket_errors_forget() once it did.
#define SOCKET_ENTRIES_USED() (socket_entries_used != 0)
void socket_errors_close(int fd);
unsigned long long socket_errors_cookie(int fd); // 0 if fd isn't a socket
void socket_errors_forget(unsigned long long cookie);

// shutdown(fd, how) succeeded: a watched socket remembers it (Linux reports a stream socket's shutdown of only
// sending no way, and a datagram socket's none). Called while socket_watchers != 0.
void socket_shutdown(int fd, int how);

// connect() or shutdown() on fd: tells its EVFILT_SOCK knotes (for-libkqueue.h's kqueue_socket_changed)
#define SOCKET_CHANGED(fd) do { if (socket_watchers != 0) kqueue_socket_changed(fd); } while (0)

// In the child of a fork, before it runs anything else.
void socket_errors_atfork_child(void);

#endif // NETWORK_SOSTATE_H
