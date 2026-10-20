#ifndef NETWORK_NOSIGPIPE_H
#define NETWORK_NOSIGPIPE_H

// SIGPIPE as XNU raises it: a send that fails with EPIPE (write, writev, sendto, sendmsg) raises SIGPIPE unless the
// socket has SO_NOSIGPIPE set or the send asked for MSG_NOSIGNAL (bsd/kern/uipc_syscalls.c sendit(),
// sys_socket.c soo_write()). Linux has no per-socket switch: it raises SIGPIPE for every EPIPE without MSG_NOSIGNAL.
// Apple's networking code sets SO_NOSIGPIPE on its sockets and relies on it (Network.framework's connections die of
// SIGPIPE otherwise when the peer goes away).
//
// sendto and sendmsg always send with Linux's MSG_NOSIGNAL and raise SIGPIPE here as XNU would. write and writev on a
// socket with SO_NOSIGPIPE send through sendmsg with MSG_NOSIGNAL; other descriptors write as before (Linux raising
// SIGPIPE itself). That needs knowing which descriptors are such sockets on every write, without a system call: the
// flag is kept per descriptor number, with the socket's cookie (sockutil.h), set by setsockopt, copied by dup(),
// dup2() and F_DUPFD, and cleared by close() and dup2() over it. A copy of the descriptor made some other way
// (received over SCM_RIGHTS, inherited across exec) doesn't have it, and neither do descriptors numbered
// NOSIGPIPE_FDS_MAX or above (whose SO_NOSIGPIPE is ignored). sendto and sendmsg also find the flag set
// through another descriptor for the same socket, and teach it to that descriptor.

#define NOSIGPIPE_FDS_MAX (1 << 20)

// Non-zero while a descriptor has SO_NOSIGPIPE: the write paths check it before looking theirs up.
extern volatile int nosigpipe_fds;

#define NOSIGPIPE_ACTIVE() (nosigpipe_fds != 0)

// setsockopt/getsockopt(SOL_SOCKET, SO_NOSIGPIPE) on fd: 0 or a negative BSD errno.
long socket_nosigpipe_set(int fd, int on);
long socket_nosigpipe_get(int fd, int* on);

// write/writev on fd: if fd is a socket with SO_NOSIGPIPE, sends iov through sendmsg with MSG_NOSIGNAL, stores the
// result (bytes, or a negative BSD errno) in *result and returns 1. Returns 0 for other descriptors. With cp, the
// sendmsg is a cancellation point's blocking call (bsdthread/cancelable.h), as write's and writev's own are.
struct iovec;
int socket_nosigpipe_write(int fd, const struct iovec* iov, int iovcnt, int cp, long* result);

// A send on fd returned ret (bytes, or a negative BSD errno) after the socket error paths (sostate.h). If it's EPIPE
// and neither the send (msg_nosignal: BSD MSG_NOSIGNAL) nor the socket asked for none, raises SIGPIPE,
// unless Linux did already (linux_raised: the call went to Linux without MSG_NOSIGNAL and Linux returned EPIPE).
// As XNU's psignal() does, it goes to the process, where a thread not blocking it takes it. (Linux's own SIGPIPE,
// for the write() of a descriptor without SO_NOSIGPIPE, goes to the sending thread.)
long socket_send_done(int fd, long ret, int msg_nosignal, int linux_raised);

// The descriptor fd is being closed, or dup2() is about to replace it.
void socket_nosigpipe_close(int fd);

// copy is now a copy of the descriptor fd (dup, dup2, F_DUPFD).
void socket_nosigpipe_dup(int fd, int copy);

// In the child of a fork, before it runs anything else.
void socket_nosigpipe_atfork_child(void);

#endif // NETWORK_NOSIGPIPE_H
