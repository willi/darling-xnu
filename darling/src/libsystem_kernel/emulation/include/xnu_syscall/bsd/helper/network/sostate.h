#ifndef NETWORK_SOSTATE_H
#define NETWORK_SOSTATE_H

// A socket's state as XNU keeps it in so_state and so_error (bsd/sys/socketvar.h), derived from the Linux socket, for
// EVFILT_SOCK (libkqueue's src/linux/socket.c, which follows XNU's filt_sockev_common).
//
// so_error needs care. XNU's EVFILT_SOCK reports a pending error (EV_EOF, with the error as data) without clearing
// it: the program then reads it with getsockopt(SO_ERROR), or recv() returns it. Linux has no way to look at a
// socket's error without clearing it, so the first look takes it from Linux and holds it here, per socket (its
// SO_COOKIE), until SO_ERROR or a read takes it, as XNU's would. A socket holds one error, the newest, as XNU's
// does. Up to SOCKET_ERRORS_MAX sockets hold an error at once; beyond that, the oldest is dropped.

#define SOCKET_ERRORS_MAX 64

// The bits of XNU's so_state this reports
#define SOSTATE_ISCONNECTED    0x01 // SS_ISCONNECTED
#define SOSTATE_ISDISCONNECTED 0x02 // SS_ISDISCONNECTED
#define SOSTATE_CANTRCVMORE    0x04 // SS_CANTRCVMORE
#define SOSTATE_CANTSENDMORE   0x08 // SS_CANTSENDMORE
// not a state: the protocol reports connection changes (XNU's PR_EVCONNINFO, which TCP has)
#define SOSTATE_EVCONNINFO     0x10

// The state of socket fd (SOSTATE_*) and its pending error (a BSD errno; 0 if none), which stays pending. Returns 0,
// or a negative BSD errno: ENOTSOCK if fd isn't a socket.
int socket_state(int fd, unsigned* state, int* error);

// The number of sockets holding an error here; the read and SO_ERROR paths check it before looking.
extern volatile int socket_errors_held;

#define SOCKET_ERRORS_HELD() (socket_errors_held != 0)

// getsockopt(SO_ERROR) on fd returned the BSD errno error (0 if none) from Linux, which cleared it there: returns
// the error XNU's would, and clears the one held here.
int socket_error_take(int fd, int error);

// A read from socket fd (read, readv, recvfrom, recvmsg) returned ret (bytes, 0 at end of file, or a negative BSD
// errno): returns what XNU's would. With no data, XNU's soreceive() returns the pending error (and clears it, unless
// MSG_PEEK) before end of file or EWOULDBLOCK.
long socket_error_read(int fd, long ret, int peek);

// In the child of a fork, before it runs anything else.
void socket_errors_atfork_child(void);

#endif // NETWORK_SOSTATE_H
