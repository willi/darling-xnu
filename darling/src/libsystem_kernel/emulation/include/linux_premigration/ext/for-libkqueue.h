#ifndef _DARLING_EMULATION_FOR_LIBKQUEUE_H_
#define _DARLING_EMULATION_FOR_LIBKQUEUE_H_

#include <stdint.h>

#include <darling/emulation/common/base.h>

VISIBLE
int _dserver_rpc_kqchan_mach_port_open_4libkqueue(uint32_t port_name, void* receive_buffer, uint64_t receive_buffer_size, uint64_t saved_filter_flags, int* out_socket);

VISIBLE
int _dserver_rpc_kqchan_proc_open_4libkqueue(int32_t pid, uint32_t flags, int* out_socket);

VISIBLE
int _dup_4libkqueue(int fd);

// EVFILT_SIGNAL (see signal_knotes.h): an eventfd that counts deliveries of the BSD signal signum, or a negative BSD
// errno. Only _signal_knote_close_4libkqueue closes it.
VISIBLE
int _signal_knote_open_4libkqueue(int signum);

VISIBLE
void _signal_knote_close_4libkqueue(int fd);

// EVFILT_SOCK (libkqueue's src/linux/socket.c) and the socket filters' error reports: a socket as XNU's
// filt_sockev_common sees it, derived from the Linux socket (sostate.h).

// The bits of XNU's so_state (bsd/sys/socketvar.h) a socket's state has
#define SOSTATE_ISCONNECTED    0x01 // SS_ISCONNECTED
#define SOSTATE_ISDISCONNECTED 0x02 // SS_ISDISCONNECTED
#define SOSTATE_CANTRCVMORE    0x04 // SS_CANTRCVMORE
#define SOSTATE_CANTSENDMORE   0x08 // SS_CANTSENDMORE
// not a state: the protocol reports connection changes (XNU's PR_EVCONNINFO, which TCP has)
#define SOSTATE_EVCONNINFO     0x10

struct socket_state_4libkqueue {
	unsigned int state; // SOSTATE_*
	int error;          // the pending error (XNU's so_error, a BSD errno; 0 if none), which stays pending
	unsigned int errors; // how many errors the socket has had that were seen here; changes with each new one
	int last_error;     // the newest of them, pending or taken since (0 if none)
};

// The state of socket fd. Returns 0, or a negative BSD errno: ENOTSOCK if fd isn't a socket.
VISIBLE
int _socket_state_4libkqueue(int fd, struct socket_state_4libkqueue* state);

// An EVFILT_SOCK knote was attached (delta 1) or detached (-1). While any is, the paths that return a socket's error
// to the program (read, recv, send, SO_ERROR) count it, so that a knote that looks later still sees that there was
// one (XNU posts the hint when the error happens).
VISIBLE
void _socket_watch_4libkqueue(int delta);


#endif // _DARLING_EMULATION_FOR_LIBKQUEUE_H_
