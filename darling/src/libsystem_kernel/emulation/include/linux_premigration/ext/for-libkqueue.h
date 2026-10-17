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
	unsigned int state;    // SOSTATE_*
	int error;             // the pending error (XNU's so_error, a BSD errno; 0 if none), which stays pending
	// XNU's TCP's one-shot hints, counted while the socket is watched (_socket_watch_4libkqueue): each changes when
	// the socket has another error that raises it, also if something has taken the error since
	unsigned int resets;   // NOTE_CONNRESET: refused or reset (tcp_input()'s RST handling)
	unsigned int timeouts; // NOTE_TIMEOUT: timed out, or unreachable (tcp_timers()' drops)
};

// The state of socket fd. Returns 0, or a negative BSD errno: ENOTSOCK if fd isn't a socket.
VISIBLE
int _socket_state_4libkqueue(int fd, struct socket_state_4libkqueue* state);

// Only the pending error of socket fd (0 if none, or if fd isn't a socket), for EVFILT_READ and EVFILT_WRITE at end
// of file. linux_error: Linux reported an error on it (EPOLLERR).
VISIBLE
int _socket_error_4libkqueue(int fd, int linux_error);

// An EVFILT_SOCK knote started (delta 1) or stopped (-1) watching socket fd. While one does, the paths that return the
// socket's errors to the program (read, recv, send, SO_ERROR) count them for its hints.
VISIBLE
void _socket_watch_4libkqueue(int fd, int delta);

// Defined by libkqueue, called by libsystem_kernel, which has weak no-op definitions for a process without libkqueue
// (close.c, dup.c, connect.c).

// close(kq): non-zero if kq is a kqueue, which libkqueue closed.
int kqueue_close(int kq);
// Descriptor fd was closed: its knotes go.
void kqueue_closed_fd(int fd);
// newfd is now a copy of oldfd (dup, dup2, F_DUPFD).
void kqueue_dup(int oldfd, int newfd);
// Socket fd's state may have changed in a way Linux wakes no one for (a datagram socket connected or disconnected, a
// shutdown): its EVFILT_SOCK knotes look again, as XNU's soevent() would have them do. Called only while EVFILT_SOCK
// knotes exist (sostate.h's socket_watchers).
void kqueue_socket_changed(int fd);


#endif // _DARLING_EMULATION_FOR_LIBKQUEUE_H_
