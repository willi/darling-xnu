#ifndef _DARLING_EMULATION_FOR_LIBKQUEUE_H_
#define _DARLING_EMULATION_FOR_LIBKQUEUE_H_

#include <stdint.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>

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

// EVFILT_SOCK (see sostate.h): socket fd's XNU so_state bits (SOSTATE_*) and pending error (a BSD errno, left
// pending), or a negative BSD errno: ENOTSOCK if fd isn't a socket.
VISIBLE
int _socket_state_4libkqueue(int fd, unsigned int* state, int* error);

#endif // _DARLING_EMULATION_FOR_LIBKQUEUE_H_
