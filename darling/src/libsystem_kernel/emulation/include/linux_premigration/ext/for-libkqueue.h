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

#endif // _DARLING_EMULATION_FOR_LIBKQUEUE_H_
