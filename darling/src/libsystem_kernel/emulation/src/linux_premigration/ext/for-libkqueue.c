#include <darling/emulation/linux_premigration/ext/for-libkqueue.h>

#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/fcntl/fcntl.h>
#include <darling/emulation/linux_premigration/signal/signal_knotes.h>

#include <darlingserver/rpc.h>

int _dserver_rpc_kqchan_mach_port_open_4libkqueue(uint32_t port_name, void* receive_buffer, uint64_t receive_buffer_size, uint64_t saved_filter_flags, int* out_socket) {
	return dserver_rpc_kqchan_mach_port_open(port_name, receive_buffer, receive_buffer_size, saved_filter_flags, out_socket);
};

int _dserver_rpc_kqchan_proc_open_4libkqueue(int32_t pid, uint32_t flags, int* out_socket) {
	return dserver_rpc_kqchan_proc_open(pid, flags, out_socket);
};

int _dup_4libkqueue(int fd) {
	int ret;

	// close-on-exec, as the other descriptors libkqueue makes are: a knote's copy must not keep the socket (or
	// file) open in a program this one execs
	ret = LINUX_SYSCALL3(__NR_fcntl, fd, LINUX_F_DUPFD_CLOEXEC, 0);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
};

int _signal_knote_open_4libkqueue(int signum) {
	int ret = signal_knote_open(signum);

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
};

void _signal_knote_close_4libkqueue(int fd) {
	signal_knote_close(fd);
};

int _socket_state_4libkqueue(int fd, unsigned int* state, int* error) {
	return socket_state(fd, state, error);
};
