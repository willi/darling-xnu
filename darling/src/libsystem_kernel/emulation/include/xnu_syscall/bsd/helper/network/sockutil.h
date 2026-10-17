#ifndef NETWORK_SOCKUTIL_H
#define NETWORK_SOCKUTIL_H

// Linux socket queries the network helpers share (route.c, sostate.c, nosigpipe.c). They return 0 or a negative
// Linux errno.

long linux_getsockopt(int fd, int level, int name, void* value, unsigned int* len);

// Linux's SO_COOKIE (Linux 4.13): an identity for the socket fd refers to, never reused while the system runs. The
// tables that remember something per socket key it by this, so a descriptor that was closed and its number reused
// isn't taken for the old socket, and copies of a descriptor (dup, fork) are the same socket.
long linux_socket_cookie(int fd, unsigned long long* cookie);

// The start of Linux's struct tcp_info, up to tcpi_segs_in (Linux 4.2)
struct linux_tcp_info {
	unsigned char state;
	unsigned char other[135];
	unsigned int segs_out;
	unsigned int segs_in;
};

// Linux's TCP states (include/net/tcp_states.h)
enum {
	LINUX_TCP_ESTABLISHED = 1,
	LINUX_TCP_SYN_SENT,
	LINUX_TCP_SYN_RECV,
	LINUX_TCP_FIN_WAIT1,
	LINUX_TCP_FIN_WAIT2,
	LINUX_TCP_TIME_WAIT,
	LINUX_TCP_CLOSE,
	LINUX_TCP_CLOSE_WAIT,
	LINUX_TCP_LAST_ACK,
	LINUX_TCP_LISTEN,
	LINUX_TCP_CLOSING,
};

// fd's TCP_INFO: 0 if fd is a TCP socket, a negative Linux errno if not.
long linux_tcp_info(int fd, struct linux_tcp_info* info);

#endif // NETWORK_SOCKUTIL_H
