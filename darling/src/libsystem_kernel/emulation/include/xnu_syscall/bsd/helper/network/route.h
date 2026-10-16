#ifndef NETWORK_ROUTE_H
#define NETWORK_ROUTE_H

// PF_ROUTE sockets (XNU's bsd/net/rtsock.c), as far as a process asks the kernel which route and interface an address
// goes out on: RTM_GET (and RTM_GET_SILENT). The iOS Simulator's Network.framework evaluates every nw_path that way
// (on a Mac it asks the host kernel); without it each path is "unsatisfied (No network route)".
//
// A routing socket is one end of a Linux AF_UNIX datagram socketpair. Writing a message to it (write, writev, sendto,
// sendmsg) is answered here, from Linux's routing table over NETLINK_ROUTE, and the reply is queued on the other end
// (the answering end), so reading it, polling it, kqueue and FIONBIO behave as on a socket.
//
// Design:
// - The answer is built in the writer's thread, before write() returns, because XNU's route_output() queues the
//   reply before returning and Network.framework reads right after, with FIONBIO set: a background responder would
//   hand it EAGAIN.
// - The answer describes the routing table entry that matched (Linux's RTM_F_FIB_MATCH): its prefix, mask and
//   origin, with the interface, gateway and source address Linux would use. The unspecified address (0.0.0.0, ::)
//   matches the default route, as in XNU's radix tree.
// - Messages other than RTM_GET fail with EPERM (the routes are Linux's), and no unsolicited messages (RTM_IFINFO,
//   RTM_NEWADDR...) are ever sent; a reply goes only to its sender, never to other routing sockets. If broadcasts are
//   ever needed, darlingserver is their home: one rtnetlink subscription, fanned out to every process's sockets.
// - The answering end is per process (a forked child shares it), and a guarded descriptor, as darlingserver's are: the
//   program can't close it or dup2() over it. Copies of a routing socket made by dup(), dup2() and F_DUPFD are
//   answered too; one inherited across exec() isn't (its answering end closed with the old image).
// - Socket options: SO_TYPE is SOCK_RAW and SO_USELOOPBACK works (off: the sender gets no replies); options of any
//   other level fail with ENOPROTOOPT, as the routing domain has none; the rest are the AF_UNIX socket's.
// - The interfaces RTM_GET names are the ones NET_RT_IFLIST lists (ifinfo.h).

long route_socket_create(int type, int protocol);

// route_socket_count is non-zero while the process has a routing socket open: the write paths check it before
// looking a descriptor up. The lookup takes no lock, so other descriptors' writes and closes never wait on one.
extern volatile int route_socket_count;

#define ROUTE_SOCKET_ACTIVE() (route_socket_count != 0)

// If fd is a routing socket, handles the message in buf (len bytes) and stores the write's result in *result
// (bytes written, or a negative BSD errno); returns 1. Returns 0 for any other descriptor. addressed: the caller gave
// a destination address (sendto, sendmsg), which a routing socket refuses with EISCONN.
int route_socket_write(int fd, const void* buf, unsigned long len, int addressed, long* result);

// The iovec flavour, for writev and sendmsg; an iovcnt out of 1...UIO_MAXIOV fails with count_errno (writev's
// EINVAL, sendmsg's EMSGSIZE).
struct iovec;
int route_socket_writev(int fd, const struct iovec* iov, int iovcnt, int addressed, int count_errno, long* result);

// getsockopt (set 0) and setsockopt (set 1): returns 1 with the result in *result if fd is a routing socket and the
// option is one handled here, 0 to leave it to Linux.
int route_socket_sockopt(int fd, int set, int level, int name, void* value, int* value_len, long* result);

// getsockname (peer 0) and getpeername (peer 1): returns 1 with the result in *result if fd is a routing socket.
int route_socket_name(int fd, int peer, void* addr, int* addr_len, long* result);

// The descriptor fd is being closed, or dup2() is about to replace it.
void route_socket_close(int fd);

// copy is now a copy of the descriptor fd (dup, dup2, F_DUPFD).
void route_socket_dup(int fd, int copy);

// In the child of a fork, before it runs anything else.
void route_atfork_child(void);

#endif // NETWORK_ROUTE_H
