#ifndef NETWORK_ROUTE_H
#define NETWORK_ROUTE_H

// PF_ROUTE sockets (XNU's bsd/net/rtsock.c), as far as a process asks the kernel which route and interface an address
// goes out on: RTM_GET (and RTM_GET_SILENT). The iOS Simulator's Network.framework evaluates every nw_path that way
// (on a Mac it asks the host kernel); without it each path is "unsatisfied (No network route)".
//
// A routing socket is one end of a Linux AF_UNIX datagram socketpair. Writing a message to it (write, writev, sendto,
// sendmsg) is answered here, from Linux's routing table over NETLINK_ROUTE, and the reply is queued on the other end,
// so reading it, polling it, kqueue and FIONBIO behave as on a socket. Messages other than RTM_GET fail with EPERM
// (the routes are Linux's), and no unsolicited messages (RTM_IFINFO, RTM_NEWADDR, ...) are ever sent.
//
// The answering end is per process (a forked child shares it): a copy of the descriptor made by dup() or inherited
// across exec() reads no replies. It is a guarded descriptor, as darlingserver's are: the program can't close it or
// dup2() over it.

long route_socket_create(int type, int protocol);

// route_socket_count is non-zero while the process has a routing socket open: the write paths check it before
// looking a descriptor up. The lookup takes no lock, so other descriptors' writes and closes never wait on one.
extern volatile int route_socket_count;

// If fd is a routing socket, handles the message in buf (len bytes) and stores the write's result in *result
// (bytes written, or a negative BSD errno); returns 1. Returns 0 for any other descriptor.
int route_socket_write(int fd, const void* buf, unsigned long len, long* result);

// The iovec flavour, for writev and sendmsg; an iovcnt out of 1...UIO_MAXIOV fails with count_errno (writev's
// EINVAL, sendmsg's EMSGSIZE).
struct iovec;
int route_socket_writev(int fd, const struct iovec* iov, int iovcnt, int count_errno, long* result);

// The descriptor fd is being closed, or dup2() is about to replace it.
void route_socket_close(int fd);

// In the child of a fork, before it runs anything else.
void route_atfork_child(void);

// The interface a Linux interface index names, as Darwin describes it in RTA_IFP and NET_RT_IFLIST: a sockaddr_dl
// with the interface's name, type and link-layer address. Returns its length, or a negative BSD errno.
struct sockaddr_dl;
int route_link_sockaddr(int ifindex, struct sockaddr_dl* sdl, unsigned long size);

#define ROUTE_SOCKET_ACTIVE() (route_socket_count != 0)

#endif // NETWORK_ROUTE_H
