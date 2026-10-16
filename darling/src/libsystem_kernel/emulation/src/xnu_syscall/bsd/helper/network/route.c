#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>

#include <stddef.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <libsimple/lock.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/network/duct.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getpid.h>

extern void* memset(void* destination, int value, __SIZE_TYPE__ length);
extern void* memcpy(void* destination, const void* source, __SIZE_TYPE__ n);
extern __SIZE_TYPE__ strnlen(const char* string, __SIZE_TYPE__ max_length);

// Linux's side: rtnetlink (linux/netlink.h, linux/rtnetlink.h) and the interface ioctls (linux/sockios.h)

#define LINUX_AF_UNIX 1
#define LINUX_AF_INET 2
#define LINUX_AF_INET6 10
#define LINUX_AF_NETLINK 16
#define LINUX_SOCK_DGRAM 2
#define LINUX_SOCK_RAW 3
#define LINUX_SOCK_CLOEXEC 02000000
#define LINUX_NETLINK_ROUTE 0
#define LINUX_SOL_SOCKET 1
#define LINUX_SO_COOKIE 57
#define LINUX_F_SETFD 2
#define LINUX_FD_CLOEXEC 1

#define LINUX_NLMSG_ERROR 2
#define LINUX_NLM_F_REQUEST 1
#define LINUX_RTM_NEWROUTE 24
#define LINUX_RTM_GETROUTE 26
#define LINUX_RTA_DST 1
#define LINUX_RTA_OIF 4
#define LINUX_RTA_GATEWAY 5
#define LINUX_RTA_PREFSRC 7
#define LINUX_RTN_LOCAL 2

#define LINUX_SIOCGIFNAME 0x8910
#define LINUX_SIOCGIFHWADDR 0x8927
#define LINUX_ARPHRD_ETHER 1
#define LINUX_ARPHRD_LOOPBACK 772
#define LINUX_IFNAMSIZ 16

struct linux_nlmsghdr {
	unsigned int nlmsg_len;
	unsigned short nlmsg_type;
	unsigned short nlmsg_flags;
	unsigned int nlmsg_seq;
	unsigned int nlmsg_pid;
};

struct linux_rtmsg {
	unsigned char rtm_family;
	unsigned char rtm_dst_len;
	unsigned char rtm_src_len;
	unsigned char rtm_tos;
	unsigned char rtm_table;
	unsigned char rtm_protocol;
	unsigned char rtm_scope;
	unsigned char rtm_type;
	unsigned int rtm_flags;
};

struct linux_rtattr {
	unsigned short rta_len;
	unsigned short rta_type;
};

struct linux_sockaddr_nl {
	unsigned short nl_family;
	unsigned short nl_pad;
	unsigned int nl_pid;
	unsigned int nl_groups;
};

struct linux_ifreq {
	char ifr_name[LINUX_IFNAMSIZ];
	union {
		int ifr_ifindex;
		struct {
			unsigned short sa_family;
			unsigned char sa_data[14];
		} ifr_hwaddr;
		char pad[24];
	};
};

// XNU's private RTM_GET that only the sender sees (net/route.h, PRIVATE)
#ifndef RTM_GET_SILENT
#define RTM_GET_SILENT 0x11
#endif

#define NL_ALIGN(len) (((len) + 3) & ~3)

// XNU's ROUNDUP32 (bsd/net/rtsock.c): each sockaddr in a routing message takes its length rounded up to 4 bytes, and
// a zero-length one (a default route's netmask) takes 4
#define ROUNDUP32(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

static long linux_socket(int domain, int type, int protocol)
{
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SOCKET, ((long[6]) { domain, type, protocol }));
#else
	return LINUX_SYSCALL(__NR_socket, domain, type, protocol);
#endif
}

static long linux_sendto(int fd, const void* buf, unsigned long len, int flags, const void* addr, int addrlen)
{
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SENDTO, ((long[6]) { fd, buf, len, flags, addr, addrlen }));
#else
	return LINUX_SYSCALL(__NR_sendto, fd, buf, len, flags, addr, addrlen);
#endif
}

static long linux_recvfrom(int fd, void* buf, unsigned long len, int flags)
{
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_RECVFROM, ((long[6]) { fd, buf, len, flags, 0, 0 }));
#else
	return LINUX_SYSCALL(__NR_recvfrom, fd, buf, len, flags, 0, 0);
#endif
}

static long linux_socket_cookie(int fd, unsigned long long* cookie)
{
	unsigned int len = sizeof(*cookie);
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_GETSOCKOPT,
			((long[6]) { fd, LINUX_SOL_SOCKET, LINUX_SO_COOKIE, cookie, &len, 0 }));
#else
	return LINUX_SYSCALL(__NR_getsockopt, fd, LINUX_SOL_SOCKET, LINUX_SO_COOKIE, cookie, &len);
#endif
}

static void linux_close(int fd)
{
	LINUX_SYSCALL1(__NR_close, fd);
}

// ---- the process's routing sockets

#define MAX_ROUTE_SOCKETS 32

struct route_socket {
	int fd;                     // the process's end; -1: free
	int peer;                   // the answering end, where replies are sent from
	unsigned long long cookie;  // Linux's SO_COOKIE of fd: the descriptor still being this socket
	unsigned long long peer_cookie;
};

static struct route_socket route_sockets[MAX_ROUTE_SOCKETS] = {
	[0 ... MAX_ROUTE_SOCKETS - 1] = { .fd = -1, .peer = -1 },
};
static libsimple_lock_t route_sockets_lock = LIBSIMPLE_LOCK_INITIALIZER;
volatile int route_socket_count;

static void forget_locked(struct route_socket* rs)
{
	unsigned long long cookie;

	// unless the process closed it itself and the number is something else's now
	if (linux_socket_cookie(rs->peer, &cookie) == 0 && cookie == rs->peer_cookie)
		linux_close(rs->peer);
	rs->fd = rs->peer = -1;
	route_socket_count--;
}

long route_socket_create(int type, int protocol)
{
	int sv[2];
	long ret;
	unsigned long long cookie, peer_cookie;

	(void) protocol; // an address family to filter unsolicited messages by; none are sent
	if (type != SOCK_RAW)
		return -EPROTOTYPE;

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SOCKETPAIR,
			((long[6]) { LINUX_AF_UNIX, LINUX_SOCK_DGRAM, 0, sv }));
#else
	ret = LINUX_SYSCALL(__NR_socketpair, LINUX_AF_UNIX, LINUX_SOCK_DGRAM, 0, sv);
#endif
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	// the answering end stays with this process image
	LINUX_SYSCALL(__NR_fcntl, sv[1], LINUX_F_SETFD, LINUX_FD_CLOEXEC);

	ret = linux_socket_cookie(sv[0], &cookie);
	if (ret >= 0)
		ret = linux_socket_cookie(sv[1], &peer_cookie);
	if (ret < 0) {
		ret = errno_linux_to_bsd(ret);
		goto fail;
	}

	libsimple_lock_lock(&route_sockets_lock);
	ret = -ENOBUFS;
	for (int i = 0; i < MAX_ROUTE_SOCKETS; i++) {
		struct route_socket* rs = &route_sockets[i];
		if (rs->fd == sv[0])
			forget_locked(rs); // a stale entry: that descriptor was closed behind our back
		if (rs->fd == -1 && ret < 0) {
			rs->fd = sv[0];
			rs->peer = sv[1];
			rs->cookie = cookie;
			rs->peer_cookie = peer_cookie;
			route_socket_count++;
			ret = sv[0];
		}
	}
	libsimple_lock_unlock(&route_sockets_lock);
	if (ret >= 0)
		return ret;

fail:
	linux_close(sv[0]);
	linux_close(sv[1]);
	return ret;
}

// The answering end of fd, or -1 when fd isn't a routing socket (any more).
static int route_socket_peer(int fd)
{
	int peer = -1;
	unsigned long long cookie = 0;

	libsimple_lock_lock(&route_sockets_lock);
	for (int i = 0; i < MAX_ROUTE_SOCKETS; i++) {
		struct route_socket* rs = &route_sockets[i];
		if (rs->fd != fd)
			continue;
		// a descriptor closed some other way (dup2 over it, say) and reused is no longer ours
		if (linux_socket_cookie(fd, &cookie) < 0 || cookie != rs->cookie)
			forget_locked(rs);
		else
			peer = rs->peer;
		break;
	}
	libsimple_lock_unlock(&route_sockets_lock);
	return peer;
}

void route_socket_close(int fd)
{
	libsimple_lock_lock(&route_sockets_lock);
	for (int i = 0; i < MAX_ROUTE_SOCKETS; i++) {
		if (route_sockets[i].fd == fd) {
			forget_locked(&route_sockets[i]);
			break;
		}
	}
	libsimple_lock_unlock(&route_sockets_lock);
}

// ---- answering RTM_GET from Linux's routing table

struct route_answer {
	int family;               // BSD AF_INET or AF_INET6
	int prefix_len;           // of the destination; the full length for a host route
	int ifindex;
	int has_gateway;
	int has_prefsrc;
	int local;                // the destination is one of this host's addresses
	unsigned char dst[16];
	unsigned char gateway[16];
	unsigned char prefsrc[16];
};

static int addr_len(int family)
{
	return family == AF_INET ? 4 : 16;
}

// Asks Linux how it routes to the address dst (family AF_INET or AF_INET6). Returns 0 or a negative BSD errno:
// ESRCH when there is no route, as XNU's rt_lookup() failing does.
static int route_lookup(int family, const unsigned char* dst, struct route_answer* ans)
{
	struct {
		struct linux_nlmsghdr h;
		struct linux_rtmsg r;
		struct linux_rtattr a;
		unsigned char addr[16];
	} req;
	union {
		struct linux_nlmsghdr h;
		unsigned char bytes[4096];
	} reply;
	struct linux_sockaddr_nl kernel = { .nl_family = LINUX_AF_NETLINK };
	int alen = addr_len(family);
	int nl;
	long ret;

	memset(&req, 0, sizeof(req));
	req.h.nlmsg_len = sizeof(req.h) + sizeof(req.r) + sizeof(req.a) + alen;
	req.h.nlmsg_type = LINUX_RTM_GETROUTE;
	req.h.nlmsg_flags = LINUX_NLM_F_REQUEST;
	req.h.nlmsg_seq = 1;
	req.r.rtm_family = family == AF_INET ? LINUX_AF_INET : LINUX_AF_INET6;
	req.r.rtm_dst_len = alen * 8;
	req.a.rta_len = sizeof(req.a) + alen;
	req.a.rta_type = LINUX_RTA_DST;
	memcpy(req.addr, dst, alen);

	nl = linux_socket(LINUX_AF_NETLINK, LINUX_SOCK_RAW | LINUX_SOCK_CLOEXEC, LINUX_NETLINK_ROUTE);
	if (nl < 0)
		return errno_linux_to_bsd(nl);
	ret = linux_sendto(nl, &req, req.h.nlmsg_len, 0, &kernel, sizeof(kernel));
	if (ret >= 0)
		ret = linux_recvfrom(nl, &reply, sizeof(reply), 0);
	linux_close(nl);
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	if (ret < (long) sizeof(reply.h) || reply.h.nlmsg_len > ret)
		return -EIO;

	if (reply.h.nlmsg_type == LINUX_NLMSG_ERROR) {
		// ENETUNREACH, EHOSTUNREACH...: no route
		return -ESRCH;
	}
	if (reply.h.nlmsg_type != LINUX_RTM_NEWROUTE)
		return -EIO;

	const struct linux_rtmsg* rtm = (const void*) (reply.bytes + sizeof(reply.h));
	memset(ans, 0, sizeof(*ans));
	ans->family = family;
	ans->prefix_len = rtm->rtm_dst_len;
	ans->local = rtm->rtm_type == LINUX_RTN_LOCAL;
	memcpy(ans->dst, dst, alen);

	unsigned long off = sizeof(reply.h) + NL_ALIGN(sizeof(*rtm));
	while (off + sizeof(struct linux_rtattr) <= reply.h.nlmsg_len) {
		const struct linux_rtattr* a = (const void*) (reply.bytes + off);
		const unsigned char* data = (const unsigned char*) (a + 1);
		int dlen = a->rta_len - (int) sizeof(*a);

		if (a->rta_len < sizeof(*a) || off + a->rta_len > reply.h.nlmsg_len)
			break;
		switch (a->rta_type) {
		case LINUX_RTA_DST:
			if (dlen == alen)
				memcpy(ans->dst, data, alen);
			break;
		case LINUX_RTA_OIF:
			if (dlen == 4)
				memcpy(&ans->ifindex, data, 4);
			break;
		case LINUX_RTA_GATEWAY:
			if (dlen == alen) {
				memcpy(ans->gateway, data, alen);
				ans->has_gateway = 1;
			}
			break;
		case LINUX_RTA_PREFSRC:
			if (dlen == alen) {
				memcpy(ans->prefsrc, data, alen);
				ans->has_prefsrc = 1;
			}
			break;
		}
		off += NL_ALIGN(a->rta_len);
	}

	return ans->ifindex > 0 ? 0 : -ESRCH;
}

int route_link_sockaddr(int ifindex, struct sockaddr_dl* sdl, unsigned long size)
{
	struct linux_ifreq ifr;
	int s, nlen, alen = 0, type = IFT_OTHER;
	unsigned char lladdr[6];
	long ret;
	unsigned long len;

	s = linux_socket(LINUX_AF_INET, LINUX_SOCK_DGRAM | LINUX_SOCK_CLOEXEC, 0);
	if (s < 0)
		return errno_linux_to_bsd(s);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;
	ret = LINUX_SYSCALL(__NR_ioctl, s, LINUX_SIOCGIFNAME, &ifr);
	if (ret < 0) {
		linux_close(s);
		return errno_linux_to_bsd(ret);
	}
	if (LINUX_SYSCALL(__NR_ioctl, s, LINUX_SIOCGIFHWADDR, &ifr) == 0) {
		if (ifr.ifr_hwaddr.sa_family == LINUX_ARPHRD_ETHER) {
			type = IFT_ETHER;
			alen = 6;
			memcpy(lladdr, ifr.ifr_hwaddr.sa_data, 6);
		} else if (ifr.ifr_hwaddr.sa_family == LINUX_ARPHRD_LOOPBACK) {
			type = IFT_LOOP;
		}
	}
	linux_close(s);

	nlen = strnlen(ifr.ifr_name, LINUX_IFNAMSIZ);
	len = sizeof(*sdl);
	if (nlen + alen > sizeof(sdl->sdl_data))
		len += nlen + alen - sizeof(sdl->sdl_data);
	if (len > size)
		return -ENOBUFS;

	memset(sdl, 0, len);
	sdl->sdl_len = len;
	sdl->sdl_family = AF_LINK;
	sdl->sdl_index = ifindex;
	sdl->sdl_type = type;
	sdl->sdl_nlen = nlen;
	sdl->sdl_alen = alen;
	memcpy(sdl->sdl_data, ifr.ifr_name, nlen);
	if (alen)
		memcpy(sdl->sdl_data + nlen, lladdr, alen);
	return len;
}

// Appends an internet address (or netmask) as a BSD sockaddr; returns the bytes used.
static int put_inet(unsigned char* out, int family, const unsigned char* addr)
{
	if (family == AF_INET) {
		struct sockaddr_in* sin = (void*) out;
		memset(sin, 0, sizeof(*sin));
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, addr, 4);
		return ROUNDUP32(sizeof(*sin));
	} else {
		struct sockaddr_in6* sin6 = (void*) out;
		memset(sin6, 0, sizeof(*sin6));
		sin6->sin6_len = sizeof(*sin6);
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, addr, 16);
		return ROUNDUP32(sizeof(*sin6));
	}
}

// The largest reply: the header and DST, GATEWAY, NETMASK, IFP and IFA
#define ROUTE_REPLY_MAX (sizeof(struct rt_msghdr) + 5 * 128)

// Builds the reply to the RTM_GET in req as XNU's route_output() does (bsd/net/rtsock.c): the request's header, with
// the route's flags and interface index and its addresses in RTA_* order. Returns its length or a negative BSD errno.
static long answer_get(const struct rt_msghdr* req, const struct sockaddr* dst, unsigned char* out)
{
	struct route_answer ans;
	struct rt_msghdr* rtm = (void*) out;
	unsigned char* p = out + sizeof(*rtm);
	unsigned char addr[16];
	int family = dst->sa_family;
	int full = addr_len(family) * 8;
	int ret;

	if (family == AF_INET) {
		if (dst->sa_len < offsetof(struct sockaddr_in, sin_zero))
			return -EINVAL;
		memcpy(addr, &((const struct sockaddr_in*) dst)->sin_addr, 4);
	} else if (family == AF_INET6) {
		if (dst->sa_len < sizeof(struct sockaddr_in6))
			return -EINVAL;
		memcpy(addr, &((const struct sockaddr_in6*) dst)->sin6_addr, 16);
	} else {
		return -EAFNOSUPPORT;
	}

	ret = route_lookup(family, addr, &ans);
	if (ret < 0)
		return ret;

	memcpy(rtm, req, sizeof(*rtm));
	rtm->rtm_addrs = 0;
	rtm->rtm_flags = RTF_UP | RTF_DONE | (ans.has_gateway ? RTF_GATEWAY : 0) | (ans.prefix_len == full ? RTF_HOST : 0);
	rtm->rtm_index = ans.ifindex;

	rtm->rtm_addrs |= RTA_DST;
	p += put_inet(p, family, ans.dst);

	rtm->rtm_addrs |= RTA_GATEWAY;
	if (ans.has_gateway) {
		p += put_inet(p, family, ans.gateway);
	} else {
		// a directly connected route's gateway is its interface (XNU's link-level gateway)
		ret = route_link_sockaddr(ans.ifindex, (void*) p, 128);
		if (ret < 0)
			return ret;
		p += ROUNDUP32(ret);
	}

	if (ans.prefix_len != full) {
		unsigned char mask[16] = { 0 };
		rtm->rtm_addrs |= RTA_NETMASK;
		if (ans.prefix_len == 0) {
			// the default route's mask, which XNU keeps zero-length
			memset(p, 0, 4);
			p += 4;
		} else {
			for (int i = 0; i < ans.prefix_len; i++)
				mask[i / 8] |= 0x80 >> (i % 8);
			p += put_inet(p, family, mask);
		}
	}

	if (req->rtm_addrs & (RTA_IFP | RTA_IFA)) {
		ret = route_link_sockaddr(ans.ifindex, (void*) p, 128);
		if (ret >= 0) {
			rtm->rtm_addrs |= RTA_IFP;
			p += ROUNDUP32(ret);
		}
		if (ans.has_prefsrc || ans.local) {
			rtm->rtm_addrs |= RTA_IFA;
			p += put_inet(p, family, ans.has_prefsrc ? ans.prefsrc : ans.dst);
		}
	}

	rtm->rtm_msglen = p - out;
	return rtm->rtm_msglen;
}

static long route_message(int peer, const unsigned char* msg, unsigned long len)
{
	const struct rt_msghdr* req = (const void*) msg;
	unsigned char reply[ROUTE_REPLY_MAX];
	const struct sockaddr* dst = NULL;
	long err = 0, rlen = -EINVAL;

	// as route_output(): a message whose length is wrong is dropped; any other failure goes back to the sender with
	// rtm_errno set, and the write fails with it
	if (len < sizeof(*req) || req->rtm_msglen != len || len > sizeof(reply))
		return -EINVAL;

	if (req->rtm_version != RTM_VERSION) {
		rlen = -EPROTONOSUPPORT;
	} else if (req->rtm_type != RTM_GET && req->rtm_type != RTM_GET_SILENT) {
		rlen = -EPERM; // the routes are Linux's: nothing here changes them
	} else {
		// rt_xaddrs(): the addresses that follow, in RTA_* bit order
		const unsigned char* p = msg + sizeof(*req);
		for (int bit = 0; bit < RTAX_MAX; bit++) {
			if (!(req->rtm_addrs & (1 << bit)))
				continue;
			const struct sockaddr* sa = (const void*) p;
			if (p + 1 > msg + len || p + ROUNDUP32(sa->sa_len) > msg + len) {
				dst = NULL;
				break;
			}
			if (bit == RTAX_DST)
				dst = sa;
			p += ROUNDUP32(sa->sa_len);
		}
		if (dst != NULL)
			rlen = answer_get(req, dst, reply);
	}

	if (rlen < 0) {
		err = rlen;
		memcpy(reply, msg, len);
		((struct rt_msghdr*) reply)->rtm_errno = -err;
		rlen = len;
	}
	struct rt_msghdr* rtm = (void*) reply;
	rtm->rtm_pid = sys_getpid();
	if (rtm->rtm_type == RTM_GET_SILENT)
		rtm->rtm_type = RTM_GET;

	// a full receive queue drops the reply, as sbappendaddr() does
	linux_sendto(peer, reply, rlen, LINUX_MSG_DONTWAIT, NULL, 0);

	return err ? err : (long) len;
}

int route_socket_write(int fd, const void* buf, unsigned long len, long* result)
{
	int peer = route_socket_peer(fd);
	if (peer < 0)
		return 0;
	*result = route_message(peer, buf, len);
	return 1;
}

int route_socket_writev(int fd, const struct iovec* iov, int iovcnt, long* result)
{
	unsigned char msg[ROUTE_REPLY_MAX];
	unsigned long len = 0;
	int peer = route_socket_peer(fd);

	if (peer < 0)
		return 0;
	for (int i = 0; i < iovcnt; i++) {
		if (len + iov[i].iov_len > sizeof(msg)) {
			*result = -EMSGSIZE;
			return 1;
		}
		memcpy(msg + len, iov[i].iov_base, iov[i].iov_len);
		len += iov[i].iov_len;
	}
	*result = route_message(peer, msg, len);
	return 1;
}
