#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <libsimple/lock.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/common/simple.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/common/guarded/table.h>
#include <darling/emulation/conversion/network/duct.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/ifinfo.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/rtnetlink.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/getpid.h>

extern void* memset(void* destination, int value, __SIZE_TYPE__ length);
extern void* memcpy(void* destination, const void* source, __SIZE_TYPE__ n);

#define LINUX_AF_UNIX 1
#define LINUX_SOCK_CLOEXEC 02000000
#define LINUX_SOL_SOCKET 1
#define LINUX_SO_COOKIE 57
#define LINUX_F_SETFD 2
#define LINUX_SYS_SOCKETPAIR 8
#define LINUX_SIG_BLOCK 0
#define LINUX_SIG_SETMASK 2

// XNU's private RTM_GET that only the sender sees (net/route.h, PRIVATE)
#ifndef RTM_GET_SILENT
#define RTM_GET_SILENT 0x11
#endif

// XNU's ROUNDUP32 (bsd/net/rtsock.c): each sockaddr in a routing message takes its length rounded up to 4 bytes, and
// a zero-length one (a default route's netmask) takes 4
#define ROUNDUP32(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

static long linux_sendto(int fd, const void* buf, unsigned long len, int flags)
{
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SENDTO, ((long[6]) { fd, buf, len, flags, 0, 0 }));
#else
	return LINUX_SYSCALL(__NR_sendto, fd, buf, len, flags, 0, 0);
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
//
// The write and close paths look a descriptor up without the lock: each slot's fd is read atomically, and only a
// match takes the lock (and re-checks), so writes and closes of other descriptors never touch it, and a signal
// handler's write() or close() can't deadlock on it. Holding the lock blocks signals for the same reason, as
// ulock_wait.c's table does.
//
// The answering end (peer) is the process's, not the program's: it's in the guard table, so the program's close()
// leaves it alone and a dup2() over it is refused, and only forget_locked() closes it, with the last descriptor that
// shares it (dup() and its kin give a routing socket more). A slot's generation changes each time it's forgotten, so
// a reply prepared while the lock was released (across the netlink round trip) goes out only if the slot still holds
// the same routing socket, through the same peer.

#define MAX_ROUTE_SOCKETS 32

struct route_socket {
	int fd;                     // the process's end; -1: free. Written under the lock, read without it.
	int peer;                   // the answering end, where replies are sent from
	unsigned long long cookie;  // Linux's SO_COOKIE of fd: the descriptor still being this socket
	unsigned long long peer_cookie;
	unsigned int generation;    // changes each time the slot is forgotten
	int* useloopback;           // SO_USELOOPBACK, one per socket: shared by the descriptors that share the peer
};

static struct route_socket route_sockets[MAX_ROUTE_SOCKETS] = {
	[0 ... MAX_ROUTE_SOCKETS - 1] = { .fd = -1, .peer = -1 },
};
// SO_USELOOPBACK of the socket whose first descriptor took slot i
static int route_useloopback[MAX_ROUTE_SOCKETS];
static libsimple_lock_t route_sockets_lock = LIBSIMPLE_LOCK_INITIALIZER;
volatile int route_socket_count;

static unsigned long long route_lock(void)
{
	unsigned long long all = ~0ull, old;

	LINUX_SYSCALL(__NR_rt_sigprocmask, LINUX_SIG_BLOCK, &all, &old, sizeof(all));
	libsimple_lock_lock(&route_sockets_lock);
	return old;
}

static void route_unlock(unsigned long long old)
{
	libsimple_lock_unlock(&route_sockets_lock);
	LINUX_SYSCALL(__NR_rt_sigprocmask, LINUX_SIG_SETMASK, &old, NULL, sizeof(old));
}

void route_atfork_child(void)
{
	// the child has only the forking thread: nobody holds the lock. Its routing sockets are the parent's (fork
	// shares them), and so are their answering ends, which it keeps.
	libsimple_lock_init(&route_sockets_lock);
}

// The slot that has fd, found without the lock; -1 if none.
static int route_slot(int fd)
{
	for (int i = 0; i < MAX_ROUTE_SOCKETS; i++) {
		if (__atomic_load_n(&route_sockets[i].fd, __ATOMIC_ACQUIRE) == fd)
			return i;
	}
	return -1;
}

static int same_socket(int fd, unsigned long long cookie)
{
	unsigned long long now;
	return linux_socket_cookie(fd, &now) == 0 && now == cookie;
}

static void forget_locked(struct route_socket* rs)
{
	int shared = 0;

	__atomic_store_n(&rs->fd, -1, __ATOMIC_RELEASE);
	rs->generation++;
	for (int i = 0; i < MAX_ROUTE_SOCKETS; i++)
		shared |= route_sockets[i].fd >= 0 && route_sockets[i].peer == rs->peer;
	if (!shared) {
		guard_table_remove(rs->peer);
		// the guard kept the program from closing it; the cookie is a last check that the number is still ours
		if (same_socket(rs->peer, rs->peer_cookie))
			linux_close(rs->peer);
	}
	rs->peer = -1;
	__atomic_sub_fetch(&route_socket_count, 1, __ATOMIC_RELAXED);
}

// Takes a free slot for fd, answered through peer; returns it, or -1 if there's none.
static int claim_locked(int fd, unsigned long long cookie, int peer, unsigned long long peer_cookie, int* useloopback)
{
	for (int i = 0; i < MAX_ROUTE_SOCKETS; i++) {
		if (route_sockets[i].fd == fd)
			forget_locked(&route_sockets[i]); // a stale entry: that descriptor was closed behind our back
	}
	for (int i = 0; i < MAX_ROUTE_SOCKETS; i++) {
		struct route_socket* rs = &route_sockets[i];
		if (rs->fd != -1)
			continue;
		rs->peer = peer;
		rs->cookie = cookie;
		rs->peer_cookie = peer_cookie;
		if (useloopback) {
			rs->useloopback = useloopback;
		} else {
			rs->useloopback = &route_useloopback[i];
			route_useloopback[i] = 1; // XNU's rts_attach() sets it
		}
		__atomic_add_fetch(&route_socket_count, 1, __ATOMIC_RELAXED);
		__atomic_store_n(&rs->fd, fd, __ATOMIC_RELEASE);
		return i;
	}
	return -1;
}

long route_socket_create(int type, int protocol)
{
	int sv[2];
	long ret;
	unsigned long long cookie, peer_cookie, mask;

	// the protocol is an address family to filter unsolicited messages by; none are sent
	(void) protocol;
	// XNU's socreate() finds no PF_ROUTE protocol of another type
	if (type != SOCK_RAW)
		return -EPROTONOSUPPORT;

	// both ends close-on-exec from the start, so no exec on another thread can take the answering end along;
	// the program's end then gets the BSD default back
#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SOCKETPAIR,
			((long[6]) { LINUX_AF_UNIX, LINUX_SOCK_DGRAM | LINUX_SOCK_CLOEXEC, 0, sv }));
#else
	ret = LINUX_SYSCALL(__NR_socketpair, LINUX_AF_UNIX, LINUX_SOCK_DGRAM | LINUX_SOCK_CLOEXEC, 0, sv);
#endif
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	ret = LINUX_SYSCALL(__NR_fcntl, sv[0], LINUX_F_SETFD, 0);
	if (ret >= 0)
		ret = linux_socket_cookie(sv[0], &cookie);
	if (ret >= 0)
		ret = linux_socket_cookie(sv[1], &peer_cookie);
	if (ret < 0) {
		ret = errno_linux_to_bsd(ret);
		goto fail;
	}

	mask = route_lock();
	ret = -ENOBUFS;
	for (int i = 0; i < MAX_ROUTE_SOCKETS; i++) {
		if (route_sockets[i].fd == sv[1])
			forget_locked(&route_sockets[i]);
	}
	if (guard_table_add(sv[1], guard_flag_prevent_close, NULL) == 0) {
		if (claim_locked(sv[0], cookie, sv[1], peer_cookie, NULL) >= 0)
			ret = sv[0];
		else
			guard_table_remove(sv[1]);
	}
	route_unlock(mask);
	if (ret >= 0)
		return ret;

fail:
	linux_close(sv[0]);
	linux_close(sv[1]);
	return ret;
}

// A routing socket as a write found it: which slot, in which generation, answered through which peer.
struct route_ref {
	int slot;
	unsigned int generation;
	int peer;
	int useloopback;
};

// Looks fd up; returns 0 and fills ref if it's a routing socket, -1 if not (any more).
static int route_socket_ref(int fd, struct route_ref* ref)
{
	int slot = route_slot(fd), found = -1;
	unsigned long long mask;

	if (slot < 0)
		return -1;
	mask = route_lock();
	struct route_socket* rs = &route_sockets[slot];
	if (rs->fd == fd) {
		// a descriptor closed some other way and reused is no longer ours
		if (!same_socket(fd, rs->cookie)) {
			forget_locked(rs);
		} else {
			ref->slot = slot;
			ref->generation = rs->generation;
			ref->peer = rs->peer;
			ref->useloopback = *rs->useloopback;
			found = 0;
		}
	}
	route_unlock(mask);
	return found;
}

// Queues reply on the routing socket ref names, unless it was closed (or its number reused) since it was looked up.
static void route_socket_reply(const struct route_ref* ref, const void* reply, unsigned long len)
{
	unsigned long long mask = route_lock();
	struct route_socket* rs = &route_sockets[ref->slot];

	// a full receive queue drops the reply, as sbappendaddr() does
	if (rs->fd >= 0 && rs->generation == ref->generation && rs->peer == ref->peer)
		linux_sendto(ref->peer, reply, len, LINUX_MSG_DONTWAIT);
	route_unlock(mask);
}

void route_socket_close(int fd)
{
	int slot = route_slot(fd);
	unsigned long long mask;

	if (slot < 0)
		return;
	mask = route_lock();
	if (route_sockets[slot].fd == fd)
		forget_locked(&route_sockets[slot]);
	route_unlock(mask);
}

void route_socket_dup(int fd, int copy)
{
	int slot = route_slot(fd);
	unsigned long long mask;

	if (slot < 0 || copy == fd)
		return;
	mask = route_lock();
	struct route_socket* rs = &route_sockets[slot];
	// the copy is the same socket (the same cookie), answered through the same peer
	if (rs->fd == fd && same_socket(copy, rs->cookie)) {
		if (claim_locked(copy, rs->cookie, rs->peer, rs->peer_cookie, rs->useloopback) < 0)
			__simple_kprintf("route: no slot for a copy (%d) of routing socket %d: it reads no replies", copy, fd);
	}
	route_unlock(mask);
}

// ---- RTM_GET: asking Linux's routing table

struct rt_entry {
	int dst_len;
	int type;           // RTN_*
	int protocol;       // RTPROT_*
	int table;
	int oif;
	unsigned int priority;
	int has_dst, has_gateway, has_prefsrc;
	unsigned char dst[16], gateway[16], prefsrc[16];
};

struct rt_walk {
	int alen;
	struct rt_entry* e;
	int found;
};

static void rt_attr(const struct linux_rtattr* attr, const void* data, int len, void* context)
{
	struct rt_walk* walk = context;
	struct rt_entry* e = walk->e;

	switch (attr->rta_type) {
	case LINUX_RTA_DST:
		if (len == walk->alen) {
			memcpy(e->dst, data, len);
			e->has_dst = 1;
		}
		break;
	case LINUX_RTA_OIF:
		if (len == 4)
			memcpy(&e->oif, data, 4);
		break;
	case LINUX_RTA_GATEWAY:
		if (len == walk->alen) {
			memcpy(e->gateway, data, len);
			e->has_gateway = 1;
		}
		break;
	case LINUX_RTA_PREFSRC:
		if (len == walk->alen) {
			memcpy(e->prefsrc, data, len);
			e->has_prefsrc = 1;
		}
		break;
	case LINUX_RTA_PRIORITY:
		if (len == 4)
			memcpy(&e->priority, data, 4);
		break;
	case LINUX_RTA_TABLE:
		if (len == 4)
			memcpy(&e->table, data, 4);
		break;
	case LINUX_RTA_MULTIPATH: {
		// a multipath route's first next hop stands for it
		const struct linux_rtnexthop* nh = data;
		if (len < (int) sizeof(*nh) || nh->rtnh_len < sizeof(*nh) || nh->rtnh_len > len)
			break;
		if (!e->oif)
			e->oif = nh->rtnh_ifindex;
		const unsigned char* p = (const unsigned char*) (nh + 1);
		const unsigned char* end = (const unsigned char*) nh + nh->rtnh_len;
		while (p + sizeof(struct linux_rtattr) <= end) {
			const struct linux_rtattr* a = (const void*) p;
			if (a->rta_len < sizeof(*a) || p + a->rta_len > end)
				break;
			if (a->rta_type == LINUX_RTA_GATEWAY && a->rta_len - sizeof(*a) == (unsigned) walk->alen
					&& !e->has_gateway) {
				memcpy(e->gateway, a + 1, walk->alen);
				e->has_gateway = 1;
			}
			p += RTNL_ALIGN(a->rta_len);
		}
		break;
	}
	}
}

static int parse_route(const struct linux_nlmsghdr* msg, int alen, struct rt_entry* e)
{
	const struct linux_rtmsg* rtm = (const void*) (msg + 1);
	struct rt_walk walk = { .alen = alen, .e = e };

	if (msg->nlmsg_type != LINUX_RTM_NEWROUTE || msg->nlmsg_len < sizeof(*msg) + sizeof(*rtm))
		return -1;
	memset(e, 0, sizeof(*e));
	e->dst_len = rtm->rtm_dst_len;
	e->type = rtm->rtm_type;
	e->protocol = rtm->rtm_protocol;
	e->table = rtm->rtm_table;
	rtnl_attrs(msg, sizeof(*rtm), rt_attr, &walk);
	return 0;
}

static int got_route(const struct linux_nlmsghdr* msg, void* context)
{
	struct rt_walk* walk = context;
	if (parse_route(msg, walk->alen, walk->e) == 0)
		walk->found = 1;
	return walk->found;
}

// Linux's answer for dst (scoped to the interface oif, if not 0): the route it would use (fib 0: OIF, GATEWAY,
// PREFSRC and the destination's type), or the routing table entry that matched (fib 1: the prefix and its origin).
static int rt_get(int nl, int family, const unsigned char* dst, int oif, int fib, struct rt_entry* e)
{
	int alen = family == AF_INET ? 4 : 16;
	union {
		struct {
			struct linux_nlmsghdr h;
			struct linux_rtmsg r;
			struct linux_rtattr dst_attr;
		} m;
		unsigned char bytes[64];
	} req;
	struct rt_walk walk = { .alen = alen, .e = e };
	unsigned long len = sizeof(req.m);

	memset(&req, 0, sizeof(req));
	req.m.r.rtm_family = family == AF_INET ? LINUX_AF_INET : LINUX_AF_INET6;
	req.m.r.rtm_dst_len = alen * 8;
	req.m.r.rtm_flags = fib ? LINUX_RTM_F_FIB_MATCH : 0;
	req.m.dst_attr.rta_len = sizeof(req.m.dst_attr) + alen;
	req.m.dst_attr.rta_type = LINUX_RTA_DST;
	memcpy(req.bytes + len, dst, alen);
	len += alen;
	if (oif) {
		struct linux_rtattr a = { .rta_len = sizeof(a) + 4, .rta_type = LINUX_RTA_OIF };
		memcpy(req.bytes + len, &a, sizeof(a));
		memcpy(req.bytes + len + sizeof(a), &oif, 4);
		len += sizeof(a) + 4;
	}
	req.m.h.nlmsg_len = len;
	req.m.h.nlmsg_type = LINUX_RTM_GETROUTE;
	req.m.h.nlmsg_flags = LINUX_NLM_F_REQUEST;

	int ret = rtnl_talk(nl, &req.m.h, got_route, &walk);
	if (ret < 0)
		return ret;
	return walk.found ? 0 : -EIO;
}

struct default_walk {
	int alen;
	struct rt_entry best;
	int found;
};

static int got_default(const struct linux_nlmsghdr* msg, void* context)
{
	struct default_walk* walk = context;
	struct rt_entry e;

	if (parse_route(msg, walk->alen, &e) < 0)
		return 0;
	if (e.dst_len != 0 || e.type != LINUX_RTN_UNICAST || e.table != LINUX_RT_TABLE_MAIN || e.oif <= 0)
		return 0;
	if (!walk->found || e.priority < walk->best.priority) {
		walk->best = e;
		walk->found = 1;
	}
	return 0;
}

// The default route of family: the main table's route to everywhere with the lowest metric.
static int rt_default(int nl, int family, struct rt_entry* e)
{
	struct {
		struct linux_nlmsghdr h;
		struct linux_rtmsg r;
	} req = {
		.h = { .nlmsg_len = sizeof(req), .nlmsg_type = LINUX_RTM_GETROUTE,
			.nlmsg_flags = LINUX_NLM_F_REQUEST | LINUX_NLM_F_DUMP },
		.r = { .rtm_family = family == AF_INET ? LINUX_AF_INET : LINUX_AF_INET6 },
	};
	struct default_walk walk = { .alen = family == AF_INET ? 4 : 16 };

	int ret = rtnl_talk(nl, &req.h, got_default, &walk);
	if (ret < 0)
		return ret;
	if (!walk.found)
		return -ESRCH;
	*e = walk.best;
	return 0;
}

// What XNU's rt_lookup() failing is: no route. Other errors (ENOBUFS, EMFILE...) are the caller's to see.
static int no_route(int err)
{
	switch (-err) {
	case ENETUNREACH:
	case EHOSTUNREACH:
	case ENETDOWN:
	case EACCES: // a prohibit route
	case EINVAL: // a blackhole route
	case ESRCH:
	case ENOENT:
		return -ESRCH;
	default:
		return err;
	}
}

struct route_answer {
	int family;
	int prefix_len;           // of the matched route; the full length for a host route
	int ifindex;
	int type;                 // the destination's RTN_*: unicast, local, broadcast, multicast
	int protocol;             // the matched route's RTPROT_*
	int has_gateway, has_prefsrc;
	unsigned char dst[16];    // the matched route's destination: the prefix
	unsigned char gateway[16], prefsrc[16];
};

static int all_zero(const unsigned char* p, int len)
{
	for (int i = 0; i < len; i++) {
		if (p[i])
			return 0;
	}
	return 1;
}

// How Linux routes to dst (scoped to oif, if not 0), as the routing table entry XNU's rt_lookup() would find: a
// prefix, its interface, gateway and interface address. Returns 0 or a negative BSD errno: ESRCH when there's no
// route.
static int route_lookup(int nl, int family, const unsigned char* dst, int oif, struct route_answer* ans)
{
	int alen = family == AF_INET ? 4 : 16;
	struct rt_entry used, matched;
	int ret;

	memset(ans, 0, sizeof(*ans));
	ans->family = family;

	if (all_zero(dst, alen)) {
		// XNU's lookup of the unspecified address matches the default route; Linux answers it with the loopback (an
		// IPv4 local route) or no route at all
		ret = rt_default(nl, family, &used);
		if (ret < 0)
			return no_route(ret);
		ans->prefix_len = 0;
		ans->protocol = used.protocol;
		ans->type = LINUX_RTN_UNICAST;
		ans->ifindex = used.oif;
		if (used.has_gateway) {
			memcpy(ans->gateway, used.gateway, alen);
			ans->has_gateway = 1;
			// the interface address: the one a packet to the gateway would leave with
			struct rt_entry via;
			if (rt_get(nl, family, used.gateway, used.oif, 0, &via) == 0 && via.has_prefsrc) {
				memcpy(ans->prefsrc, via.prefsrc, alen);
				ans->has_prefsrc = 1;
			}
		}
	} else {
		ret = rt_get(nl, family, dst, oif, 0, &used);
		if (ret < 0)
			return no_route(ret);
		switch (used.type) {
		case LINUX_RTN_BLACKHOLE:
		case LINUX_RTN_UNREACHABLE:
		case LINUX_RTN_PROHIBIT:
		case LINUX_RTN_THROW:
			return -ESRCH;
		}
		ans->type = used.type;
		ans->ifindex = used.oif;
		if (used.has_gateway) {
			memcpy(ans->gateway, used.gateway, alen);
			ans->has_gateway = 1;
		}
		if (used.has_prefsrc) {
			memcpy(ans->prefsrc, used.prefsrc, alen);
			ans->has_prefsrc = 1;
		}

		// the entry that matched is the route XNU reports (Linux describes the route it would use as a host route
		// to dst)
		if (rt_get(nl, family, dst, oif, 1, &matched) == 0 && matched.dst_len <= alen * 8) {
			ans->prefix_len = matched.dst_len;
			ans->protocol = matched.protocol;
			if (matched.has_dst)
				memcpy(ans->dst, matched.dst, alen);
		} else {
			// a kernel without RTM_F_FIB_MATCH (before 4.13): the host route
			ans->prefix_len = alen * 8;
			ans->protocol = LINUX_RTPROT_KERNEL;
			memcpy(ans->dst, dst, alen);
		}
	}

	if (ans->ifindex <= 0 || ans->ifindex > IFINFO_MAX_INDEX)
		return -ESRCH;
	return 0;
}

// ---- RTM_GET: the reply

static int scoped_in6(const struct in6_addr* a)
{
	return IN6_IS_ADDR_LINKLOCAL(a) || IN6_IS_ADDR_MC_LINKLOCAL(a) || IN6_IS_ADDR_MC_NODELOCAL(a);
}

// Appends an address as a BSD sockaddr; returns the bytes used. A scoped IPv6 address carries its interface in its
// second 16 bits, as XNU's routes' do (the KAME embedded scope).
static int put_inet(unsigned char* out, int family, const unsigned char* addr, int ifindex)
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
		if (ifindex && scoped_in6(&sin6->sin6_addr)) {
			sin6->sin6_addr.s6_addr[2] = ifindex >> 8;
			sin6->sin6_addr.s6_addr[3] = ifindex;
		}
		return ROUNDUP32(sizeof(*sin6));
	}
}

// Appends a netmask as XNU's routes keep it (sa_trim()): the sockaddr cut after its last non-zero byte, and a
// zero-length one for the default route's.
static int put_mask(unsigned char* out, int family, int prefix_len)
{
	unsigned char mask[16] = { 0 };
	int skip = family == AF_INET ? offsetof(struct sockaddr_in, sin_addr) : offsetof(struct sockaddr_in6, sin6_addr);
	int bytes = (prefix_len + 7) / 8;
	int len = bytes ? skip + bytes : 0;

	for (int i = 0; i < prefix_len; i++)
		mask[i / 8] |= 0x80 >> (i % 8);
	put_inet(out, family, mask, 0);
	memset(out + len, 0, ROUNDUP32(len) - len);
	((struct sockaddr*) out)->sa_len = len;
	return ROUNDUP32(len);
}

static int route_flags(const struct route_answer* ans)
{
	int flags = RTF_UP | RTF_DONE;

	if (ans->has_gateway)
		flags |= RTF_GATEWAY;
	if (ans->prefix_len == (ans->family == AF_INET ? 32 : 128))
		flags |= RTF_HOST;
	switch (ans->type) {
	case LINUX_RTN_LOCAL:
		flags |= RTF_LOCAL;
		break;
	case LINUX_RTN_BROADCAST:
		flags |= RTF_BROADCAST;
		break;
	case LINUX_RTN_MULTICAST:
		flags |= RTF_MULTICAST;
		break;
	}
	// the kernel's own routes (an interface's prefix, its addresses) are neither
	if (ans->protocol == LINUX_RTPROT_REDIRECT)
		flags |= RTF_DYNAMIC;
	else if (ans->protocol != LINUX_RTPROT_KERNEL && ans->protocol != LINUX_RTPROT_UNSPEC)
		flags |= RTF_STATIC;
	return flags;
}

// The largest reply: the header and DST, GATEWAY, NETMASK, IFP and IFA
#define ROUTE_REPLY_MAX (sizeof(struct rt_msghdr) + 5 * 128)

// Builds the reply to the RTM_GET in req as XNU's route_output() does (bsd/net/rtsock.c): the request's header with
// the route's flags, interface index and metrics, and the route's addresses in RTA_* order. Returns its length or a
// negative BSD errno.
static long answer_get(const struct rt_msghdr* req, const struct sockaddr* dst, int ifscope, unsigned char* out)
{
	struct route_answer ans;
	struct ifinfo link;
	struct rt_msghdr* rtm = (void*) out;
	unsigned char* p = out + sizeof(*rtm);
	unsigned char addr[16];
	int family = dst->sa_family;
	int nl, ret, have_link;

	if (family == AF_INET)
		memcpy(addr, &((const struct sockaddr_in*) dst)->sin_addr, 4);
	else
		memcpy(addr, &((const struct sockaddr_in6*) dst)->sin6_addr, 16);

	nl = rtnl_open();
	if (nl < 0)
		return nl;
	ret = route_lookup(nl, family, addr, ifscope, &ans);
	have_link = ret == 0 && ifinfo_get(nl, ans.ifindex, &link) == 0;
	rtnl_close(nl);
	if (ret < 0)
		return ret;
	if (!have_link)
		return -ESRCH; // the interface went away

	memcpy(rtm, req, sizeof(*rtm));
	rtm->rtm_flags = route_flags(&ans);
	rtm->rtm_index = ans.ifindex;
	// rt_getmetrics(): Linux keeps none of the route's apart; its path MTU is the interface's
	memset(&rtm->rtm_rmx, 0, sizeof(rtm->rtm_rmx));
	rtm->rtm_rmx.rmx_mtu = link.mtu;

	rtm->rtm_addrs = RTA_DST | RTA_GATEWAY;
	p += put_inet(p, family, ans.dst, ans.ifindex);
	if (ans.has_gateway)
		p += put_inet(p, family, ans.gateway, ans.ifindex);
	else // a directly connected route's gateway is its interface (XNU's link-level gateway)
		p += ROUNDUP32(ifinfo_link_sockaddr(&link, (void*) p, 128));

	// a host route has no mask
	if (ans.prefix_len != (family == AF_INET ? 32 : 128)) {
		rtm->rtm_addrs |= RTA_NETMASK;
		p += put_mask(p, family, ans.prefix_len);
	}

	if (req->rtm_addrs & (RTA_IFP | RTA_IFA)) {
		rtm->rtm_addrs |= RTA_IFP;
		p += ROUNDUP32(ifinfo_link_sockaddr(&link, (void*) p, 128));
		if (ans.has_prefsrc || ans.type == LINUX_RTN_LOCAL) {
			rtm->rtm_addrs |= RTA_IFA;
			p += put_inet(p, family, ans.has_prefsrc ? ans.prefsrc : addr, ans.ifindex);
		}
	}

	rtm->rtm_msglen = p - out;
	return rtm->rtm_msglen;
}

// ---- route_output()

// XNU's rt_xaddrs(): the addresses after the header, in RTA_* bit order, each copied into storage (so a short one
// reads as zeroes past its end). Returns 0 or EINVAL; like XNU, it stops at the end of the message, at a zero-length
// address (which reads as all zeroes), and when the last address's padding runs past the end.
static int rt_xaddrs(const unsigned char* p, const unsigned char* end, int addrs,
		struct sockaddr_storage storage[RTAX_MAX], const struct sockaddr* info[RTAX_MAX])
{
	for (int i = 0; i < RTAX_MAX; i++)
		info[i] = NULL;
	for (int i = 0; i < RTAX_MAX && p < end; i++) {
		if (!(addrs & (1 << i)))
			continue;
		unsigned char sa_len = *p;
		if (p + sa_len > end || sa_len > sizeof(struct sockaddr_storage))
			return -EINVAL;
		memset(&storage[i], 0, sizeof(storage[i]));
		info[i] = (const struct sockaddr*) &storage[i];
		if (sa_len == 0)
			return 0; // "should be EINVAL but for compat"
		if (sa_len < offsetof(struct sockaddr, sa_data))
			return -EINVAL;
		memcpy(&storage[i], p, sa_len);
		if (p + ROUNDUP32(sa_len) > end)
			break;
		p += ROUNDUP32(sa_len);
	}
	return 0;
}

// An inet sockaddr long enough to be one (route_output()'s minimums)
static int inet_ok(const struct sockaddr* sa)
{
	if (sa->sa_family == AF_INET)
		return sa->sa_len >= offsetof(struct sockaddr_in, sin_zero);
	if (sa->sa_family == AF_INET6)
		return sa->sa_len >= sizeof(struct sockaddr_in6);
	return 1;
}

static long route_get(const struct rt_msghdr* req, unsigned long len, unsigned char* answer)
{
	struct sockaddr_storage storage[RTAX_MAX];
	const struct sockaddr* info[RTAX_MAX];
	int ifscope = 0;

	if (rt_xaddrs((const unsigned char*) (req + 1), (const unsigned char*) req + len, req->rtm_addrs, storage, info))
		return -EINVAL;
	const struct sockaddr* dst = info[RTAX_DST];
	const struct sockaddr* gateway = info[RTAX_GATEWAY];
	if (dst == NULL || dst->sa_family >= AF_MAX || (gateway != NULL && gateway->sa_family >= AF_MAX))
		return -EINVAL;
	if (!inet_ok(dst) || (gateway != NULL && !inet_ok(gateway)))
		return -EINVAL;

	// a scoped lookup: the interface the request names, or a scoped IPv6 address's
	if (req->rtm_flags & RTF_IFSCOPE) {
		if (dst->sa_family != AF_INET && dst->sa_family != AF_INET6)
			return -EINVAL;
		ifscope = req->rtm_index;
	}
	if (req->rtm_flags & RTF_PROXY)
		return -EINVAL;
	if (dst->sa_family == AF_INET6) {
		struct sockaddr_in6* sin6 = (struct sockaddr_in6*) &storage[RTAX_DST];
		if (scoped_in6(&sin6->sin6_addr) && sin6->sin6_scope_id == 0) {
			// the KAME embedded scope
			sin6->sin6_scope_id = (sin6->sin6_addr.s6_addr[2] << 8) | sin6->sin6_addr.s6_addr[3];
			sin6->sin6_addr.s6_addr[2] = sin6->sin6_addr.s6_addr[3] = 0;
		}
		if (!ifscope && scoped_in6(&sin6->sin6_addr))
			ifscope = sin6->sin6_scope_id;
	}

	// the families with routing tables
	if (dst->sa_family != AF_INET && dst->sa_family != AF_INET6)
		return -EAFNOSUPPORT;
	return answer_get(req, dst, ifscope, answer);
}

// Handles the routing message in msg (len bytes, the process's own copy) as XNU's route_output() does. Returns the
// write's result (len, or a negative BSD errno) and points *reply at the message to queue for the sender (*reply_len
// bytes; 0: none): the answer, built in answer, or the request itself (with rtm_errno set if it got that far).
static long route_message(unsigned char* msg, unsigned long len, int useloopback, unsigned char* answer,
		const void** reply, unsigned long* reply_len)
{
	struct rt_msghdr* req = (void*) msg;
	long err;

	*reply_len = 0;
	if (len < sizeof(intptr_t))
		return -ENOBUFS; // m_pullup() fails: nothing is queued
	if (len < sizeof(*req) || req->rtm_msglen != len) {
		err = -EINVAL; // queued back as it came
		goto queue_request;
	}
	if (req->rtm_version != RTM_VERSION) {
		err = -EPROTONOSUPPORT;
		goto refused;
	}
	if (req->rtm_type == RTM_GET_SILENT) {
		if (!useloopback) {
			err = -EINVAL;
			goto refused;
		}
		req->rtm_type = RTM_GET;
	}
	if (req->rtm_type != RTM_GET) {
		err = -EPERM; // the routes are Linux's: nothing here changes them
		goto refused;
	}
	req->rtm_pid = sys_getpid();

	err = route_get(req, len, answer);
	if (err >= 0) {
		*reply = answer;
		*reply_len = err;
		err = len;
		goto deliver;
	}

refused:
	req->rtm_errno = -err;
queue_request:
	*reply = msg;
	*reply_len = len;
deliver:
	// without SO_USELOOPBACK the sender doesn't get its own messages, and there's no other listener
	if (!useloopback)
		*reply_len = 0;
	return err;
}

// ---- writes

// XNU's route_sendspace: a longer message fails with EMSGSIZE, as sosend() fails it
#define ROUTE_MSG_MAX 8192
#define LINUX_UIO_MAXIOV 1024

// Copies from the process's own memory as the kernel would: a bad address fails with EFAULT instead of faulting here.
static long read_self(struct iovec* local, unsigned long nlocal, const struct iovec* remote, unsigned long nremote)
{
	return LINUX_SYSCALL(__NR_process_vm_readv, LINUX_SYSCALL0(__NR_getpid), local, nlocal, remote, nremote, 0);
}

// Gathers the message that iov (iovcnt entries, validated by the caller) describes into msg; returns its length or a
// negative BSD errno.
static long route_copyin(const struct iovec* iov, int iovcnt, unsigned char* msg)
{
	struct iovec chunk[16];
	unsigned long total = 0;
	long ret;
	int direct = 0; // process_vm_readv() refused (a seccomp filter, say): read the memory as it is

	for (int i = 0; i < iovcnt; i += 16) {
		int n = iovcnt - i < 16 ? iovcnt - i : 16;
		struct iovec local = { chunk, n * sizeof(struct iovec) };
		struct iovec remote = { (void*) (iov + i), n * sizeof(struct iovec) };

		ret = direct ? -LINUX_ENOSYS : read_self(&local, 1, &remote, 1);
		if (ret == -LINUX_ENOSYS || ret == -LINUX_EPERM) {
			direct = 1;
			memcpy(chunk, iov + i, n * sizeof(struct iovec));
		} else if (ret != (long) local.iov_len) {
			return -EFAULT;
		}
		for (int k = 0; k < n; k++) {
			// the total must be a valid ssize_t, as XNU's uio_calculateresid() and Linux's import_iovec() require
			if (chunk[k].iov_len > (unsigned long) __LONG_MAX__ - total)
				return -EINVAL;
			total += chunk[k].iov_len;
		}
	}
	if (total > ROUTE_MSG_MAX)
		return -EMSGSIZE;

	struct iovec all = { msg, total };
	if (!direct) {
		ret = read_self(&all, 1, iov, iovcnt);
		if (ret == -LINUX_ENOSYS || ret == -LINUX_EPERM)
			direct = 1;
		else if (ret != (long) total)
			return -EFAULT;
	}
	if (direct) {
		unsigned long off = 0;
		for (int i = 0; i < iovcnt; i++) {
			memcpy(msg + off, iov[i].iov_base, iov[i].iov_len);
			off += iov[i].iov_len;
		}
	}
	return total;
}

int route_socket_writev(int fd, const struct iovec* iov, int iovcnt, int addressed, int count_errno, long* result)
{
	unsigned char msg[ROUTE_MSG_MAX];
	unsigned char answer[ROUTE_REPLY_MAX];
	struct route_ref ref;
	const void* reply;
	unsigned long reply_len;
	long len;

	if (route_socket_ref(fd, &ref) < 0)
		return 0;
	if (iovcnt <= 0 || iovcnt > LINUX_UIO_MAXIOV) {
		*result = -count_errno;
		return 1;
	}
	// a routing socket is connected (raw_usend())
	if (addressed) {
		*result = -EISCONN;
		return 1;
	}
	len = route_copyin(iov, iovcnt, msg);
	if (len < 0) {
		*result = len;
		return 1;
	}
	*result = route_message(msg, len, ref.useloopback, answer, &reply, &reply_len);
	if (reply_len)
		route_socket_reply(&ref, reply, reply_len);
	return 1;
}

int route_socket_write(int fd, const void* buf, unsigned long len, int addressed, long* result)
{
	struct iovec iov = { (void*) buf, len };
	return route_socket_writev(fd, &iov, 1, addressed, EINVAL, result);
}

// ---- socket options and names

int route_socket_sockopt(int fd, int set, int level, int name, void* value, int* value_len, long* result)
{
	int slot = route_slot(fd);
	unsigned long long mask;

	if (slot < 0)
		return 0;
	// the routing domain has no options of its own (no pr_ctloutput): ROUTE_MSGFILTER is FreeBSD's and OpenBSD's
	if (level != SOL_SOCKET) {
		*result = -ENOPROTOOPT;
		return 1;
	}
	if ((name != SO_TYPE && name != SO_USELOOPBACK) || (set && name == SO_TYPE))
		return 0; // Linux's own (buffer sizes, timeouts, SO_ERROR...), or not settable, as Linux says too

	if (*value_len < (int) sizeof(int)) {
		*result = -EINVAL;
		return 1;
	}
	mask = route_lock();
	struct route_socket* rs = &route_sockets[slot];
	if (rs->fd != fd || !same_socket(fd, rs->cookie)) {
		route_unlock(mask);
		return 0;
	}
	if (name == SO_TYPE)
		*(int*) value = SOCK_RAW;
	else if (set)
		*rs->useloopback = *(const int*) value != 0;
	else
		*(int*) value = *rs->useloopback ? SO_USELOOPBACK : 0;
	route_unlock(mask);
	if (!set)
		*value_len = sizeof(int);
	*result = 0;
	return 1;
}

int route_socket_name(int fd, int peer, void* addr, int* addr_len, long* result)
{
	// raw_usockaddr() has no local address to give; raw_upeeraddr() gives route_src
	static const struct sockaddr route_src = { .sa_len = 2, .sa_family = PF_ROUTE };
	struct route_ref ref;

	if (route_socket_ref(fd, &ref) < 0)
		return 0;
	if (!peer) {
		*result = -EINVAL;
		return 1;
	}
	int len = *addr_len < route_src.sa_len ? *addr_len : route_src.sa_len;
	if (len > 0)
		memcpy(addr, &route_src, len);
	*addr_len = route_src.sa_len;
	*result = 0;
	return 1;
}
