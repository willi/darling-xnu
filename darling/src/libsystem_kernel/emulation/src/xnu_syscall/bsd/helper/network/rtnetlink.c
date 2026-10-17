#include <darling/emulation/xnu_syscall/bsd/helper/network/rtnetlink.h>

#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/network/socket.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/recvfrom.h>
#include <darling/emulation/xnu_syscall/bsd/impl/network/sendto.h>

#define LINUX_SOCK_RAW 3
#define LINUX_SOCK_CLOEXEC 02000000
#define LINUX_NETLINK_ROUTE 0
#define LINUX_MSG_TRUNC 0x20

struct linux_sockaddr_nl {
	unsigned short nl_family;
	unsigned short nl_pad;
	unsigned int nl_pid;
	unsigned int nl_groups;
};

int rtnl_open(void)
{
	long nl;
#ifdef __NR_socketcall
	nl = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SOCKET,
			((long[6]) { LINUX_AF_NETLINK, LINUX_SOCK_RAW | LINUX_SOCK_CLOEXEC, LINUX_NETLINK_ROUTE }));
#else
	nl = LINUX_SYSCALL(__NR_socket, LINUX_AF_NETLINK, LINUX_SOCK_RAW | LINUX_SOCK_CLOEXEC, LINUX_NETLINK_ROUTE);
#endif
	return nl < 0 ? errno_linux_to_bsd(nl) : nl;
}

void rtnl_close(int nl)
{
	LINUX_SYSCALL1(__NR_close, nl);
}

static long rtnl_send(int nl, const void* buf, unsigned long len)
{
	struct linux_sockaddr_nl kernel = { .nl_family = LINUX_AF_NETLINK };
#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SENDTO, ((long[6]) { nl, buf, len, 0, &kernel, sizeof(kernel) }));
#else
	return LINUX_SYSCALL(__NR_sendto, nl, buf, len, 0, &kernel, sizeof(kernel));
#endif
}

static long rtnl_recv(int nl, void* buf, unsigned long len)
{
	long ret;
	do {
#ifdef __NR_socketcall
		ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_RECVFROM, ((long[6]) { nl, buf, len, 0, 0, 0 }));
#else
		ret = LINUX_SYSCALL(__NR_recvfrom, nl, buf, len, 0, 0, 0);
#endif
	} while (ret == -LINUX_EINTR); // a signal doesn't fail the caller's write() or sysctl()
	return ret;
}

int rtnl_talk(int nl, struct linux_nlmsghdr* req, rtnl_reply_f each, void* context)
{
	// a dump comes in datagrams of at most the largest read the socket has seen, and at least NLMSG_GOODSIZE (a page)
	union {
		struct linux_nlmsghdr h;
		unsigned char bytes[8192];
	} buf;
	static unsigned int seq; // only tells this request's replies from a stale one's
	long ret;

	req->nlmsg_seq = __atomic_add_fetch(&seq, 1, __ATOMIC_RELAXED);
	ret = rtnl_send(nl, req, req->nlmsg_len);
	if (ret < 0)
		return errno_linux_to_bsd(ret);

	for (;;) {
		ret = rtnl_recv(nl, &buf, sizeof(buf));
		if (ret < 0)
			return errno_linux_to_bsd(ret);

		unsigned long off = 0;
		while (off + sizeof(struct linux_nlmsghdr) <= (unsigned long) ret) {
			const struct linux_nlmsghdr* msg = (const void*) (buf.bytes + off);
			if (msg->nlmsg_len < sizeof(*msg) || off + msg->nlmsg_len > (unsigned long) ret)
				return -EIO;
			off += RTNL_ALIGN(msg->nlmsg_len);
			if (msg->nlmsg_seq != req->nlmsg_seq)
				continue;
			if (msg->nlmsg_type == LINUX_NLMSG_DONE)
				return 0;
			if (msg->nlmsg_type == LINUX_NLMSG_ERROR) {
				const int* error = (const void*) (msg + 1);
				if (msg->nlmsg_len < sizeof(*msg) + sizeof(*error))
					return -EIO;
				// 0 acknowledges a request that has no other reply
				return *error ? errno_linux_to_bsd(*error) : 0;
			}
			int stop = each(msg, context);
			if (stop)
				return stop;
			if (!(msg->nlmsg_flags & LINUX_NLM_F_MULTI))
				return 0;
		}
	}
}

void rtnl_attrs(const struct linux_nlmsghdr* msg, unsigned long fixed_len, rtnl_attr_f each_attr, void* context)
{
	unsigned long off = sizeof(*msg) + RTNL_ALIGN(fixed_len);

	while (off + sizeof(struct linux_rtattr) <= msg->nlmsg_len) {
		const struct linux_rtattr* attr = (const void*) ((const unsigned char*) msg + off);
		if (attr->rta_len < sizeof(*attr) || off + attr->rta_len > msg->nlmsg_len)
			break;
		each_attr(attr, attr + 1, attr->rta_len - (int) sizeof(*attr), context);
		off += RTNL_ALIGN(attr->rta_len);
	}
}
