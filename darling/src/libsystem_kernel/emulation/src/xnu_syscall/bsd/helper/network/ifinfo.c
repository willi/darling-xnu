#include <darling/emulation/xnu_syscall/bsd/helper/network/ifinfo.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>

#include <darling/emulation/xnu_syscall/bsd/helper/network/rtnetlink.h>

extern void* memset(void* destination, int value, __SIZE_TYPE__ length);
extern void* memcpy(void* destination, const void* source, __SIZE_TYPE__ n);
extern __SIZE_TYPE__ strnlen(const char* string, __SIZE_TYPE__ max_length);
extern int memcmp(const void* a, const void* b, __SIZE_TYPE__ n);

// Linux's IFF_* that differ from Darwin's (linux/if.h): the rest of the low ten bits are the same
#define LINUX_IFF_MASTER 0x400
#define LINUX_IFF_SLAVE 0x800
#define LINUX_IFF_MULTICAST 0x1000

#define ROUNDUP32(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

static void link_attr(const struct linux_rtattr* attr, const void* data, int len, void* context)
{
	struct ifinfo* info = context;
	// rtnl_link_stats64 / rtnl_link_stats: rx_packets, tx_packets, rx_bytes, tx_bytes, rx_errors, tx_errors,
	// rx_dropped, tx_dropped, multicast, collisions
	unsigned long long s[10];

	switch (attr->rta_type) {
	case LINUX_IFLA_IFNAME:
		info->name_len = strnlen(data, len < LINUX_IFNAMSIZ ? len : LINUX_IFNAMSIZ);
		memcpy(info->name, data, info->name_len);
		break;
	case LINUX_IFLA_ADDRESS:
		if (len <= (int) sizeof(info->lladdr)) {
			memcpy(info->lladdr, data, len);
			info->lladdr_len = len;
		}
		break;
	case LINUX_IFLA_MTU:
		if (len == 4)
			memcpy(&info->mtu, data, 4);
		break;
	case LINUX_IFLA_STATS64:
		if (len < (int) sizeof(s))
			break;
		memcpy(s, data, sizeof(s));
		goto stats;
	case LINUX_IFLA_STATS:
		if (len < 10 * 4 || info->ipackets || info->opackets) // the 64-bit ones, if they came first
			break;
		for (int i = 0; i < 10; i++)
			s[i] = ((const unsigned int*) data)[i];
	stats:
		info->ipackets = s[0];
		info->opackets = s[1];
		info->ibytes = s[2];
		info->obytes = s[3];
		info->ierrors = s[4];
		info->oerrors = s[5];
		info->iqdrops = s[6];
		info->imcasts = s[8];
		info->collisions = s[9];
		break;
	}
}

static int parse_link(const struct linux_nlmsghdr* msg, struct ifinfo* info)
{
	const struct linux_ifinfomsg* ifi = (const void*) (msg + 1);

	if (msg->nlmsg_type != LINUX_RTM_NEWLINK || msg->nlmsg_len < sizeof(*msg) + sizeof(*ifi))
		return -1;
	memset(info, 0, sizeof(*info));
	info->index = ifi->ifi_index;
	info->arphrd = ifi->ifi_type;
	info->flags = ifi->ifi_flags;
	rtnl_attrs(msg, sizeof(*ifi), link_attr, info);
	return 0;
}

static int got_link(const struct linux_nlmsghdr* msg, void* context)
{
	struct ifinfo* info = context;
	int index = info->index;
	if (parse_link(msg, info) == 0 && info->index == index)
		return 1;
	info->index = index;
	return 0;
}

int ifinfo_get(int nl, int index, struct ifinfo* info)
{
	struct {
		struct linux_nlmsghdr h;
		struct linux_ifinfomsg ifi;
	} req = {
		.h = { .nlmsg_len = sizeof(req), .nlmsg_type = LINUX_RTM_GETLINK, .nlmsg_flags = LINUX_NLM_F_REQUEST },
		.ifi = { .ifi_family = LINUX_AF_UNSPEC, .ifi_index = index },
	};

	if (index <= 0 || index > IFINFO_MAX_INDEX)
		return -ENXIO;
	info->index = index;
	int ret = rtnl_talk(nl, &req.h, got_link, info);
	return ret == 1 ? 0 : ret < 0 ? ret : -ENXIO;
}

static int ift_type(const struct ifinfo* info)
{
	switch (info->arphrd) {
	case LINUX_ARPHRD_ETHER:
		return IFT_ETHER;
	case LINUX_ARPHRD_LOOPBACK:
		return IFT_LOOP;
	default:
		return IFT_OTHER;
	}
}

int ifinfo_link_sockaddr(const struct ifinfo* info, struct sockaddr_dl* sdl, unsigned long size)
{
	// an Ethernet address is the link-layer address Darwin shows; the loopback has none, nor do other links here
	int alen = info->arphrd == LINUX_ARPHRD_ETHER && info->lladdr_len == 6 ? 6 : 0;
	unsigned long len = sizeof(*sdl);

	if (info->name_len + alen > (int) sizeof(sdl->sdl_data))
		len += info->name_len + alen - sizeof(sdl->sdl_data);
	if (len > size)
		return -ENOBUFS;

	memset(sdl, 0, len);
	sdl->sdl_len = len;
	sdl->sdl_family = AF_LINK;
	sdl->sdl_index = info->index;
	sdl->sdl_type = ift_type(info);
	sdl->sdl_nlen = info->name_len;
	sdl->sdl_alen = alen;
	memcpy(sdl->sdl_data, info->name, info->name_len);
	memcpy(sdl->sdl_data + info->name_len, info->lladdr, alen);
	return len;
}

static int bsd_flags(const struct ifinfo* info)
{
	int flags = info->flags & 0x3ff & ~LINUX_IFF_MASTER;
	if (info->flags & LINUX_IFF_MULTICAST)
		flags |= IFF_MULTICAST;
	// an Ethernet interface can't hear its own transmissions, as Darwin's say
	if (info->arphrd == LINUX_ARPHRD_ETHER)
		flags |= IFF_SIMPLEX;
	return flags;
}

// ---- NET_RT_IFLIST

struct iflist_out {
	char* old;
	unsigned long size;  // of old
	unsigned long used;  // copied into old
	unsigned long total; // all the messages
	int truncated;
};

static void put(struct iflist_out* out, const void* msg, unsigned long len)
{
	out->total += len;
	if (!out->old || out->truncated)
		return;
	if (out->used + len > out->size) {
		out->truncated = 1;
		return;
	}
	memcpy(out->old + out->used, msg, len);
	out->used += len;
}

static void put_link(struct iflist_out* out, const struct ifinfo* info)
{
	union {
		struct if_msghdr ifm;
		unsigned char bytes[sizeof(struct if_msghdr) + 128];
	} msg;
	struct if_msghdr* ifm = &msg.ifm;

	memset(&msg, 0, sizeof(msg));
	int dl_len = ifinfo_link_sockaddr(info, (void*) (ifm + 1), 128);
	if (dl_len < 0)
		return;
	ifm->ifm_msglen = sizeof(*ifm) + ROUNDUP32(dl_len);
	ifm->ifm_version = RTM_VERSION;
	ifm->ifm_type = RTM_IFINFO;
	ifm->ifm_addrs = RTA_IFP;
	ifm->ifm_flags = bsd_flags(info);
	ifm->ifm_index = info->index;
	ifm->ifm_data.ifi_type = ift_type(info);
	ifm->ifm_data.ifi_addrlen = ((struct sockaddr_dl*) (ifm + 1))->sdl_alen;
	ifm->ifm_data.ifi_hdrlen = info->arphrd == LINUX_ARPHRD_ETHER ? 14 : 0;
	ifm->ifm_data.ifi_mtu = info->mtu;
	ifm->ifm_data.ifi_ipackets = info->ipackets;
	ifm->ifm_data.ifi_opackets = info->opackets;
	ifm->ifm_data.ifi_ibytes = info->ibytes;
	ifm->ifm_data.ifi_obytes = info->obytes;
	ifm->ifm_data.ifi_ierrors = info->ierrors;
	ifm->ifm_data.ifi_oerrors = info->oerrors;
	ifm->ifm_data.ifi_iqdrops = info->iqdrops;
	ifm->ifm_data.ifi_imcasts = info->imcasts;
	ifm->ifm_data.ifi_collisions = info->collisions;
	put(out, &msg, ifm->ifm_msglen);
}

struct addr {
	int have_address, have_local, have_broadcast;
	unsigned char address[16], local[16], broadcast[16];
};

static void addr_attr(const struct linux_rtattr* attr, const void* data, int len, void* context)
{
	struct addr* a = context;
	if (len != 4 && len != 16)
		return;
	switch (attr->rta_type) {
	case LINUX_IFA_ADDRESS:
		memcpy(a->address, data, len);
		a->have_address = 1;
		break;
	case LINUX_IFA_LOCAL:
		memcpy(a->local, data, len);
		a->have_local = 1;
		break;
	case LINUX_IFA_BROADCAST:
		memcpy(a->broadcast, data, len);
		a->have_broadcast = 1;
		break;
	}
}

// An address (or mask) of family af as a sockaddr; returns the bytes used. A link-local IPv6 address carries its
// interface in its second 16 bits, as XNU's do (the KAME embedded scope).
static int put_sockaddr(unsigned char* p, int af, const unsigned char* addr, int index)
{
	if (af == AF_INET) {
		struct sockaddr_in* sin = (void*) p;
		memset(sin, 0, sizeof(*sin));
		sin->sin_len = sizeof(*sin);
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, addr, 4);
		return ROUNDUP32(sizeof(*sin));
	}
	struct sockaddr_in6* sin6 = (void*) p;
	memset(sin6, 0, sizeof(*sin6));
	sin6->sin6_len = sizeof(*sin6);
	sin6->sin6_family = AF_INET6;
	memcpy(&sin6->sin6_addr, addr, 16);
	if (index && IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
		sin6->sin6_addr.s6_addr[2] = index >> 8;
		sin6->sin6_addr.s6_addr[3] = index;
	}
	return ROUNDUP32(sizeof(*sin6));
}

struct addr_walk {
	struct iflist_out* out;
	const struct ifinfo* link;
	int af;
};

static int got_addr(const struct linux_nlmsghdr* msg, void* context)
{
	struct addr_walk* walk = context;
	const struct linux_ifaddrmsg* ifa = (const void*) (msg + 1);
	struct addr a = { 0 };
	unsigned char mask[16] = { 0 };
	union {
		struct ifa_msghdr ifam;
		unsigned char bytes[sizeof(struct ifa_msghdr) + 3 * 28];
	} out;
	unsigned char* p = (unsigned char*) (&out.ifam + 1);
	int af, alen;

	if (msg->nlmsg_type != LINUX_RTM_NEWADDR || msg->nlmsg_len < sizeof(*msg) + sizeof(*ifa)
			|| (int) ifa->ifa_index != walk->link->index)
		return 0;
	if (ifa->ifa_family == LINUX_AF_INET) {
		af = AF_INET;
		alen = 4;
	} else if (ifa->ifa_family == LINUX_AF_INET6) {
		af = AF_INET6;
		alen = 16;
	} else {
		return 0;
	}
	if ((walk->af && walk->af != af) || ifa->ifa_prefixlen > alen * 8)
		return 0;
	rtnl_attrs(msg, sizeof(*ifa), addr_attr, &a);
	// IFA_LOCAL is the interface's own address when IFA_ADDRESS is a point-to-point link's other end
	const unsigned char* own = a.have_local ? a.local : a.address;
	if (!a.have_local && !a.have_address)
		return 0;

	memset(&out, 0, sizeof(out));
	for (int i = 0; i < ifa->ifa_prefixlen; i++)
		mask[i / 8] |= 0x80 >> (i % 8);
	out.ifam.ifam_addrs = RTA_NETMASK | RTA_IFA;
	p += put_sockaddr(p, af, mask, 0);
	p += put_sockaddr(p, af, own, walk->link->index);
	if (a.have_local && a.have_address && memcmp(a.local, a.address, alen) != 0) {
		out.ifam.ifam_addrs |= RTA_BRD; // the destination of a point-to-point link
		p += put_sockaddr(p, af, a.address, walk->link->index);
	} else if (a.have_broadcast) {
		out.ifam.ifam_addrs |= RTA_BRD;
		p += put_sockaddr(p, af, a.broadcast, 0);
	}
	out.ifam.ifam_msglen = p - out.bytes;
	out.ifam.ifam_version = RTM_VERSION;
	out.ifam.ifam_type = RTM_NEWADDR;
	out.ifam.ifam_index = walk->link->index;
	put(walk->out, &out, out.ifam.ifam_msglen);
	return 0;
}

#define IFLIST_MAX_LINKS 256

struct link_walk {
	int indexes[IFLIST_MAX_LINKS];
	int count;
};

static int got_link_index(const struct linux_nlmsghdr* msg, void* context)
{
	struct link_walk* walk = context;
	const struct linux_ifinfomsg* ifi = (const void*) (msg + 1);

	if (msg->nlmsg_type == LINUX_RTM_NEWLINK && msg->nlmsg_len >= sizeof(*msg) + sizeof(*ifi)
			&& ifi->ifi_index > 0 && ifi->ifi_index <= IFINFO_MAX_INDEX && walk->count < IFLIST_MAX_LINKS)
		walk->indexes[walk->count++] = ifi->ifi_index;
	return 0;
}


int ifinfo_iflist(int af, int index, void* old, unsigned long* oldlen)
{
	struct iflist_out out = { .old = old, .size = old ? *oldlen : 0 };
	struct link_walk links = { .count = 0 };
	struct {
		struct linux_nlmsghdr h;
		struct linux_ifinfomsg ifi;
	} link_req = {
		.h = { .nlmsg_len = sizeof(link_req), .nlmsg_type = LINUX_RTM_GETLINK,
			.nlmsg_flags = LINUX_NLM_F_REQUEST | LINUX_NLM_F_DUMP },
		.ifi = { .ifi_family = LINUX_AF_UNSPEC },
	};
	int nl, ret;

	if (af != 0 && af != AF_INET && af != AF_INET6)
		af = -1; // no addresses of any other family
	nl = rtnl_open();
	if (nl < 0)
		return nl;
	ret = rtnl_talk(nl, &link_req.h, got_link_index, &links);

	for (int i = 0; ret >= 0 && i < links.count; i++) {
		struct ifinfo link;
		if (index && links.indexes[i] != index)
			continue;
		if (ifinfo_get(nl, links.indexes[i], &link) < 0)
			continue; // gone since the dump
		put_link(&out, &link);
		if (af < 0)
			continue;

		struct {
			struct linux_nlmsghdr h;
			struct linux_ifaddrmsg ifa;
		} addr_req = {
			.h = { .nlmsg_len = sizeof(addr_req), .nlmsg_type = LINUX_RTM_GETADDR,
				.nlmsg_flags = LINUX_NLM_F_REQUEST | LINUX_NLM_F_DUMP },
			.ifa = { .ifa_family = af == AF_INET ? LINUX_AF_INET : af == AF_INET6 ? LINUX_AF_INET6 : LINUX_AF_UNSPEC },
		};
		struct addr_walk walk = { .out = &out, .link = &link, .af = af };
		ret = rtnl_talk(nl, &addr_req.h, got_addr, &walk);
	}
	rtnl_close(nl);
	if (ret < 0)
		return ret;

	*oldlen = old ? out.used : out.total;
	return out.truncated ? -ENOMEM : 0;
}
