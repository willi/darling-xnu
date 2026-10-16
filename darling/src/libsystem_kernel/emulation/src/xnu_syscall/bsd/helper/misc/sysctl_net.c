#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_net.h>

#include <sys/errno.h>
#include <net/route.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>

#include <darling/emulation/xnu_syscall/bsd/impl/network/socket.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>
#include <darling/emulation/xnu_syscall/bsd/impl/ioctl/ioctl.h>
#include <darling/emulation/xnu_syscall/bsd/impl/unistd/close.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>

extern void* memset(void* destination, int value, size_t length);
extern void* memcpy(void* destination, const void* source, size_t n);
extern char* strncpy(char* destination, const char* source, size_t length);
extern size_t strlcpy(char* destination, const char* source, size_t size);

static sysctl_handler(handle_route);
static int do_iflist(void* old, unsigned long* oldlen);

#define LINUX_SIOCGIFCONF 0x8912
#define LINUX_SIOCGIFBRDADDR 0x8919
#define LINUX_SIOCGIFNETMASK 0x891b
#define LINUX_SIOCGIFINDEX 0x8933
#define LINUX_IFNAMSIZ 16


struct linux_sockaddr {
	unsigned short sa_family;
	char sa_data[14];
};

struct linux_ifmap {
	unsigned long mem_start;
	unsigned long mem_end;
	unsigned short base_addr;
	unsigned char irq;
	unsigned char dma;
	unsigned char port;
};

struct linux_ifreq {
	char lifr_name[LINUX_IFNAMSIZ];
	union {
		struct linux_sockaddr lifr_addr;
		struct linux_sockaddr lifr_dstaddr;
		struct linux_sockaddr lifr_broadaddr;
		struct linux_sockaddr lifr_netmask;
		struct linux_sockaddr lifr_hwaddr;
		short lifr_flags;
		int lifr_ifindex;
		int lifr_metric;
		int lifr_mtu;
		struct linux_ifmap lifr_map;
		char lifr_slave[LINUX_IFNAMSIZ];
		char lifr_newname[LINUX_IFNAMSIZ];
		char* lifr_data;
	};
};

// arbitrary number; only exists to avoid blowing up the stack
#define IFC_MAX_INTERFACES 5

struct linux_ifconf {
	int lifc_len;
	union {
		char* lifc_buf;
		struct linux_ifreq* lifc_req;
	};
};

enum {
	_NET_ROUTE = 17,
};

enum {
	_NET_RT_IFLIST = 3,
};

const struct known_sysctl sysctls_net[] = {
	// technically a CTLTYPE_NODE in XNU, but for us that means that it has children and isn't a variable in and of itself.
	// the actual value doesn't really matter as long as it's not CTLTYPE_NODE
	{ .oid = _NET_ROUTE, .type = CTLTYPE_OPAQUE, .exttype = "", .name = "route", .handler = handle_route },
	{ .oid = -1 },
};

static unsigned long round_up_sizeof_u32(unsigned long number) {
	return (number + (sizeof(uint32_t) - 1)) & ~(sizeof(uint32_t) - 1);
}

static int do_iflist(void* old, unsigned long* oldlen) {
	// we only do IPv4 addresses for now
	int tmp_sock;
	char buf[IFC_MAX_INTERFACES * sizeof(struct linux_ifreq)];
	struct linux_ifconf lifc = {
		.lifc_len = sizeof(buf),
		.lifc_buf = buf,
	};
	int status = 0;
	char* old_ptr = old;
	unsigned long total_len = 0;

	if ((status = tmp_sock = sys_socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		goto out;

	if ((status = __real_ioctl(tmp_sock, LINUX_SIOCGIFCONF, &lifc)) < 0)
		goto out;

	for (int i = 0; i < lifc.lifc_len; i += sizeof(struct linux_ifreq)) {
		struct linux_ifreq* curr = &lifc.lifc_req[i / sizeof(struct linux_ifreq)];
		struct linux_ifreq idx;
		char dl_buf[128];
		int dl_len;

		// Linux's own interface index, as PF_ROUTE's RTM_GET reports it too
		memcpy(idx.lifr_name, curr->lifr_name, sizeof(curr->lifr_name));
		if ((status = __real_ioctl(tmp_sock, LINUX_SIOCGIFINDEX, &idx)) < 0)
			goto out;
		size_t iface_idx = idx.lifr_ifindex;

		// its name, type and link-layer address
		if ((status = dl_len = route_link_sockaddr(iface_idx, (struct sockaddr_dl*)dl_buf, sizeof(dl_buf))) < 0)
			goto out;

		size_t ifm_length = sizeof(struct if_msghdr) + round_up_sizeof_u32(dl_len);
		size_t ifam_length = sizeof(struct ifa_msghdr) + round_up_sizeof_u32(sizeof(struct sockaddr)) * 3;

		if (old && *oldlen >= total_len + ifm_length) {
			struct if_msghdr* ifm = (void*)old_ptr;

			memset(old_ptr, 0, ifm_length);

			ifm->ifm_msglen = ifm_length;
			ifm->ifm_index = iface_idx;
			ifm->ifm_type = RTM_IFINFO;
			ifm->ifm_version = RTM_VERSION;
			ifm->ifm_addrs = RTA_IFP;

			memcpy(old_ptr + sizeof(struct if_msghdr), dl_buf, dl_len);

			old_ptr += ifm_length;
		}
		total_len += ifm_length;

		if (old && *oldlen >= total_len + ifam_length) {
			struct ifa_msghdr* ifam = (void*)old_ptr;
			struct sockaddr* netmask = (void*)(old_ptr + sizeof(struct ifa_msghdr));
			struct sockaddr* ip_addr = (void*)(old_ptr + sizeof(struct ifa_msghdr) + round_up_sizeof_u32(sizeof(struct sockaddr)));
			struct sockaddr* broad_addr = (void*)(old_ptr + sizeof(struct ifa_msghdr) + round_up_sizeof_u32(sizeof(struct sockaddr)) * 2);
			struct linux_ifreq tmp;

			memset(old_ptr, 0, ifam_length);

			ifam->ifam_msglen = ifam_length;
			ifam->ifam_index = iface_idx;
			ifam->ifam_type = RTM_NEWADDR;
			ifam->ifam_version = RTM_VERSION;
			ifam->ifam_addrs = RTA_NETMASK | RTA_IFA | RTA_BRD;

			sockaddr_fixup_from_linux((struct sockaddr_fixup*)ip_addr, &curr->lifr_addr, sizeof(struct linux_sockaddr));

			memcpy(tmp.lifr_name, curr->lifr_name, sizeof(curr->lifr_name));

			// get the netmask
			if ((status = __real_ioctl(tmp_sock, LINUX_SIOCGIFNETMASK, &tmp)) < 0)
				goto out;
			sockaddr_fixup_from_linux((struct sockaddr_fixup*)netmask, &tmp.lifr_netmask, sizeof(struct linux_sockaddr));

			// get the broadcast address
			if ((status = __real_ioctl(tmp_sock, LINUX_SIOCGIFBRDADDR, &tmp)) < 0)
				goto out;
			sockaddr_fixup_from_linux((struct sockaddr_fixup*)broad_addr, &tmp.lifr_broadaddr, sizeof(struct linux_sockaddr));

			old_ptr += ifam_length;
		}
		total_len += ifam_length;
	}

	// we succeeded if we got here
	status = 0;

out:
	if (tmp_sock >= 0) {
		// ignore errors while closing
		close_internal(tmp_sock);
	}
	*oldlen = total_len;
	return status;
};

static sysctl_handler(handle_route) {
	int status = 0;

	if (nlen != 6) {
		status = -EINVAL;
		goto out;
	}

	// name[4] is the desired operation
	switch (name[4]) {
		case _NET_RT_IFLIST:
			status = do_iflist(old, oldlen);
			break;
		default:
			status = -EINVAL;
			goto out;
	}

out:
	return status;
}
