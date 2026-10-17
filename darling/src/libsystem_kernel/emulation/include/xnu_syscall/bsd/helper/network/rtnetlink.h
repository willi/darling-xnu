#ifndef NETWORK_RTNETLINK_H
#define NETWORK_RTNETLINK_H

// Asking Linux about its interfaces, addresses and routes over NETLINK_ROUTE (linux/netlink.h, linux/rtnetlink.h,
// linux/if_link.h, linux/if_addr.h), for the BSD views of them: PF_ROUTE's RTM_GET (route.c) and NET_RT_IFLIST
// (ifinfo.c).

#define LINUX_AF_UNSPEC 0
#define LINUX_AF_INET 2
#define LINUX_AF_INET6 10
#define LINUX_AF_NETLINK 16

#define LINUX_NLMSG_ERROR 2
#define LINUX_NLMSG_DONE 3
#define LINUX_NLM_F_REQUEST 0x1
#define LINUX_NLM_F_MULTI 0x2
#define LINUX_NLM_F_DUMP 0x300

#define LINUX_RTM_NEWLINK 16
#define LINUX_RTM_GETLINK 18
#define LINUX_RTM_NEWADDR 20
#define LINUX_RTM_GETADDR 22
#define LINUX_RTM_NEWROUTE 24
#define LINUX_RTM_GETROUTE 26

#define LINUX_RTM_F_FIB_MATCH 0x2000

#define LINUX_RTA_DST 1
#define LINUX_RTA_OIF 4
#define LINUX_RTA_GATEWAY 5
#define LINUX_RTA_PRIORITY 6
#define LINUX_RTA_PREFSRC 7
#define LINUX_RTA_MULTIPATH 9
#define LINUX_RTA_TABLE 15

#define LINUX_RTN_UNICAST 1
#define LINUX_RTN_LOCAL 2
#define LINUX_RTN_BROADCAST 3
#define LINUX_RTN_MULTICAST 5
#define LINUX_RTN_BLACKHOLE 6
#define LINUX_RTN_UNREACHABLE 7
#define LINUX_RTN_PROHIBIT 8
#define LINUX_RTN_THROW 9

#define LINUX_RTPROT_UNSPEC 0
#define LINUX_RTPROT_REDIRECT 1
#define LINUX_RTPROT_KERNEL 2

#define LINUX_RT_TABLE_MAIN 254

#define LINUX_IFLA_ADDRESS 1
#define LINUX_IFLA_IFNAME 3
#define LINUX_IFLA_MTU 4
#define LINUX_IFLA_STATS 7
#define LINUX_IFLA_STATS64 23

#define LINUX_IFA_ADDRESS 1
#define LINUX_IFA_LOCAL 2
#define LINUX_IFA_BROADCAST 4

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

struct linux_ifinfomsg {
	unsigned char ifi_family;
	unsigned char ifi_pad;
	unsigned short ifi_type;
	int ifi_index;
	unsigned int ifi_flags;
	unsigned int ifi_change;
};

struct linux_ifaddrmsg {
	unsigned char ifa_family;
	unsigned char ifa_prefixlen;
	unsigned char ifa_flags;
	unsigned char ifa_scope;
	unsigned int ifa_index;
};

struct linux_rtattr {
	unsigned short rta_len;
	unsigned short rta_type;
};

struct linux_rtnexthop {
	unsigned short rtnh_len;
	unsigned char rtnh_flags;
	unsigned char rtnh_hops;
	int rtnh_ifindex;
};

#define RTNL_ALIGN(len) (((len) + 3) & ~3)

// A NETLINK_ROUTE socket (close-on-exec), or a negative BSD errno.
int rtnl_open(void);
void rtnl_close(int nl);

// Called for each message of a reply: returns 0 to go on, anything else to stop with it as the result.
typedef int (*rtnl_reply_f)(const struct linux_nlmsghdr* msg, void* context);

// Sends the request req (its nlmsg_len bytes; its sequence number is set here) and passes each message of the reply
// (all of a dump's) to each. Returns 0, what each stopped with, or a negative BSD errno: the request's NLMSG_ERROR
// as a Linux errno converted, or the transport's.
int rtnl_talk(int nl, struct linux_nlmsghdr* req, rtnl_reply_f each, void* context);

// The attributes of a message whose fixed part (rtmsg, ifinfomsg, ...) is fixed_len bytes: calls each_attr for each.
typedef void (*rtnl_attr_f)(const struct linux_rtattr* attr, const void* data, int len, void* context);
void rtnl_attrs(const struct linux_nlmsghdr* msg, unsigned long fixed_len, rtnl_attr_f each_attr, void* context);

#endif // NETWORK_RTNETLINK_H
