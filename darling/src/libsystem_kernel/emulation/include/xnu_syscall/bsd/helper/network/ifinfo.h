#ifndef NETWORK_IFINFO_H
#define NETWORK_IFINFO_H

// Linux's interfaces as Darwin describes them: one numbering (Linux's own interface index, which PF_ROUTE's RTM_GET,
// NET_RT_IFLIST and so getifaddrs(), if_nametoindex() and if_indextoname() all report) and one enumeration (every link
// rtnetlink lists, with all its IPv4 and IPv6 addresses).
//
// Darwin's indexes are 16 bits (ifm_index, sdl_index, rtm_index): an interface whose Linux index is larger can't be
// named, so it isn't listed, and RTM_GET finds no route through it.

#define IFINFO_MAX_INDEX 0xffff

struct ifinfo {
	int index;
	unsigned short arphrd;    // Linux's link type (ARPHRD_*)
	unsigned int flags;       // Linux's IFF_*
	unsigned int mtu;
	char name[16];
	int name_len;
	unsigned char lladdr[32];
	int lladdr_len;
	unsigned long long ipackets, opackets, ibytes, obytes, ierrors, oerrors, iqdrops, imcasts, collisions;
};

// The interface Linux numbers index, over the rtnetlink socket nl. Returns 0 or a negative BSD errno.
int ifinfo_get(int nl, int index, struct ifinfo* info);

// Its sockaddr_dl, as RTA_IFP and NET_RT_IFLIST carry it: name, type and link-layer address. Returns its length, or
// -ENOBUFS if size is too small.
struct sockaddr_dl;
int ifinfo_link_sockaddr(const struct ifinfo* info, struct sockaddr_dl* sdl, unsigned long size);

// NET_RT_IFLIST (XNU's sysctl_iflist()): for each interface (only index's, if not 0), an RTM_IFINFO message, then an
// RTM_NEWADDR for each of its addresses (only family af's, if not 0). With old NULL, *oldlen is set to the size
// needed; otherwise the messages that fit go into old and *oldlen is set to their size (-ENOMEM if not all fit).
int ifinfo_iflist(int af, int index, void* old, unsigned long* oldlen);

#endif // NETWORK_IFINFO_H
