#include <darling/emulation/xnu_syscall/bsd/helper/misc/sysctl_net.h>

#include <sys/errno.h>

#include <darling/emulation/xnu_syscall/bsd/helper/network/ifinfo.h>

static sysctl_handler(handle_route);

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

static sysctl_handler(handle_route) {
	if (nlen != 6)
		return -EINVAL;

	// net.route.0.<address family>.<operation>.<interface index>
	switch (name[4]) {
		case _NET_RT_IFLIST:
			return ifinfo_iflist(name[3], name[5], old, oldlen);
		default:
			return -EINVAL;
	}
}
