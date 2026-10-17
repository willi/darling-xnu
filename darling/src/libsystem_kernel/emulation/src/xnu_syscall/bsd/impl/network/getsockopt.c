#include <darling/emulation/xnu_syscall/bsd/impl/network/getsockopt.h>

#include <stddef.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/network/getsockopt.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>
#include <darling/emulation/xnu_syscall/bsd/impl/time/gettimeofday.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sostate.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/nosigpipe.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockutil.h>

extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n);

#define LINUX_FIONREAD 0x541B
#define LINUX_EINVAL 22

// XNU's sooptcopyout() of an int option: as much of it as fits
static long int_option(int value, void* optval, int* optlen)
{
	int n = *optlen < (int) sizeof(value) ? *optlen : (int) sizeof(value);

	if (n < 0)
		return -EINVAL;
	memcpy(optval, &value, n);
	*optlen = n;
	return 0;
}

// SO_NREAD (XNU's sogetoptlock()): the bytes a stream socket has to read, or the first datagram's; Linux's FIONREAD
// (SIOCINQ) is the same, but refuses a listening TCP socket, which has none
static long so_nread(int fd, void* optval, int* optlen)
{
	unsigned long long cookie;
	int n = 0;
	long ret = linux_socket_cookie(fd, &cookie);

	if (ret < 0)
		return errno_linux_to_bsd(ret);
	ret = LINUX_SYSCALL(__NR_ioctl, fd, LINUX_FIONREAD, &n);
	if (ret == -LINUX_EINVAL)
		n = 0;
	else if (ret < 0)
		return errno_linux_to_bsd(ret);
	return int_option(n, optval, optlen);
}

long sys_getsockopt(int fd, int level, int optname, void* optval, int* optlen)
{
	int ret, linux_level, linux_optname;
	long route_ret;

	if (ROUTE_SOCKET_ACTIVE() && route_socket_sockopt(fd, 0, level, optname, optval, optlen, &route_ret))
		return route_ret;

	if (level == BSD_SOL_SOCKET && optname == BSD_SO_NREAD)
		return so_nread(fd, optval, optlen);
	if (level == BSD_SOL_SOCKET && optname == BSD_SO_NOSIGNAL) {
		int on;
		ret = socket_nosigpipe_get(fd, &on);
		return ret < 0 ? ret : int_option(on, optval, optlen);
	}

	linux_level = level;
	linux_optname = optname;
	
	ret = sockopt_bsd_to_linux(&linux_level, &linux_optname, NULL, optval);
	
	if (ret != 0 || !linux_optname)
		return ret;

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_GETSOCKOPT,
			((long[6]) { fd, linux_level, linux_optname, optval, optlen, 0 }));
#else
	ret = LINUX_SYSCALL(__NR_getsockopt, fd, linux_level, linux_optname,
			optval, optlen);
#endif

	if (ret < 0)
		ret = errno_linux_to_bsd(ret);
	else
	{
		if (level == BSD_SOL_SOCKET)
		{
			if (optname == BSD_SO_LINGER_TICKS)
			{
				struct xnu_linger* l = (struct xnu_linger*) optval;
				l->l_linger *= LINGER_TICKS_PER_SEC;
			}
			else if (optname == BSD_SO_ERROR)
			{
				int* err = (int*) optval;
				if (err && *err)
					*err = errno_linux_to_bsd(*err);
				// an error EVFILT_SOCK took from Linux, held for this (sostate.h)
				if (err && SOCKET_ERROR_OPT_HOOKED(*err))
					*err = socket_error_take(fd, *err);
			}
			else if (optname == BSD_SO_RCVTIMEO)
			{
				// This only makes a difference on big-endian (PPC)
				struct linux_timeval ltv = *((struct linux_timeval*) optval);
				struct bsd_timeval* btv = (struct bsd_timeval*) optval;
				btv->tv_sec = ltv.tv_sec;
				btv->tv_usec = ltv.tv_usec;
			}
		}
	}

	return ret;
}
