#include <darling/emulation/xnu_syscall/bsd/impl/network/sendto.h>

#include <sys/errno.h>
#include <stddef.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/network/duct.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>
#include <darling/emulation/xnu_syscall/bsd/helper/bsdthread/cancelable.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/route.h>

extern void *memcpy(void *dest, const void *src, __SIZE_TYPE__ n);

long sys_sendto(int fd, const void* buffer, unsigned long length,
		int flags, const void* sockaddr, int socklen)
{
	CANCELATION_POINT();
	return sys_sendto_nocancel(fd, buffer, length, flags, sockaddr, socklen);
}

long sys_sendto_nocancel(int fd, const void* buffer, unsigned long length,
		int flags, const void* sockaddr, int socklen)
{
	int ret, linux_flags, local_dgram;

	struct sockaddr_fixup* fixed = NULL;
	long route_ret;

	if (ROUTE_SOCKET_ACTIVE() && route_socket_write(fd, buffer, length, sockaddr != NULL, &route_ret))
		return route_ret;

	if (socklen > 512)
		return -EINVAL;

	if (sockaddr != NULL) {
		fixed = __builtin_alloca(sockaddr_fixup_size_from_bsd(sockaddr, socklen));
		ret = socklen = sockaddr_fixup_from_bsd(fixed, sockaddr, socklen);
		if (ret < 0)
			return ret;
	}

	linux_flags = local_dgram_send_flags(fd, msgflags_bsd_to_linux(flags), &local_dgram);

#ifdef __NR_socketcall
	ret = LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_SENDTO,
			((long[6]) { fd, buffer, length, linux_flags, fixed, socklen }));
#else
	ret = LINUX_SYSCALL(__NR_sendto, fd, buffer, length,
			linux_flags, fixed, socklen);
#endif

	ret = local_dgram_send_result(local_dgram, ret);
	if (ret < 0)
		ret = errno_linux_to_bsd(ret);

	return ret;
}
