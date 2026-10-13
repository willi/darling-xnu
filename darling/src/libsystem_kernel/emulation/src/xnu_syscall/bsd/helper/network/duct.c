#include <darling/emulation/xnu_syscall/bsd/helper/network/duct.h>

#include <sys/socket.h>

#include <darling/emulation/conversion/network/duct.h>
#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/conversion/duct_errno.h>
#include <darling/emulation/conversion/network/getsockopt.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/linux_premigration/vchroot_expand.h>
#include <darling/emulation/common/bsdthread/per_thread_wd.h>

unsigned long sockaddr_fixup_size_from_bsd(const void* bsd_sockaddr, int bsd_sockaddr_len) {
	return (((struct sockaddr_fixup*)bsd_sockaddr)->bsd_family == PF_LOCAL) ? sizeof(struct sockaddr_fixup) : bsd_sockaddr_len;
}

int sockaddr_fixup_from_bsd(struct sockaddr_fixup* out, const void* bsd_sockaddr, int bsd_sockaddr_len) {
	int ret = bsd_sockaddr_len;

	memcpy(out, bsd_sockaddr, bsd_sockaddr_len);

	out->linux_family = sfamily_bsd_to_linux(out->bsd_family);

	if (out->linux_family == LINUX_PF_LOCAL) {
		struct vchroot_expand_args vc;
		vc.flags = VCHROOT_FOLLOW;
		vc.dfd = get_perthread_wd();

		strcpy(vc.path, out->sun_path);

		ret = vchroot_expand(&vc);
		if (ret < 0)
			return errno_linux_to_bsd(ret);

		strncpy(out->sun_path, vc.path, sizeof(out->sun_path) - 1);
		out->sun_path[sizeof(out->sun_path) - 1] = '\0';
		ret = sizeof(*out) - sizeof(out->sun_path) + strlen(out->sun_path);
	}

	return ret;
}

int sockaddr_fixup_from_linux(struct sockaddr_fixup* out, const void* linux_sockaddr, int linux_sockaddr_len) {
	int ret = linux_sockaddr_len;

	memcpy(out, linux_sockaddr, linux_sockaddr_len);

	out->bsd_family = sfamily_linux_to_bsd(out->linux_family);

	if (out->bsd_family == PF_LOCAL) {
		struct vchroot_unexpand_args vc;
		strcpy(vc.path, out->sun_path);

		ret = vchroot_unexpand(&vc);
		if (ret < 0)
			return errno_linux_to_bsd(ret);

		strncpy(out->sun_path, vc.path, sizeof(out->sun_path) - 1);
		out->sun_path[sizeof(out->sun_path) - 1] = '\0';
		ret = sizeof(*out) - sizeof(out->sun_path) + strlen(out->sun_path) + 1;
	}

	if (ret >= 0) {
		out->bsd_length = ret;
	}

	return ret;
}

static int linux_socket_option(int fd, int optname, int* value)
{
	unsigned int len = sizeof(*value);

#ifdef __NR_socketcall
	return LINUX_SYSCALL(__NR_socketcall, LINUX_SYS_GETSOCKOPT,
			((long[6]) { fd, LINUX_SOL_SOCKET, optname, value, &len, 0 }));
#else
	return LINUX_SYSCALL(__NR_getsockopt, fd, LINUX_SOL_SOCKET, optname, value, &len);
#endif
}

int local_dgram_send_flags(int fd, int linux_flags, int* local_dgram)
{
	int type, domain;

	*local_dgram = linux_socket_option(fd, LINUX_SO_TYPE, &type) == 0 && type == LINUX_SOCK_DGRAM
		&& linux_socket_option(fd, LINUX_SO_DOMAIN, &domain) == 0 && domain == LINUX_PF_LOCAL;

	return *local_dgram ? (linux_flags | LINUX_MSG_DONTWAIT) : linux_flags;
}

long local_dgram_send_result(int local_dgram, long linux_ret)
{
	return (local_dgram && linux_ret == -LINUX_EAGAIN) ? -LINUX_ENOBUFS : linux_ret;
}
