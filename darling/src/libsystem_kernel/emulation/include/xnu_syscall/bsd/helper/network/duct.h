#ifndef NETWORK_DUCT_H
#define NETWORK_DUCT_H

struct sockaddr_fixup
{
	union
	{
		unsigned short linux_family;
		struct
		{
			unsigned char bsd_length;
			unsigned char bsd_family;
		};
	};
	union
	{
		char sun_path[104];
	};
};

unsigned long sockaddr_fixup_size_from_bsd(const void* bsd_sockaddr, int bsd_sockaddr_len);
int sockaddr_fixup_from_bsd(struct sockaddr_fixup* out, const void* bsd_sockaddr, int bsd_sockaddr_len);
int sockaddr_fixup_from_linux(struct sockaddr_fixup* out, const void* linux_sockaddr, int linux_sockaddr_len);

// XNU fails a local datagram with ENOBUFS when the receiving socket is full (see uipc_send()); Linux blocks the
// sender instead, once the receiver has net.unix.max_dgram_qlen datagrams queued. sendto() and sendmsg() send
// local datagrams with these two to do as XNU does.
int local_dgram_send_flags(int fd, int linux_flags, int* local_dgram);
long local_dgram_send_result(int local_dgram, long linux_ret);

#endif // NETWORK_DUCT_H
