#include <darling/emulation/xnu_syscall/bsd/helper/network/tcpinfo.h>

#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>

#include <darling/emulation/common/base.h>
#include <darling/emulation/conversion/errno.h>
#include <darling/emulation/linux_premigration/linux-syscalls/linux.h>
#include <darling/emulation/xnu_syscall/bsd/helper/network/sockutil.h>

extern void* memcpy(void* dest, const void* src, __SIZE_TYPE__ n);
extern void* memset(void* dest, int c, __SIZE_TYPE__ n);

#define LINUX_SOL_TCP 6
#define LINUX_TCP_INFO 11
#define LINUX_SIOCOUTQ 0x5411

// Linux's struct tcp_info (include/uapi/linux/tcp.h), as far as this takes it; a kernel older than a field leaves it 0
// (sockutil.h's linux_tcp_info is its start)
struct linux_tcp_info_full {
	uint8_t tcpi_state;
	uint8_t tcpi_ca_state;
	uint8_t tcpi_retransmits;
	uint8_t tcpi_probes;
	uint8_t tcpi_backoff;
	uint8_t tcpi_options;
	uint8_t tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;
	uint8_t tcpi_delivery_rate_app_limited : 1, tcpi_fastopen_client_fail : 2;

	uint32_t tcpi_rto;
	uint32_t tcpi_ato;
	uint32_t tcpi_snd_mss;
	uint32_t tcpi_rcv_mss;

	uint32_t tcpi_unacked;
	uint32_t tcpi_sacked;
	uint32_t tcpi_lost;
	uint32_t tcpi_retrans;
	uint32_t tcpi_fackets;

	uint32_t tcpi_last_data_sent;
	uint32_t tcpi_last_ack_sent;
	uint32_t tcpi_last_data_recv;
	uint32_t tcpi_last_ack_recv;

	uint32_t tcpi_pmtu;
	uint32_t tcpi_rcv_ssthresh;
	uint32_t tcpi_rtt;
	uint32_t tcpi_rttvar;
	uint32_t tcpi_snd_ssthresh;
	uint32_t tcpi_snd_cwnd;
	uint32_t tcpi_advmss;
	uint32_t tcpi_reordering;

	uint32_t tcpi_rcv_rtt;
	uint32_t tcpi_rcv_space;

	uint32_t tcpi_total_retrans;

	uint64_t tcpi_pacing_rate;
	uint64_t tcpi_max_pacing_rate;
	uint64_t tcpi_bytes_acked;
	uint64_t tcpi_bytes_received;
	uint32_t tcpi_segs_out;
	uint32_t tcpi_segs_in;

	uint32_t tcpi_notsent_bytes;
	uint32_t tcpi_min_rtt;
	uint32_t tcpi_data_segs_in;
	uint32_t tcpi_data_segs_out;

	uint64_t tcpi_delivery_rate;

	uint64_t tcpi_busy_time;
	uint64_t tcpi_rwnd_limited;
	uint64_t tcpi_sndbuf_limited;

	uint32_t tcpi_delivered;
	uint32_t tcpi_delivered_ce;

	uint64_t tcpi_bytes_sent;
	uint64_t tcpi_bytes_retrans;
	uint32_t tcpi_dsack_dups;
	uint32_t tcpi_reord_seen;

	uint32_t tcpi_rcv_ooopack;

	uint32_t tcpi_snd_wnd;
	uint32_t tcpi_rcv_wnd;	// Linux 6.2 on
};

// Linux's TCPI_OPT_* bits for these are XNU's
#define LINUX_TCPI_OPT_MASK (TCPI_OPT_TIMESTAMPS | TCPI_OPT_SACK | TCPI_OPT_WSCALE | TCPI_OPT_ECN)
#define LINUX_TCP_CA_RECOVERY 3
#define LINUX_TCP_INFINITE_SSTHRESH 0x7fffffff
// XNU's ssthresh before there's one: TCP_MAXWIN << TCP_MAX_WINSHIFT (tcp_newtcpcb())
#define XNU_INITIAL_SSTHRESH (65535 << 14)

// Linux's TCP states as XNU's
static uint8_t tcp_state(uint8_t linux_state)
{
	switch (linux_state)
	{
		case LINUX_TCP_ESTABLISHED: return TCPS_ESTABLISHED;
		case LINUX_TCP_SYN_SENT: return TCPS_SYN_SENT;
		case LINUX_TCP_SYN_RECV: return TCPS_SYN_RECEIVED;
		case LINUX_TCP_FIN_WAIT1: return TCPS_FIN_WAIT_1;
		case LINUX_TCP_FIN_WAIT2: return TCPS_FIN_WAIT_2;
		case LINUX_TCP_TIME_WAIT: return TCPS_TIME_WAIT;
		case LINUX_TCP_CLOSE_WAIT: return TCPS_CLOSE_WAIT;
		case LINUX_TCP_LAST_ACK: return TCPS_LAST_ACK;
		case LINUX_TCP_LISTEN: return TCPS_LISTEN;
		case LINUX_TCP_CLOSING: return TCPS_CLOSING;
		default: return TCPS_CLOSED;
	}
}

// what Linux knows of the connection (`got`: how much of it this kernel has), and the bytes in its send buffer
static long read_linux_tcp_info(int fd, struct linux_tcp_info_full* info, unsigned int* got, uint32_t* sbbytes)
{
	unsigned int len = sizeof(*info);
	int outq = 0;
	long ret;

	memset(info, 0, sizeof(*info));
	ret = linux_getsockopt(fd, LINUX_SOL_TCP, LINUX_TCP_INFO, info, &len);
	// Linux answers a socket that isn't TCP with EOPNOTSUPP (95), which comes out as EOPNOTSUPP (102), as XNU's
	// uipc_ctloutput() answers a local socket (bsd/kern/uipc_usrreq.c:803). XNU answers a UDP or raw IP socket
	// EINVAL (ip_ctloutput(), bsd/netinet/ip_output.c:2252; rip_ctloutput(), raw_ip.c:742), which this doesn't tell
	// apart.
	if (ret < 0)
		return errno_linux_to_bsd(ret);
	*got = len;

	// unsent and unacknowledged bytes, as XNU's so_snd.sb_cc; a listening socket has none
	if (LINUX_SYSCALL(__NR_ioctl, fd, LINUX_SIOCOUTQ, &outq) < 0)
		outq = 0;
	*sbbytes = outq;
	return 0;
}

static uint32_t bytes_of_segments(uint32_t segments, uint32_t mss)
{
	uint64_t bytes = (uint64_t) segments * mss;
	return bytes > UINT32_MAX ? UINT32_MAX : (uint32_t) bytes;
}

// XNU's tcp_fill_info(), from Linux's: times in ms (Linux's are µs), windows and thresholds in bytes (Linux's are in
// segments). Linux has no counterpart for the sequence numbers, the interface and its kind, the flow hash, the
// connectivity probes or the TFO and ECN details, so they are 0.
static void fill_info(const struct linux_tcp_info_full* l, unsigned int got, uint32_t sbbytes, struct xnu_tcp_info* ti)
{
	uint32_t mss = l->tcpi_snd_mss;

	memset(ti, 0, sizeof(*ti));

	ti->tcpi_state = tcp_state(l->tcpi_state);
	ti->tcpi_options = l->tcpi_options & LINUX_TCPI_OPT_MASK;
	if (ti->tcpi_options & TCPI_OPT_WSCALE)
	{
		ti->tcpi_snd_wscale = l->tcpi_snd_wscale;
		ti->tcpi_rcv_wscale = l->tcpi_rcv_wscale;
	}

	/* Are we in retranmission episode */
	if (l->tcpi_ca_state >= LINUX_TCP_CA_RECOVERY || l->tcpi_retransmits > 0)
		ti->tcpi_flags |= TCPI_FLAG_LOSSRECOVERY;

	// XNU's is 0 without its retransmit timer, which runs while there's data in flight
	ti->tcpi_rto = l->tcpi_unacked ? l->tcpi_rto / 1000 : 0;
	ti->tcpi_snd_mss = mss;
	ti->tcpi_rcv_mss = mss;

	// (Linux keeps no latest sample, only the smoothed RTT)
	ti->tcpi_rttcur = l->tcpi_rtt / 1000;
	ti->tcpi_srtt = l->tcpi_rtt / 1000;
	ti->tcpi_rcv_srtt = l->tcpi_rcv_rtt / 1000;
	ti->tcpi_rttvar = l->tcpi_rttvar / 1000;
	// (Linux's minimum is ~0U until there's a sample; XNU's best starts at 0)
	ti->tcpi_rttbest = (l->tcpi_min_rtt == UINT32_MAX) ? 0 : l->tcpi_min_rtt / 1000;

	ti->tcpi_snd_ssthresh = (l->tcpi_snd_ssthresh >= LINUX_TCP_INFINITE_SSTHRESH) ? XNU_INITIAL_SSTHRESH
		: bytes_of_segments(l->tcpi_snd_ssthresh, mss);
	ti->tcpi_snd_cwnd = bytes_of_segments(l->tcpi_snd_cwnd, mss);
	ti->tcpi_snd_sbbytes = sbbytes;

	// what's left of the advertised window (rcv_adv - rcv_nxt): Linux's last advertised one, which differs only by what
	// has come in since. A kernel before 6.2 hasn't got it: then its receive space, its estimate of the window the
	// connection needs.
	ti->tcpi_rcv_space = (got >= offsetof(struct linux_tcp_info_full, tcpi_rcv_wnd) + sizeof(l->tcpi_rcv_wnd))
		? l->tcpi_rcv_wnd : l->tcpi_rcv_space;
	ti->tcpi_snd_wnd = l->tcpi_snd_wnd;

	ti->tcpi_txpackets = l->tcpi_segs_out;
	ti->tcpi_txbytes = l->tcpi_bytes_sent;
	ti->tcpi_txretransmitbytes = l->tcpi_bytes_retrans;
	ti->tcpi_txretransmitpackets = l->tcpi_total_retrans;
	// snd_max - snd_una: what the send buffer holds that has gone out
	ti->tcpi_txunacked = (sbbytes > l->tcpi_notsent_bytes) ? sbbytes - l->tcpi_notsent_bytes : 0;

	ti->tcpi_rxpackets = l->tcpi_segs_in;
	ti->tcpi_rxbytes = l->tcpi_bytes_received;

	ti->tcpi_ecn_success = (ti->tcpi_options & TCPI_OPT_ECN) ? 1 : 0;

	ti->tcpi_rcvoopack = l->tcpi_rcv_ooopack;
	ti->tcpi_reordered_pkts = l->tcpi_reord_seen;
	ti->tcpi_dsack_recvd = l->tcpi_dsack_dups;
}

// XNU's tcp_connection_fill_info(): the same values, as tcp_fill_info() has them
static void connection_fill_info(const struct xnu_tcp_info* ti, struct xnu_tcp_connection_info* tci)
{
	memset(tci, 0, sizeof(*tci));

	tci->tcpi_state = ti->tcpi_state;
	tci->tcpi_snd_wscale = ti->tcpi_snd_wscale;
	tci->tcpi_rcv_wscale = ti->tcpi_rcv_wscale;
	// the TCPCI_OPT_* bits are the TCPI_OPT_* ones
	tci->tcpi_options = ti->tcpi_options;
	if (ti->tcpi_flags & TCPI_FLAG_LOSSRECOVERY)
		tci->tcpi_flags |= TCPCI_FLAG_LOSSRECOVERY;
	// XNU's TF_PKTS_REORDERED: reordering seen on the connection
	if (ti->tcpi_reordered_pkts > 0)
		tci->tcpi_flags |= TCPCI_FLAG_REORDERING_DETECTED;
	tci->tcpi_rto = ti->tcpi_rto;
	tci->tcpi_maxseg = ti->tcpi_snd_mss;
	tci->tcpi_snd_ssthresh = ti->tcpi_snd_ssthresh;
	tci->tcpi_snd_cwnd = ti->tcpi_snd_cwnd;
	tci->tcpi_snd_wnd = ti->tcpi_snd_wnd;
	tci->tcpi_snd_sbbytes = ti->tcpi_snd_sbbytes;
	tci->tcpi_rcv_wnd = ti->tcpi_rcv_space;
	tci->tcpi_rttcur = ti->tcpi_rttcur;
	tci->tcpi_srtt = ti->tcpi_srtt;
	tci->tcpi_rttvar = ti->tcpi_rttvar;
	tci->tcpi_txpackets = ti->tcpi_txpackets;
	tci->tcpi_txbytes = ti->tcpi_txbytes;
	tci->tcpi_txretransmitbytes = ti->tcpi_txretransmitbytes;
	tci->tcpi_txretransmitpackets = ti->tcpi_txretransmitpackets;
	tci->tcpi_rxpackets = ti->tcpi_rxpackets;
	tci->tcpi_rxbytes = ti->tcpi_rxbytes;
	tci->tcpi_rxoutoforderbytes = ti->tcpi_rxoutoforderbytes;
}

long tcp_info_option(int fd, int optname, void* optval, int* optlen)
{
	struct linux_tcp_info_full l;
	struct xnu_tcp_info ti;
	struct xnu_tcp_connection_info tci;
	uint32_t sbbytes;
	unsigned int got;
	const void* value;
	int size, n;
	long ret;

	// XNU's getsockopt() copies the length in only with a buffer, but out whenever the option is read
	// (bsd/kern/uipc_syscalls.c:3317): a missing length is EFAULT, with a buffer or without
	if (optlen == NULL)
		return -EFAULT;

	ret = read_linux_tcp_info(fd, &l, &got, &sbbytes);
	if (ret < 0)
		return ret;

	fill_info(&l, got, sbbytes, &ti);
	if (optname == BSD_TCP_CONNECTION_INFO)
	{
		connection_fill_info(&ti, &tci);
		value = &tci;
		size = sizeof(tci);
	}
	else
	{
		value = &ti;
		size = sizeof(ti);
	}

	// sooptcopyout(): as much as fits
	if (optval == NULL)
	{
		*optlen = 0;
		return 0;
	}
	// (a socklen_t is unsigned: a length that reads as negative here is a large one, which gets the whole struct)
	n = ((unsigned int) *optlen < (unsigned int) size) ? *optlen : size;
	memcpy(optval, value, n);
	*optlen = n;
	return 0;
}
