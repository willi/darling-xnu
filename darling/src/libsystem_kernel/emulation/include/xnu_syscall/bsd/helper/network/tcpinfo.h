#ifndef NETWORK_TCPINFO_H
#define NETWORK_TCPINFO_H

#include <stdint.h>
#include <sys/types.h>

// getsockopt(IPPROTO_TCP, TCP_INFO) and (IPPROTO_TCP, TCP_CONNECTION_INFO), as XNU answers them (tcp_fill_info() and
// tcp_connection_fill_info() in bsd/netinet/tcp_usrreq.c), from Linux's TCP_INFO. libnetwork asks for both of every
// connection (nw_socket_copy_info). The values Linux has no counterpart for are 0; see tcpinfo.c.
long tcp_info_option(int fd, int optname, void* optval, int* optlen);

#define BSD_TCP_CONNECTION_INFO 0x106
#define BSD_TCP_INFO 0x200

//
// copied from XNU's bsd/netinet/tcp_private.h and bsd/netinet/tcp.h (xnu-10002.1.13), the structures renamed
//

#pragma pack(4)

#define TCPI_OPT_TIMESTAMPS     0x01
#define TCPI_OPT_SACK           0x02
#define TCPI_OPT_WSCALE         0x04
#define TCPI_OPT_ECN            0x08

#define TCPI_FLAG_LOSSRECOVERY  0x01    /* Currently in loss recovery */
#define TCPI_FLAG_STREAMING_ON  0x02    /* Streaming detection on */

struct xnu_tcp_conn_status {
	union {
		struct {
			unsigned int    probe_activated : 1;
			unsigned int    write_probe_failed : 1;
			unsigned int    read_probe_failed : 1;
			unsigned int    conn_probe_failed : 1;
		};
		uint32_t        pad_field;
	};
};

/*
 * Add new fields to this structure at the end only. This will preserve
 * binary compatibility.
 */
struct xnu_tcp_info {
	u_int8_t        tcpi_state;                 /* TCP FSM state. */
	u_int8_t        tcpi_options;       /* Options enabled on conn. */
	u_int8_t        tcpi_snd_wscale;    /* RFC1323 send shift value. */
	u_int8_t        tcpi_rcv_wscale;    /* RFC1323 recv shift value. */

	u_int32_t       tcpi_flags;                 /* extra flags (TCPI_FLAG_xxx) */

	u_int32_t       tcpi_rto;                   /* Retransmission timeout in milliseconds */
	u_int32_t       tcpi_snd_mss;       /* Max segment size for send. */
	u_int32_t       tcpi_rcv_mss;       /* Max segment size for receive. */

	u_int32_t       tcpi_rttcur;        /* Most recent value of RTT */
	u_int32_t       tcpi_srtt;          /* Sender's Smoothed RTT */
	u_int32_t       tcpi_rttvar;        /* RTT variance */
	u_int32_t       tcpi_rttbest;       /* Best RTT we've seen */

	u_int32_t       tcpi_snd_ssthresh;  /* Slow start threshold. */
	u_int32_t       tcpi_snd_cwnd;      /* Send congestion window. */

	u_int32_t       tcpi_rcv_space;     /* Advertised recv window. */

	u_int32_t       tcpi_snd_wnd;       /* Advertised send window. */
	u_int32_t       tcpi_snd_nxt;       /* Next egress seqno */
	u_int32_t       tcpi_rcv_nxt;       /* Next ingress seqno */

	int32_t         tcpi_last_outif;    /* if_index of interface used to send last */
	u_int32_t       tcpi_snd_sbbytes;   /* bytes in snd buffer including data inflight */

	u_int64_t       tcpi_txpackets __attribute__((aligned(8))); /* total packets sent */
	u_int64_t       tcpi_txbytes __attribute__((aligned(8)));
	/* total bytes sent */
	u_int64_t       tcpi_txretransmitbytes __attribute__((aligned(8)));
	/* total bytes retransmitted */
	u_int64_t       tcpi_txunacked __attribute__((aligned(8)));
	/* current number of bytes not acknowledged */
	u_int64_t       tcpi_rxpackets __attribute__((aligned(8))); /* total packets received */
	u_int64_t       tcpi_rxbytes __attribute__((aligned(8)));
	/* total bytes received */
	u_int64_t       tcpi_rxduplicatebytes __attribute__((aligned(8)));
	/* total duplicate bytes received */
	u_int64_t       tcpi_rxoutoforderbytes __attribute__((aligned(8)));
	/* total out of order bytes received */
	u_int64_t       tcpi_snd_bw __attribute__((aligned(8)));    /* measured send bandwidth in bits/sec */
	u_int8_t        tcpi_synrexmits;    /* Number of syn retransmits before connect */
	u_int8_t        tcpi_unused1;
	u_int16_t       tcpi_unused2;
	u_int64_t       tcpi_cell_rxpackets __attribute((aligned(8)));/* packets received over cellular */
	u_int64_t       tcpi_cell_rxbytes __attribute((aligned(8)));/* bytes received over cellular */
	u_int64_t       tcpi_cell_txpackets __attribute((aligned(8)));/* packets transmitted over cellular */
	u_int64_t       tcpi_cell_txbytes __attribute((aligned(8)));/* bytes transmitted over cellular */
	u_int64_t       tcpi_wifi_rxpackets __attribute((aligned(8)));/* packets received over Wi-Fi */
	u_int64_t       tcpi_wifi_rxbytes __attribute((aligned(8)));/* bytes received over Wi-Fi */
	u_int64_t       tcpi_wifi_txpackets __attribute((aligned(8)));/* packets transmitted over Wi-Fi */
	u_int64_t       tcpi_wifi_txbytes __attribute((aligned(8)));/* bytes transmitted over Wi-Fi */
	u_int64_t       tcpi_wired_rxpackets __attribute((aligned(8)));/* packets received over Wired */
	u_int64_t       tcpi_wired_rxbytes __attribute((aligned(8)));/* bytes received over Wired */
	u_int64_t       tcpi_wired_txpackets __attribute((aligned(8)));/* packets transmitted over Wired */
	u_int64_t       tcpi_wired_txbytes __attribute((aligned(8)));/* bytes transmitted over Wired */
	struct xnu_tcp_conn_status  tcpi_connstatus;/* status of connection probes */

	u_int16_t
	    tcpi_tfo_cookie_req:1, /* Cookie requested? */
	    tcpi_tfo_cookie_rcv:1, /* Cookie received? */
	    tcpi_tfo_syn_loss:1,   /* Fallback to reg. TCP after SYN-loss */
	    tcpi_tfo_syn_data_sent:1, /* SYN+data has been sent out */
	    tcpi_tfo_syn_data_acked:1, /* SYN+data has been fully acknowledged */
	    tcpi_tfo_syn_data_rcv:1, /* Server received SYN+data with a valid cookie */
	    tcpi_tfo_cookie_req_rcv:1, /* Server received cookie-request */
	    tcpi_tfo_cookie_sent:1, /* Server announced cookie */
	    tcpi_tfo_cookie_invalid:1, /* Server received an invalid cookie */
	    tcpi_tfo_cookie_wrong:1, /* Our sent cookie was wrong */
	    tcpi_tfo_no_cookie_rcv:1, /* We did not receive a cookie upon our request */
	    tcpi_tfo_heuristics_disable:1, /* TFO-heuristics disabled it */
	    tcpi_tfo_send_blackhole:1, /* A sending-blackhole got detected */
	    tcpi_tfo_recv_blackhole:1, /* A receiver-blackhole got detected */
	    tcpi_tfo_onebyte_proxy:1; /* A proxy acknowledges all but one byte of the SYN */

	u_int16_t       tcpi_ecn_client_setup:1,    /* Attempted ECN setup from client side */
	    tcpi_ecn_server_setup:1,                /* Attempted ECN setup from server side */
	    tcpi_ecn_success:1,                     /* peer negotiated ECN */
	    tcpi_ecn_lost_syn:1,                    /* Lost SYN with ECN setup */
	    tcpi_ecn_lost_synack:1,                 /* Lost SYN-ACK with ECN setup */
	    tcpi_local_peer:1,                      /* Local to the host or the subnet */
	    tcpi_if_cell:1,                 /* Interface is cellular */
	    tcpi_if_wifi:1,                 /* Interface is WiFi */
	    tcpi_if_wired:1,                /* Interface is wired - ethernet , thunderbolt etc,. */
	    tcpi_if_wifi_infra:1,           /* Interface is wifi infrastructure */
	    tcpi_if_wifi_awdl:1,            /* Interface is wifi AWDL */
	    tcpi_snd_background:1,          /* Using delay based algorithm on sender side */
	    tcpi_rcv_background:1;          /* Using delay based algorithm on receive side */

	u_int32_t       tcpi_ecn_recv_ce;   /* Packets received with CE */
	u_int32_t       tcpi_ecn_recv_cwr;  /* Packets received with CWR */

	u_int32_t       tcpi_rcvoopack;     /* out-of-order packets received */
	u_int32_t       tcpi_pawsdrop;      /* segments dropped due to PAWS */
	u_int32_t       tcpi_sack_recovery_episode;/* SACK recovery episodes */
	u_int32_t       tcpi_reordered_pkts;/* packets reorderd */
	u_int32_t       tcpi_dsack_sent;    /* Sent DSACK notification */
	u_int32_t       tcpi_dsack_recvd;   /* Received a valid DSACK option */
	u_int32_t       tcpi_flowhash;      /* Unique id for the connection */

	u_int64_t       tcpi_txretransmitpackets __attribute__((aligned(8)));

#define TCPINFO_HAS_RCV_RTT 1
	uint32_t       tcpi_rcv_srtt;       /* Receiver's Smoothed RTT */
	uint32_t       tcpi_client_accecn_state;   /* Client's Accurate ECN state */
	uint32_t       tcpi_server_accecn_state;   /* Server's Accurate ECN state as seen by clent */
	uint64_t       tcpi_ecn_capable_packets_sent;   /* Packets sent with ECT */
	uint64_t       tcpi_ecn_capable_packets_acked;  /* Packets sent with ECT that were ACKed */
	uint64_t       tcpi_ecn_capable_packets_marked; /* Packets sent with ECT that were marked */
	uint64_t       tcpi_ecn_capable_packets_lost;   /* Packets sent with ECT that were lost */
};

#pragma pack()

struct xnu_tcp_connection_info {
	u_int8_t        tcpi_state;     /* connection state */
	u_int8_t        tcpi_snd_wscale; /* Window scale for send window */
	u_int8_t        tcpi_rcv_wscale; /* Window scale for receive window */
	u_int8_t        __pad1;
	u_int32_t       tcpi_options;   /* TCP options supported */
#define TCPCI_OPT_TIMESTAMPS    0x00000001 /* Timestamps enabled */
#define TCPCI_OPT_SACK          0x00000002 /* SACK enabled */
#define TCPCI_OPT_WSCALE        0x00000004 /* Window scaling enabled */
#define TCPCI_OPT_ECN           0x00000008 /* ECN enabled */
	u_int32_t       tcpi_flags;     /* flags */
#define TCPCI_FLAG_LOSSRECOVERY 0x00000001
#define TCPCI_FLAG_REORDERING_DETECTED  0x00000002
	u_int32_t       tcpi_rto;       /* retransmit timeout in ms */
	u_int32_t       tcpi_maxseg;    /* maximum segment size supported */
	u_int32_t       tcpi_snd_ssthresh; /* slow start threshold in bytes */
	u_int32_t       tcpi_snd_cwnd;  /* send congestion window in bytes */
	u_int32_t       tcpi_snd_wnd;   /* send widnow in bytes */
	u_int32_t       tcpi_snd_sbbytes; /* bytes in send socket buffer, including in-flight data */
	u_int32_t       tcpi_rcv_wnd;   /* receive window in bytes*/
	u_int32_t       tcpi_rttcur;    /* most recent RTT in ms */
	u_int32_t       tcpi_srtt;      /* average RTT in ms */
	u_int32_t       tcpi_rttvar;    /* RTT variance */
	u_int32_t
	    tcpi_tfo_cookie_req:1,             /* Cookie requested? */
	    tcpi_tfo_cookie_rcv:1,             /* Cookie received? */
	    tcpi_tfo_syn_loss:1,               /* Fallback to reg. TCP after SYN-loss */
	    tcpi_tfo_syn_data_sent:1,             /* SYN+data has been sent out */
	    tcpi_tfo_syn_data_acked:1,             /* SYN+data has been fully acknowledged */
	    tcpi_tfo_syn_data_rcv:1,             /* Server received SYN+data with a valid cookie */
	    tcpi_tfo_cookie_req_rcv:1,             /* Server received cookie-request */
	    tcpi_tfo_cookie_sent:1,             /* Server announced cookie */
	    tcpi_tfo_cookie_invalid:1,             /* Server received an invalid cookie */
	    tcpi_tfo_cookie_wrong:1,             /* Our sent cookie was wrong */
	    tcpi_tfo_no_cookie_rcv:1,             /* We did not receive a cookie upon our request */
	    tcpi_tfo_heuristics_disable:1,             /* TFO-heuristics disabled it */
	    tcpi_tfo_send_blackhole:1,             /* A sending-blackhole got detected */
	    tcpi_tfo_recv_blackhole:1,             /* A receiver-blackhole got detected */
	    tcpi_tfo_onebyte_proxy:1,             /* A proxy acknowledges all but one byte of the SYN */
	    __pad2:17;
	u_int64_t       tcpi_txpackets __attribute__((aligned(8)));
	u_int64_t       tcpi_txbytes __attribute__((aligned(8)));
	u_int64_t       tcpi_txretransmitbytes __attribute__((aligned(8)));
	u_int64_t       tcpi_rxpackets __attribute__((aligned(8)));
	u_int64_t       tcpi_rxbytes __attribute__((aligned(8)));
	u_int64_t       tcpi_rxoutoforderbytes __attribute__((aligned(8)));
	u_int64_t       tcpi_txretransmitpackets __attribute__((aligned(8)));
};

#define TCPS_CLOSED             0       /* closed */
#define TCPS_LISTEN             1       /* listening for connection */
#define TCPS_SYN_SENT           2       /* active, have sent syn */
#define TCPS_SYN_RECEIVED       3       /* have send and received syn */
#define TCPS_ESTABLISHED        4       /* established */
#define TCPS_CLOSE_WAIT         5       /* rcvd fin, waiting for close */
#define TCPS_FIN_WAIT_1         6       /* have closed, sent fin */
#define TCPS_CLOSING            7       /* closed xchd FIN; await FIN ACK */
#define TCPS_LAST_ACK           8       /* had fin and close; await FIN ACK */
#define TCPS_FIN_WAIT_2         9       /* have closed, fin is acked */
#define TCPS_TIME_WAIT          10      /* in 2*msl quiet wait after close */

//
// end copied from XNU
//

// XNU's sizes (pack(4) caps tcp_info's aligned(8) members)
_Static_assert(sizeof(struct xnu_tcp_info) == 336, "struct tcp_info is 336 bytes");
_Static_assert(sizeof(struct xnu_tcp_connection_info) == 112, "struct tcp_connection_info is 112 bytes");

#endif // NETWORK_TCPINFO_H
