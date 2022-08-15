#![no_std]

pub struct TracePayload {
    pub time: u64,
    pub offset_time: u64,
    pub probe: TcpProbe,
}

pub const SADDR_OFFSET: usize = 8;
pub const AF_INET: AddressFamily = 2;
pub const AF_INET6: AddressFamily = 10;

// there's plenty of approach of generating these struct, eg
// aya-gen, libc, uapi, rustix, relibc,  nix
// but they have issues building with no_std so I decide to just write them by hand

/*
https://elixir.bootlin.com/linux/v4.0/source/net/ipv4/tcp_probe.c
    % sudo cat /sys/kernel/debug/tracing/events/tcp/tcp_probe/format
name: tcp_probe
ID: 624
format:
    field:unsigned short common_type;   offset:0;   size:2; signed:0;
    field:unsigned char common_flags;   offset:2;   size:1; signed:0;
    field:unsigned char common_preempt_count;   offset:3;   size:1; signed:0;
    field:int common_pid;   offset:4;   size:4; signed:1;

    field:__u8 saddr[sizeof(struct sockaddr_in6)];  offset:8;   size:28;    signed:0;
    field:__u8 daddr[sizeof(struct sockaddr_in6)];  offset:36;  size:28;    signed:0;
    field:__u16 sport;  offset:64;  size:2; signed:0;
    field:__u16 dport;  offset:66;  size:2; signed:0;
    field:__u32 mark;   offset:68;  size:4; signed:0;
    field:__u16 data_len;   offset:72;  size:2; signed:0;
    field:__u32 snd_nxt;    offset:76;  size:4; signed:0;
    field:__u32 snd_una;    offset:80;  size:4; signed:0;
    field:__u32 snd_cwnd;   offset:84;  size:4; signed:0;
    field:__u32 ssthresh;   offset:88;  size:4; signed:0;
    field:__u32 snd_wnd;    offset:92;  size:4; signed:0;
    field:__u32 srtt;   offset:96;  size:4; signed:0;
    field:__u32 rcv_wnd;    offset:100; size:4; signed:0;
    field:__u64 sock_cookie;    offset:104; size:8; signed:0;

print fmt: "src=%pISpc dest=%pISpc mark=%#x data_len=%d snd_nxt=%#x snd_una=%#x snd_cwnd=%u ssthresh=%u snd_wnd=%u srtt=%u rcv_wnd=%u sock_cookie=%llx", REC->saddr, REC->daddr, REC->mark, REC->data_len, REC->snd_nxt, REC->snd_una, REC->snd_cwnd, REC->ssthresh, REC->snd_wnd, REC->srtt, REC->rcv_wnd, REC->sock_cookie
*/

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TcpProbe {
    pub common_type: u16,
    pub common_flags: u8,
    pub common_preempt_count: u8,
    pub common_pid: i32,
    pub saddr: socket,
    pub daddr: socket,
    pub sport: u16,
    pub dport: u16,
    pub mark: u32,
    pub data_len: u16,
    pub snd_nxt: u32,
    pub snd_una: u32,
    pub snd_cwnd: u32,
    pub ssthresh: u32,
    pub snd_wnd: u32,
    pub srtt: u32,
    pub rcv_wnd: u32,
    pub sock_cookie: u64,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr {
    pub sa_family: AddressFamily,
    pub port: u16,
    pub addr: [u8; 4],
    pub zeros: [u8; 8], // just padding
}

pub type AddressFamily = u16;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_in6 {
    pub sin6_family: AddressFamily,
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct in6_addr {
    pub s6_addr: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub union socket {
    pub v4: sockaddr,
    pub v6: sockaddr_in6,
}

pub const STARTED_KTIME: u8 = 0;
pub const PORT_FILTER: u8 = 1;

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct tcp_info {
    //https://elixir.bootlin.com/linux/v5.4.208/source/include/uapi/linux/tcp.h#L206
    pub tcpi_state: u8,                     //;
    pub tcpi_ca_state: u8,                  //;
    pub tcpi_retransmits: u8,               //;
    pub tcpi_probes: u8,                    //;
    pub tcpi_backoff: u8,                   //;
    pub tcpi_options: u8,                   //;
    pub tcpi_rcv_wscale: u8,                //	tcpi_snd_wscale : 4,, // : 4;
    pub tcpi_delivery_rate_app_limited: u8, //:1;

    pub tcpi_rto: u32,     //;
    pub tcpi_ato: u32,     //;
    pub tcpi_snd_mss: u32, //;
    pub tcpi_rcv_mss: u32, //;

    pub tcpi_unacked: u32, //;
    pub tcpi_sacked: u32,  //;
    pub tcpi_lost: u32,    //;
    pub tcpi_retrans: u32, //;
    pub tcpi_fackets: u32, //;

    /* Times. */
    pub tcpi_last_data_sent: u32, //;
    pub tcpi_last_ack_sent: u32,  //;     /* Not remembered, sorry. */
    pub tcpi_last_data_recv: u32, //;
    pub tcpi_last_ack_recv: u32,  //;

    /* Metrics. */
    pub tcpi_pmtu: u32,         //;
    pub tcpi_rcv_ssthresh: u32, //;
    pub tcpi_rtt: u32,          //;
    pub tcpi_rttvar: u32,       //;
    pub tcpi_snd_ssthresh: u32, //;
    pub tcpi_snd_cwnd: u32,     //;
    pub tcpi_advmss: u32,       //;
    pub tcpi_reordering: u32,   //;

    pub tcpi_rcv_rtt: u32,   //;
    pub tcpi_rcv_space: u32, //;

    pub tcpi_total_retrans: u32, //;

    pub tcpi_pacing_rate: u64,     //;
    pub tcpi_max_pacing_rate: u64, //;
    pub tcpi_bytes_acked: u64,     //;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
    pub tcpi_bytes_received: u64,  //; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
    pub tcpi_segs_out: u32,        //;	     /* RFC4898 tcpEStatsPerfSegsOut */
    pub tcpi_segs_in: u32,         //;	     /* RFC4898 tcpEStatsPerfSegsIn */

    pub tcpi_notsent_bytes: u32, //;
    pub tcpi_min_rtt: u32,       //;
    pub tcpi_data_segs_in: u32,  //;	/* RFC4898 tcpEStatsDataSegsIn */
    pub tcpi_data_segs_out: u32, //;	/* RFC4898 tcpEStatsDataSegsOut */

    pub tcpi_delivery_rate: u64, //;

    pub tcpi_busy_time: u64,      //;      /* Time (usec) busy sending data */
    pub tcpi_rwnd_limited: u64,   //;   /* Time (usec) limited by receive window */
    pub tcpi_sndbuf_limited: u64, //; /* Time (usec) limited by send buffer */

    pub tcpi_delivered: u32,    //;
    pub tcpi_delivered_ce: u32, //;

    pub tcpi_bytes_sent: u64, //;     /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
    pub tcpi_bytes_retrans: u64, //;  /* RFC4898 tcpEStatsPerfOctetsRetrans */
    pub tcpi_dsack_dups: u32, //;     /* RFC4898 tcpEStatsStackDSACKDups */
    pub tcpi_reord_seen: u32, //;     /* reordering events seen */

    pub tcpi_rcv_ooopack: u32, //;    /* Out-of-order packets received */

    pub tcpi_snd_wnd: u32, //;	     /* peer's advertised receive window after scaling (bytes) */
}

pub type __u8 = u8;
pub type __u16 = u16;
pub type __u32 = u32;
pub type __be16 = __u16;
pub type __be32 = __u32;
pub type __sum16 = __u16;
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ethhdr {
    pub h_dest: [u8; 6usize],
    pub h_source: [u8; 6usize],
    pub h_proto: __be16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct iphdr {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: [u8; 1usize],
    pub tos: __u8,
    pub tot_len: __be16,
    pub id: __be16,
    pub frag_off: __be16,
    pub ttl: __u8,
    pub protocol: __u8,
    pub check: __sum16,
    pub saddr: __be32,
    pub daddr: __be32,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct udphdr {
    pub source: __be16,
    pub dest: __be16,
    pub len: __be16,
    pub check: __sum16,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct tcphdr {
    pub source: __be16,
    pub dest: __be16,
    pub seq: __be32,
    pub ack_seq: __be32,
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: [u8; 2usize],
    pub window: __be16,
    pub check: __sum16,
    pub urg_ptr: __be16,
}
