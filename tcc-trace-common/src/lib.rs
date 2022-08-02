#![no_std]

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
