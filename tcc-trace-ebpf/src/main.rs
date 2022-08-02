#![no_std]
#![no_main]

use aya_bpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;

// sockaddr_in6
// uapi (x), rustix (x), libc (X), relibc (X), aya-gen, nix (X)

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
    // some fields omitted
}

#[repr(C)]
#[derive(Copy, Clone)]
union sock {
    v4: sockaddr,
    v6: sockaddr_in6,
}

#[repr(C)]
#[derive(Copy, Clone)]

struct TcpProbe {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    saddr: sock,
    daddr: sock,
    sport: u16,
    dport: u16,
    mark: u32,
    data_len: u16,
    snd_nxt: u32,
    snd_una: u32,
    snd_cwnd: u32,
    ssthresh: u32,
    snd_wnd: u32,
    srtt: u32,
    rcv_wnd: u32,
    sock_cookie: u64,
}

#[tracepoint(name = "tcc_trace")]
pub fn tcc_trace(ctx: TracePointContext) -> u64 {
    match unsafe { try_tcc_trace(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn get(sock: sock, ctx: &TracePointContext) {
    match sock.v6.sin6_family {
        AF_INET => {
            let addr = sock.v4;
            // info!(
            //     ctx,
            //     "IP4 source {}.{}.{}.{} port {} ",
            //     addr.addr[0],
            //     addr.addr[1],
            //     addr.addr[2],
            //     addr.addr[3],
            //     u16::from_be(addr.port)
            // );
        }
        AF_INET6 => {
            let addr = sock.v6;
            info!(
                ctx,
                "IP6  {} Port: {}",
                addr.sin6_family,
                u16::from_be(addr.sin6_port)
            );
            //     info!(
            //         ctx,
            //         "{} {} {} {} {} {} {} {} {} {} {} {} {} {} {} {} ",
            //         addr.sin6_addr.s6_addr[0],
            //         addr.sin6_addr.s6_addr[1],
            //         addr.sin6_addr.s6_addr[2],
            //         addr.sin6_addr.s6_addr[3],
            //         addr.sin6_addr.s6_addr[4],
            //         addr.sin6_addr.s6_addr[5],
            //         addr.sin6_addr.s6_addr[6],
            //         addr.sin6_addr.s6_addr[7],
            //         addr.sin6_addr.s6_addr[8],
            //         addr.sin6_addr.s6_addr[9],
            //         addr.sin6_addr.s6_addr[10],
            //         addr.sin6_addr.s6_addr[11],
            //         addr.sin6_addr.s6_addr[12],
            //         addr.sin6_addr.s6_addr[13],
            //         addr.sin6_addr.s6_addr[14],
            //         addr.sin6_addr.s6_addr[15],
            //     );
        }
        _ => {}
    }
}

const SADDR_OFFSET: usize = 8;

const AF_INET: AddressFamily = 2;
const AF_INET6: AddressFamily = 10;

unsafe fn try_tcc_trace(ctx: TracePointContext) -> Result<u64, u64> {
    /*
    https://github.com/libpnet/libpnet/blob/44f17c8c570caf244b0df52e69bbda7b545fb7f3/pnet_sys/src/unix.rs#L169

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

    let probe: TcpProbe = ctx.read_at(0).map_err(|e| e as u64)?;

    let TcpProbe {
        common_type,
        common_flags,
        common_preempt_count,
        common_pid,
        saddr,
        daddr,
        sport,
        dport,
        mark,
        data_len,
        snd_nxt,
        snd_una,
        snd_cwnd,
        ssthresh,
        snd_wnd,
        srtt,
        rcv_wnd,
        sock_cookie,
    } = probe;

    let target_port = 443;

    if sport == target_port || dport == target_port {
        info!(
            &ctx,
            "common_type {} common_flags {} common_preempt_count {} common_pid {}",
            common_type,
            common_flags,
            common_preempt_count,
            i32::from_be(common_pid)
        );

        // info!(&ctx, "tracepoint tcp_probe called");
        // get(saddr, &ctx);
        // get(daddr, &ctx);

        info!(
            &ctx,
            "sport {} dport {} mark {} data len {}", sport, dport, mark, data_len
        );
        // info!(
        //     &ctx,
        //     "snd_nxt {} snd_una {} snd_cwnd {} ssthresh {}", snd_nxt, snd_una, snd_cwnd, ssthresh
        // );
        // info!(
        //     &ctx,
        //     "snd_wnd {} srtt {} rcv_wnd {} sock_cookie {}", snd_wnd, srtt, rcv_wnd, sock_cookie
        // );
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
