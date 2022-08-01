#![no_std]
#![no_main]

use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint(name="tcc_trace")]
pub fn tcc_trace(ctx: TracePointContext) -> u32 {
    match unsafe { try_tcc_trace(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_tcc_trace(ctx: TracePointContext) -> Result<u32, u32> {
    /*
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
    
    const sport_offset: usize = 64;
    const dport_offset: usize = 66;
    const mark_offset: usize = 68;
    const data_len_offset: usize = 72;
    const snd_nxt_offset: usize = 76;
    const snd_una_offset: usize = 80;
    const snd_cwnd_offset: usize = 84;
    const ssthresh_offset: usize = 88;
    const snd_wnd_offset: usize = 92;
    const srtt_offset: usize = 96;
    const rcv_wnd_offset: usize = 100;
    const sock_cookie_offset: usize = 104;

    let sport: u16 = ctx.read_at(sport_offset).map_err(|e| e as u32)?;
    let dport: u16 = ctx.read_at(dport_offset).map_err(|e| e as u32)?;
    let mark: u32 = ctx.read_at(mark_offset).map_err(|e| e as u32)?;
    let data_len: u16 = ctx.read_at(data_len_offset).map_err(|e| e as u32)?;
    let snd_nxt: u32 = ctx.read_at(snd_nxt_offset).map_err(|e| e as u32)?;
    let snd_una: u32 = ctx.read_at(snd_una_offset).map_err(|e| e as u32)?;
    let snd_cwnd: u32 = ctx.read_at(snd_cwnd_offset).map_err(|e| e as u32)?;
    let ssthresh: u32 = ctx.read_at(ssthresh_offset).map_err(|e| e as u32)?;
    let snd_wnd: u32 = ctx.read_at(snd_wnd_offset).map_err(|e| e as u32)?;
    let srtt: u32 = ctx.read_at(srtt_offset).map_err(|e| e as u32)?;
    let rcv_wnd: u32 = ctx.read_at(rcv_wnd_offset).map_err(|e| e as u32)?;
    let sock_cookie: u64 = ctx.read_at(sock_cookie_offset).map_err(|e| e as u32)?;

    let target_port = 22;

    if sport == target_port || dport == target_port {
        info!(&ctx, "tracepoint tcp_probe called");
        info!(&ctx, "sport {} dport {} mark {} data len {}", sport, dport, mark, data_len);
        info!(&ctx, "snd_nxt {} snd_una {} snd_cwnd {} ssthresh {}", snd_nxt, snd_una, snd_cwnd, ssthresh);
        info!(&ctx, "snd_wnd {} srtt {} rcv_wnd {} sock_cookie {}", snd_wnd, srtt, rcv_wnd, sock_cookie);
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
