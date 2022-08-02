#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use tcc_trace_common::TcpProbe;

#[map]
static mut TCP_PROBES: PerfEventArray<TcpProbe> = PerfEventArray::new(0);

#[tracepoint(name = "tcc_trace")]
pub fn tcc_trace(ctx: TracePointContext) -> u64 {
    match unsafe { try_tcc_trace(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret as u64,
    }
}

unsafe fn try_tcc_trace(ctx: TracePointContext) -> Result<u64, i64> {
    let probe: TcpProbe = ctx.read_at(0)?;

    // As an optimization, filtering can be done in kernel space
    // for now, just send to user space

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

    // send perf event
    TCP_PROBES.output(&ctx, &probe, 0);

    if sport == target_port || dport == target_port {

        // info!(
        //     &ctx,
        //     "common_type {} common_flags {} common_preempt_count {} common_pid {}",
        //     common_type,
        //     common_flags,
        //     common_preempt_count,
        //     i32::from_be(common_pid)
        // );

        // info!(&ctx, "tracepoint tcp_probe called");
        // get(saddr, &ctx);
        // get(daddr, &ctx);

        // info!(
        //     &ctx,
        //     "sport {} dport {} mark {} data len {}", sport, dport, mark, data_len
        // );
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
