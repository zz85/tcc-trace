#![no_std]
#![no_main]

use aya_bpf::{macros::tracepoint, programs::TracePointContext};
use aya_log_ebpf::info;
use tcc_trace_common::{sock, TcpProbe};

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

unsafe fn try_tcc_trace(ctx: TracePointContext) -> Result<u64, u64> {
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
