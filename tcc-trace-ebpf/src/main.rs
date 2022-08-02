#![no_std]
#![no_main]

use aya_bpf::{
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};
use aya_log_ebpf::info;
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

    let TcpProbe { sport, dport, .. } = probe;

    let target_port = 443;
    if sport == target_port || dport == target_port {
        // As an optimization, filtering can be done in kernel space
        // Currently, we'll make do with sending and filtering in user space
    }

    // TODO add timestamp via
    // bpf_ktime_get_ns
    // bpf_ktime_get_boot_ns

    // send perf event
    TCP_PROBES.output(&ctx, &probe, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
