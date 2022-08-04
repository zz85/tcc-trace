#![no_std]
#![no_main]

use aya_bpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, tracepoint},
    maps::{PerfEventArray, HashMap},
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use tcc_trace_common::{TcpProbe, TracePayload, STARTED_KTIME};

#[map]
static mut TCP_PROBES: PerfEventArray<TracePayload> = PerfEventArray::new(0);

#[map]
static mut TCC_SETTINGS: HashMap<u8, u64> = HashMap::with_max_entries(1024, 0);

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

    // bpf_ktime_get_boot_ns() to include suspection time
    // would be useful on mobile devices, see
    // https://www.spinics.net/lists/netdev/msg645539.html
    let time = bpf_ktime_get_ns();

    let started = match TCC_SETTINGS.get(&STARTED_KTIME) {
        None => {
            TCC_SETTINGS.insert(&STARTED_KTIME, &time, 0)?;
            time
        }

        Some(started) => { *started }
    };

    let payload = TracePayload {
        time,
        offset_time: time - started,
        probe,
    };

    // send perf event
    TCP_PROBES.output(&ctx, &payload, 0);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
