#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{
    bindings::{
        TC_ACT_OK, TC_ACT_PIPE, TC_ACT_RECLASSIFY, TC_ACT_REDIRECT, TC_ACT_SHOT, TC_ACT_UNSPEC,
    },
    helpers::bpf_ktime_get_ns,
    macros::{classifier, map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::{SkBuffContext, TracePointContext},
    BpfContext,
};
use aya_log_ebpf::{error, info};
use memoffset::offset_of;
use tcc_trace_common::{
    TcpProbe, TracePayload, __sk_buff, ethhdr, iphdr, udphdr, PORT_FILTER, PORT_MAP_TO,
    STARTED_KTIME,
};

#[map]
static mut TCP_PROBES: PerfEventArray<TracePayload> = PerfEventArray::new(0);

#[map]
static mut TCC_SETTINGS: HashMap<u8, u64> = HashMap::with_max_entries(1024, 0);

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

#[map]
static mut MATCHLIST_V4: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);
// TODO, use LSM instead

#[classifier(name = "tc_cls_ingress")]
pub fn tc_cls_ingress(ctx: SkBuffContext) -> i32 {
    match { try_tc_cls_ingress(ctx) } {
        Ok(_) => {
            // TC_ACT_OK
            TC_ACT_PIPE
        }
        Err(1) => {
            TC_ACT_OK
            // TC_ACT_PIPE
            // TC_ACT_RECLASSIFY
            // TC_ACT_UNSPEC
            // all works except this
            // TC_ACT_REDIRECT
        }

        Err(_) => TC_ACT_SHOT,
    }
}

fn try_tc_cls_ingress(mut ctx: SkBuffContext) -> Result<(), i64> {
    let eth_proto = u16::from_be(ctx.load(offset_of!(ethhdr, h_proto))?);
    let ip_proto = ctx.load::<u8>(ETH_HDR_LEN + offset_of!(iphdr, protocol))?;
    if !(eth_proto == ETH_P_IP && (ip_proto == IPPROTO_TCP || ip_proto == IPPROTO_UDP)) {
        return Ok(());
    }

    // process only UDP or TCP and IPv4 only right now

    if ip_proto != IPPROTO_UDP {
        return Ok(());
    }

    // let buff = unsafe { core::mem::transmute::<_, &mut __sk_buff>(ctx.as_ptr()) };
    // in my testing only works up to napi_id field

    let protocol: u8 = ctx.load(ETH_HDR_LEN + offset_of!(iphdr, protocol))?;

    let saddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, saddr))?);
    let daddr = u32::from_be(ctx.load(ETH_HDR_LEN + offset_of!(iphdr, daddr))?);

    info!(&ctx, "protocol {}", protocol);

    let match_saddr = unsafe { MATCHLIST_V4.get(&saddr) };
    let match_addr = unsafe { MATCHLIST_V4.get(&daddr) };

    if match_saddr.or(match_addr).is_none() {
        error!(&ctx, "nothing to do");

        return Ok(());
        // return Err(-1);
    }

    info!(&ctx, "matched ip!");

    let map_from = unsafe { TCC_SETTINGS.get(&PORT_FILTER) }
        .map(|v| *v)
        .unwrap_or_default() as u16;
    let map_to = unsafe { TCC_SETTINGS.get(&PORT_MAP_TO) }
        .map(|v| *v)
        .unwrap_or_default() as u16;

    // let map_from = 12345;
    // let map_to = 1234u16;

    let UDP_SRC_PORT = ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, source);
    let UDP_DEST_PORT = ETH_HDR_LEN + IP_HDR_LEN + offset_of!(udphdr, dest);

    let src_port = u16::from_be(ctx.load(UDP_SRC_PORT)?);
    let dest_port = u16::from_be(ctx.load(UDP_DEST_PORT)?);

    info!(&ctx, "current: source -> dest {} {}", src_port, dest_port);

    if dest_port == map_from {
        // when matches map from
        let changed = map_to.to_be_bytes();
        ctx.store(UDP_DEST_PORT, &changed, 0)?;
        // ctx.l4_csum_replace(UDP_DEST_PORT, source_port as u64, changed as u64, 0);
        info!(&ctx, "modified: source -> dest {} {}", src_port, map_to);
        return Err(1);
    }

    if src_port == map_to {
        let changed = map_from.to_be_bytes();
        ctx.store(UDP_SRC_PORT, &changed, 0)?;
        info!(&ctx, "modified: source -> dest {} {}", map_from, dest_port);
    }

    // info!(&ctx, "accepted packet");
    Ok(())
}

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

    if let Some(target_port) = TCC_SETTINGS.get(&PORT_FILTER) {
        let target_port = *target_port;
        if sport as u64 != target_port && dport as u64 != target_port {
            // As an optimization, filtering can be done in kernel space
            // Currently, IP filtering still done in user space
            return Ok(0);
        }
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

        Some(started) => *started,
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
