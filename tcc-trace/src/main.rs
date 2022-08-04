use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tcc_trace_common::{socket, TcpProbe, TracePayload, AF_INET, AF_INET6};
use tokio::{signal, task};

/// Congestion Control tracer for TCP connections
#[derive(Debug, Parser)]
struct Opt {
    /// Filter by port number (display all ports by default)
    #[clap(short, long, value_parser)]
    port: Option<u16>,

    /// Filter by ip (shows all ips by default)
    #[clap(short, long, value_parser)]
    ip: Option<IpAddr>,

    #[clap(short, long, value_parser)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let Opt { port, ip, debug } = Opt::parse();

    if let Some(ip) = ip {
        println!("Filtering IP: {:?}", ip);
    }

    if let Some(port) = port {
        println!("Filtering port: {}", port);
    }

    if (None, None) == (port, ip) {
        println!("No filters...");
    }

    if debug {
        TermLogger::init(
            LevelFilter::Debug,
            ConfigBuilder::new()
                .set_target_level(LevelFilter::Error)
                .set_location_level(LevelFilter::Error)
                .build(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )?;
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/tcc-trace"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/tcc-trace"
    ))?;
    BpfLogger::init(&mut bpf)?;

    let start = Instant::now();
    let program: &mut TracePoint = bpf.program_mut("tcc_trace").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp", "tcp_probe")?;
    println!(
        "TCP Probe attached via BPF Tracepoint in {:.3}ms",
        start.elapsed().as_secs_f64() * 1000.0
    );

    let mut handler = Handler::new(ip, port);
    let event_count = Arc::new(AtomicU64::new(0));
    let filtered_count = Arc::new(AtomicU64::new(0));
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("TCP_PROBES")?)?;

    let (tx, rx) = mpsc::channel();

    task::spawn(async move {
        while let Ok(payload) = rx.recv() {
            handler.process_event(payload);
        }
    });

    for cpu_id in online_cpus()? {
        let event_count = event_count.clone();
        let filtered_count = filtered_count.clone();

        let mut buf = perf_array.open(cpu_id, None)?;
        let tx = tx.clone();

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                event_count.fetch_add(events.read as u64 + events.lost as u64, Ordering::Relaxed);
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const TracePayload;
                    let payload = unsafe { ptr.read_unaligned() };

                    tx.send(payload).unwrap();
                }
            }
        });
    }

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    let event_count = event_count.load(Ordering::Relaxed);
    let filtered_count = filtered_count.load(Ordering::Relaxed);

    println!(
        "Total events: {}, Filtered: {}, Displayed: {}",
        event_count,
        filtered_count,
        event_count - filtered_count
    );

    Ok(())
}

struct Handler {
    port: Option<u16>,
    ip: Option<IpAddr>,
    start: Instant,
    cache: std::collections::HashMap<(SocketAddr, SocketAddr), Instant>,
    // TODO clean cached entries out automatically - it's possible to
    // tcp state events to observe connection has close or timeout
    // to clean up these entries
    first_drift: Option<Duration>,
}

impl Handler {
    fn new(ip: Option<IpAddr>, port: Option<u16>) -> Self {
        Self {
            ip,
            port,
            start: Instant::now(),
            cache: Default::default(),
            first_drift: Default::default(),
        }
    }
    fn process_event(&mut self, payload: TracePayload) {
        let TracePayload {
            time,
            offset_time,
            probe,
        } = payload;
        // Process probe
        let TcpProbe {
            // common_type,
            // common_flags,
            // common_preempt_count,
            // common_pid,
            saddr,
            daddr,
            sport,
            dport,
            // mark,
            data_len,
            snd_nxt,
            snd_una,
            snd_cwnd,
            ssthresh,
            snd_wnd,
            srtt,
            rcv_wnd,
            sock_cookie,
            ..
        } = probe;

        if let Some(port) = self.port {
            // if port is set, filter connections that doesn't match
            if sport != port && dport != port {
                // filtered_count.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        let source = format_socket(saddr).unwrap();
        let dest = format_socket(daddr).unwrap();
        let source_ip = source.ip();
        let dest_ip = dest.ip();

        if let Some(ip) = self.ip {
            if ip != source_ip && ip != dest_ip {
                // filtered_count.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }

        let first_seen = self.cache.entry((source, dest)).or_insert(Instant::now());

        let debug_drift = false;
        if debug_drift {
            // estimate drift from kernel -> userspace
            match self.first_drift {
                Some(first_drift) => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos();
                    let current_drift = Duration::from_nanos(now as u64 - time);

                    let diff = if first_drift > current_drift {
                        first_drift - current_drift
                    } else {
                        current_drift - first_drift
                    };
                    print!("drift:{:?} | ", diff);
                }
                None => {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_nanos();
                    let drift = Duration::from_nanos(now as u64 - time);
                    self.first_drift = Some(drift);
                }
            }
        }

        println!(
        "k:{} {:.3}ms | {:.3} ms| {:?}.{} > {:?}.{} | snd_cwnd {} ssthresh {} snd_wnd {} srtt {:3} rcv_wnd {} length {}",
        time, offset_time as f64 / 1e6 ,
        // self.start.elapsed().as_secs_f64() * 1000.0,
        first_seen.elapsed().as_secs_f64() * 1000.0,
        source_ip,
        sport,
        dest_ip,
        dport,
        snd_cwnd,
        ssthresh,
        snd_wnd, srtt, rcv_wnd,
        data_len,
    );

        // snd_nxt {} snd_una {}  sock_cookie {}
        // snd_nxt,
        // snd_una,
        // sock_cookie,
        // "common_type {} common_flags {} common_preempt_count {} common_pid {}",
        // common_type,
        // common_flags,
        // common_preempt_count,
        // i32::from_be(common_pid)
        // mark
    }
}

fn format_socket(sock: socket) -> Option<SocketAddr> {
    unsafe {
        match sock.v6.sin6_family {
            AF_INET => {
                let addr = sock.v4;

                let sockaddrv4 = SocketAddrV4::new(
                    Ipv4Addr::new(addr.addr[0], addr.addr[1], addr.addr[2], addr.addr[3]),
                    u16::from_be(addr.port),
                );
                Some(SocketAddr::V4(sockaddrv4))
            }
            AF_INET6 => {
                let addr = sock.v6;

                let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    u16::from_be(addr.sin6_port),
                    u32::from_be(addr.sin6_flowinfo),
                    addr.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }
}
