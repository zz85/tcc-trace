use std::mem::{self, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::prelude::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::HashMap;
use aya::programs::{tc, SchedClassifier, TcAttachType, TracePoint};
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tcc_trace_common::{
    socket, tcp_info, TcpProbe, TracePayload, AF_INET, AF_INET6, PORT_FILTER, PORT_MAP_FROM,
    PORT_MAP_TO,
};
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

    /// Port mapped from
    #[clap(short = 'f', long, value_parser)]
    map_from: Option<u16>,

    /// Port mapped to
    #[clap(short = 't', long, value_parser)]
    map_to: Option<u16>,

    /// TCP Probe HTTP Server
    #[clap(short, long, value_parser)]
    http_server: bool,

    #[clap(long, value_parser)]
    if_name: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let Opt {
        port,
        ip,
        debug,
        map_from,
        map_to,
        http_server,
        if_name,
    } = Opt::parse();

    if http_server {
        std::thread::spawn(|| {
            start_tcpinfo_server().map_err(|e| {
                println!("Error {:?}", e);
                e
            });
        });
    }

    if let Some(ip) = ip {
        println!("Filtering IP: {:?}", ip);
    }

    if let Some(port) = port {
        println!("Filtering port: {}", port);
    }

    if (None, None) == (port, ip) {
        println!("No filters...");
    }

    println!("Map from to Map to {:?} -> {:?}", map_from, map_to);

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

    let tcprog: &mut SchedClassifier = bpf.program_mut("tc_cls_ingress").unwrap().try_into()?;
    tcprog.load()?;

    let ifname = match if_name {
        Some(name) => name,
        None => "lo".to_string(),
    };
    let _ = tc::qdisc_add_clsact(&ifname);
    tcprog.attach(&ifname, TcAttachType::Ingress, 0)?;
    tcprog.attach(&ifname, TcAttachType::Egress, 0)?;

    let mut handler = Handler::new(ip, port);
    let event_count = Arc::new(AtomicU64::new(0));
    let filtered_count = Arc::new(AtomicU64::new(0));
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("TCP_PROBES")?)?;
    let mut tcc_settings = HashMap::try_from(bpf.map_mut("TCC_SETTINGS")?)?;
    let mut matchlist_v4 = HashMap::try_from(bpf.map_mut("MATCHLIST_V4")?)?;

    if let Some(ip) = ip {
        if let IpAddr::V4(ip4) = ip {
            let ip4: u32 = ip4.into();

            matchlist_v4.insert(ip4, 1u8, 0)?;
        }
    }

    if let Some(port) = port {
        tcc_settings.insert(PORT_FILTER, port as u64, 0)?;
    }

    if let Some(map_from) = map_from {
        tcc_settings.insert(PORT_MAP_FROM, map_from as u64, 0)?;
    }

    if let Some(map_to) = map_to {
        tcc_settings.insert(PORT_MAP_TO, map_to as u64, 0)?;
    }

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
    cache: std::collections::HashMap<(SocketAddr, SocketAddr), u64>,
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
                println!("shouldn't happen!");
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

        let first_seen = self.cache.entry((source, dest)).or_insert(time);
        let connection_duration = Duration::from_nanos(time - *first_seen);

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

        let bytes_in_flight = snd_nxt - snd_una;

        println!(
        "{:.5}s | {:.3} ms| {:?}.{} > {:?}.{} | snd_cwnd {} ssthresh {} snd_wnd {} srtt {:3} rcv_wnd {} length {} bytes in flight {}",
        offset_time as f64 / 1e9 ,
        connection_duration.as_secs_f64() * 1000.0,
        source_ip,
        sport,
        dest_ip,
        dport,
        snd_cwnd,
        ssthresh,
        snd_wnd, srtt, rcv_wnd,
        data_len,
        bytes_in_flight,
    );

        let info = TcpinfoEvent {
            time: offset_time as f64 / 1e9,
            snd_cwnd: snd_cwnd,
            snd_ssthresh: ssthresh,
            bytes_sent: data_len.into(),
        };

        let json = serde_json::to_string(&info).unwrap();
        println!("{}", json);

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

fn start_tcpinfo_server() -> Result<(), anyhow::Error> {
    use socket2::{Domain, Socket, Type};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    // Create a TCP listener bound to two addresses.
    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;

    socket.set_reuse_port(true)?;

    use nix::sys::socket::sockopt::TcpCongestion;
    use nix::sys::socket::SetSockOpt;
    use std::ffi::OsString;

    let congestion = TcpCongestion {};
    congestion.set(socket.as_raw_fd(), &OsString::from("cubic"))?;

    /*
    unsafe {
        setsockopt(
            self.as_raw(),
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            reuse as c_int,
        )
    }
    */

    let address: SocketAddr = "[::]:12345".parse().unwrap();
    socket.bind(&address.into())?;
    socket.listen(128)?;

    let listener: TcpListener = socket.into();

    let blank = " ".repeat(1024);

    while let Ok((mut stream, peer)) = listener.accept() {
        println!("{:?} {:?}", stream, peer);
        let mut buf = [0 as u8; 1024]; // using 50 byte buffer
        let fd = stream.as_raw_fd();

        /*
        struct tcp_info tcpi;
        socklen_t len = sizeof(struct tcp_info);
        int rc = getsockopt(c->fd, IPPROTO_TCP, TCP_INFO,
                        &tcpi, &len);

            tcp_info_length = sizeof(tcp_info);
         ( getsockopt( tcp_work_socket, SOL_TCP, TCP_INFO, (void *)&tcp_info, &tcp_info_length ) == 0 ) {
        */

        let start = Instant::now();

        while match stream.read(&mut buf) {
            Ok(size) => {
                if size == 0 {
                    false
                } else {
                    println!("Got something {}", size);
                    for i in 0..2000 {
                        // perhaps we can switch this out for the nix crate
                        let mut tcp_info_length = mem::size_of::<tcp_info>() as _;
                        let info = unsafe {
                            let mut payload: MaybeUninit<tcp_info> = MaybeUninit::uninit();
                            let ret = libc::getsockopt(
                                fd,
                                libc::SOL_TCP,
                                libc::TCP_INFO,
                                payload.as_mut_ptr().cast(),
                                &mut tcp_info_length,
                            );

                            if ret == -1 {
                                return Err(std::io::Error::last_os_error().into());
                            }

                            payload.assume_init()
                        };

                        let debug = format!("info {:?}", info);

                        if i % 1000 == 0 {
                            println!("{}", debug);
                        }

                        let info = TcpinfoEvent {
                            time: start.elapsed().as_secs_f64() * 1000.0,
                            snd_cwnd: info.tcpi_snd_cwnd,
                            snd_ssthresh: info.tcpi_snd_ssthresh,
                            bytes_sent: info.tcpi_bytes_sent,
                        };

                        let json = serde_json::to_string(&info)?;
                        stream.write(json.as_bytes())?;
                        stream.write(b"\n")?;
                        for i in 0..10 {
                            stream.write(blank.as_bytes())?;
                        }
                        stream.write(b"\n")?;
                        stream.flush()?;
                    }
                    stream.shutdown(std::net::Shutdown::Both)?;

                    true
                }
            }
            Err(_) => {
                println!(
                    "An error occurred, terminating connection with {}",
                    stream.peer_addr().unwrap()
                );
                stream.shutdown(std::net::Shutdown::Both).unwrap();
                false
            }
        } {}
    }

    Ok(())
}

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
/// streaming event to a client
struct TcpinfoEvent {
    time: f64,
    snd_cwnd: u32,
    snd_ssthresh: u32,
    bytes_sent: u64,
}
