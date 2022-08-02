use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use log::info;
use simplelog::{ColorChoice, ConfigBuilder, LevelFilter, TermLogger, TerminalMode};
use tcc_trace_common::{socket, TcpProbe, AF_INET, AF_INET6};
use tokio::{signal, task};

#[derive(Debug, Parser)]
struct Opt {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    TermLogger::init(
        LevelFilter::Debug,
        ConfigBuilder::new()
            .set_target_level(LevelFilter::Error)
            .set_location_level(LevelFilter::Error)
            .build(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )?;

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
    let program: &mut TracePoint = bpf.program_mut("tcc_trace").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp", "tcp_probe")?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.map_mut("TCP_PROBES")?)?;
    for cpu_id in online_cpus()? {
        // println!("CPU {}", cpu_id);
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            //

            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                //

                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const TcpProbe;
                    //

                    let probe = unsafe { ptr.read_unaligned() };

                    info!(
                        "[{:?} -> {:?}] {} -> {}, Len: [{}]",
                        get(probe.saddr).unwrap(),
                        get(probe.daddr).unwrap(),
                        probe.sport,
                        probe.dport,
                        probe.data_len,
                    );
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

fn get(sock: socket) -> Option<SocketAddr> {
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
