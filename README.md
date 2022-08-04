# tcc-trace

### TCC Trace = TCP Congestion Control Tracing
implemented with ebpf using tcp/tcp_probe tracepoint using the aya rust library.

```
tcc-trace$ sudo target/release/tcc-trace --help
tcc-trace 
Congestion Control tracer for TCP connections

USAGE:
    tcc-trace [OPTIONS]

OPTIONS:
    -h, --help           Print help information
    -i, --ip <IP>        Filter by ip (shows all ips by default)
    -p, --port <PORT>    Filter by port number (display all ports by default)

tcc-trace$ sudo target/release/tcc-trace --port 443

Filtering port: 443
TCP Probe attached via BPF Tracepoint in 1.452ms
Waiting for Ctrl-C...
1.72180s | 0.000 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 65535 srtt 16980 rcv_wnd 62592 length 0
1.73081s | 9.009 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 16976 rcv_wnd 62592 length 2416
1.73084s | 9.042 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 16976 rcv_wnd 60288 length 2416
1.73087s | 9.076 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 16976 rcv_wnd 57984 length 1858
1.74927s | 27.476 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 16976 rcv_wnd 56704 length 648
1.74999s | 28.188 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17001 rcv_wnd 56704 length 31
1.76130s | 39.498 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17001 rcv_wnd 56704 length 327
1.76134s | 39.546 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17001 rcv_wnd 56704 length 251
1.76138s | 39.579 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17001 rcv_wnd 56704 length 31
1.76144s | 39.640 ms| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.51114 > 2607:f8b0:4009:806::200e.443 | snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17001 rc
```

## Motivation
I built this because I wanted to find out how linux tcp congestion control is changing it's congestion window
[instead of guessing](https://github.com/sirupsen/initcwnd) and modprobe tcpprobe wasn't an option.
cwnd could also be retrieved via netlink (the way ss does it),
but https://www.brendangregg.com/blog/2018-03-22/tcp-tracepoints.html defintely convinced me tracing approach
is better. Reading and playing around with https://github.com/iovisor/bcc/ and reading the kernel code
also gave me some understanding how tracepoints work.

## Done
- [x] Basic TCP Probing via Tracepoint
- [x] Display cwnd, ssthresh, sttt, length
- [x] Filtering based on IP or port number

## TODOs
- [ ] Test binaries on different hosts
- [ ] Logging to trace file
- [ ] Nicer colors, UI
- [ ] Identify and run timer for individual connections
- [ ] Trace other pieces of connection properties
- [ ] In kernel filtering optimization

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag

## Build Userspace

```bash
cargo build
```

## Run

```bash
cargo xtask run
```
