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

tcc-trace$ sudo target/release/tcc-trace --port 22

Filtering port: 22
TCP Probe attached via BPF Tracepoint in 1.456ms
Waiting for Ctrl-C...
k:22329653706207571 21.992ms | 0.002 ms| 172.31.46.125.22 > 52.95.4.0.29736 | snd_cwnd 10 ssthresh 46 snd_wnd 261632 srtt 77035 rcv_wnd 56576 length 0
k:22329653729933673 45.719ms | 0.001 ms| 172.31.46.125.22 > 52.95.4.0.9249 | snd_cwnd 10 ssthresh 24 snd_wnd 131072 srtt 72946 rcv_wnd 93952 length 0
k:22329653735191663 50.977ms | 5.237 ms| 172.31.46.125.22 > 52.95.4.0.9249 | snd_cwnd 11 ssthresh 24 snd_wnd 131072 srtt 72867 rcv_wnd 93952 length 0
k:22329653735996878 51.782ms | 29.746 ms| 172.31.46.125.22 > 52.95.4.0.29736 | snd_cwnd 11 ssthresh 46 snd_wnd 261632 srtt 76853 rcv_wnd 56576 length 0
k:22329653742158975 57.944ms | 35.912 ms| 172.31.46.125.22 > 52.95.4.0.29736 | snd_cwnd 12 ssthresh 46 snd_wnd 261632 srtt 77035 rcv_wnd 56576 length 0
k:22329653747879769 63.665ms | 17.925 ms| 172.31.46.125.22 > 52.95.4.0.9249 | snd_cwnd 12 ssthresh 24 snd_wnd 131072 srtt 72908 rcv_wnd 93952 length 0
k:22329653754174690 69.960ms | 47.925 ms| 172.31.46.125.22 > 52.95.4.0.29736 | snd_cwnd 13 ssthresh 46 snd_wnd 261632 srtt 77432 rcv_wnd 56576 length 0
k:22329653757416239 73.201ms | 27.458 ms| 172.31.46.125.22 > 52.95.4.0.9249 | snd_cwnd 13 ssthresh 24 snd_wnd 131072 srtt 72714 rcv_wnd 93952 length 0
k:22329653760128801 75.914ms | 30.170 ms| 172.31.46.125.22 > 52.95.4.0.9249 | snd_cwnd 14 ssthresh 24 snd_wnd 131072 srtt 72765 rcv_wnd 93952 length 0
k:22329653760940866 76.726ms | 54.689 ms| 172.31.46.125.22 > 52.95.4.0.29736 | snd_cwnd 14 ssthresh 46 snd_wnd 261632 srtt 77465 rcv_wnd 56576 length 0
k:22329653766101023 81.886ms | 59.883 ms| 172.31.46.125.22 > 52.95.4.0.29736 | snd_cwnd 15 ssthresh 46 snd_wnd 261632 srtt 77368 rcv_wnd 56576 length 0
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
