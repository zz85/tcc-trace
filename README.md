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
BPF Tracepoint attached 1.6007ms
Waiting for Ctrl-C...
6302.613| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.55788 > 2607:f8b0:4009:814::200e.443 | snd_nxt 3034180476 snd_una 3034179959 snd_cwnd 10 ssthresh 2147483647 snd_wnd 65535 srtt 17133 rcv_wnd 62592 sock_cookie 490 length 0
6311.617| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.55788 > 2607:f8b0:4009:814::200e.443 | snd_nxt 3034180476 snd_una 3034180476 snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17116 rcv_wnd 62592 sock_cookie 490 length 2416
6311.639| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.55788 > 2607:f8b0:4009:814::200e.443 | snd_nxt 3034180476 snd_una 3034180476 snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17116 rcv_wnd 60288 sock_cookie 490 length 2416
6311.695| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.55788 > 2607:f8b0:4009:814::200e.443 | snd_nxt 3034180476 snd_una 3034180476 snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17116 rcv_wnd 57984 sock_cookie 490 length 1858
6330.893| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.55788 > 2607:f8b0:4009:814::200e.443 | snd_nxt 3034180744 snd_una 3034180476 snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17116 rcv_wnd 56704 sock_cookie 490 length 648
6331.401| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.55788 > 2607:f8b0:4009:814::200e.443 | snd_nxt 3034180775 snd_una 3034180744 snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17239 rcv_wnd 56704 sock_cookie 490 length 31
6343.370| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.55788 > 2607:f8b0:4009:814::200e.443 | snd_nxt 3034180775 snd_una 3034180744 snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17239 rcv_wnd 56704 sock_cookie 490 length 327
6343.391| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.55788 > 2607:f8b0:4009:814::200e.443 | snd_nxt 3034180775 snd_una 3034180744 snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17239 rcv_wnd 56704 sock_cookie 490 length 251
6343.455| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.55788 > 2607:f8b0:4009:814::200e.443 | snd_nxt 3034180775 snd_una 3034180744 snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17239 rcv_wnd 56704 sock_cookie 490 length 31
6343.482| 2600:1f16:bb9:f90b:5f12:132a:4ab3:6493.55788 > 2607:f8b0:4009:814::200e.443 | snd_nxt 3034180775 snd_una 3034180744 snd_cwnd 10 ssthresh 2147483647 snd_wnd 66816 srtt 17239 rcv_wnd 56704 sock_cookie 490 length 39
```

## Motivation
I built this because I wanted to find out how linux tcp congestion control is changing it's congestion window
[instead of guessing](https://github.com/sirupsen/initcwnd) and modprobe tcpprobe wasn't an option.
cwnd could also be retrieved via netlink (the way ss does it),
but https://www.brendangregg.com/blog/2018-03-22/tcp-tracepoints.html defintely convinced me tracing approach
is better. Reading and playing around with https://github.com/iovisor/bcc/ and reading the kernel code
also gave me some understanding how tracepoints work.


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
