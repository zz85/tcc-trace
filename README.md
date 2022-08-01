# tcc-trace

TCC Trace = TCP Congestion Control Tracing, implemented with ebpf using tcp/tcp_probe tracepoint using the aya rust library.

```
12:02:46 [INFO] tcc_trace: [tcc-trace/src/main.rs:43] Waiting for Ctrl-C...
12:02:48 [INFO] tcc_trace: [src/main.rs:76] tracepoint tcp_probe called
12:02:48 [INFO] tcc_trace: [src/main.rs:77] sport 54806 dport 443 mark 0 data len 0
12:02:48 [INFO] tcc_trace: [src/main.rs:78] snd_nxt 610998041 snd_una 610997524 snd_cwnd 10 ssthresh 2147483647
12:02:48 [INFO] tcc_trace: [src/main.rs:79] snd_wnd 65535 srtt 17109 rcv_wnd 62592 sock_cookie 140
12:02:48 [INFO] tcc_trace: [src/main.rs:76] tracepoint tcp_probe called
12:02:48 [INFO] tcc_trace: [src/main.rs:77] sport 54806 dport 443 mark 0 data len 2416
12:02:48 [INFO] tcc_trace: [src/main.rs:78] snd_nxt 610998041 snd_una 610998041 snd_cwnd 10 ssthresh 2147483647
12:02:48 [INFO] tcc_trace: [src/main.rs:79] snd_wnd 66816 srtt 17111 rcv_wnd 62592 sock_cookie 140
12:02:48 [INFO] tcc_trace: [src/main.rs:76] tracepoint tcp_probe called
12:02:48 [INFO] tcc_trace: [src/main.rs:77] sport 54806 dport 443 mark 0 data len 2416
12:02:48 [INFO] tcc_trace: [src/main.rs:78] snd_nxt 610998041 snd_una 610998041 snd_cwnd 10 ssthresh 2147483647
12:02:48 [INFO] tcc_trace: [src/main.rs:79] snd_wnd 66816 srtt 17111 rcv_wnd 60288 sock_cookie 140
12:02:48 [INFO] tcc_trace: [src/main.rs:76] tracepoint tcp_probe called
12:02:48 [INFO] tcc_trace: [src/main.rs:77] sport 54806 dport 443 mark 0 data len 1858
12:02:48 [INFO] tcc_trace: [src/main.rs:78] snd_nxt 610998041 snd_una 610998041 snd_cwnd 10 ssthresh 2147483647
12:02:48 [INFO] tcc_trace: [src/main.rs:79] snd_wnd 66816 srtt 17111 rcv_wnd 57984 sock_cookie 140
12:02:48 [INFO] tcc_trace: [src/main.rs:76] tracepoint tcp_probe called
12:02:48 [INFO] tcc_trace: [src/main.rs:77] sport 54806 dport 443 mark 0 data len 648
12:02:48 [INFO] tcc_trace: [src/main.rs:78] snd_nxt 610998309 snd_una 610998041 snd_cwnd 10 ssthresh 2147483647
12:02:48 [INFO] tcc_trace: [src/main.rs:79] snd_wnd 66816 srtt 17111 rcv_wnd 56704 sock_cookie 140
12:02:48 [INFO] tcc_trace: [src/main.rs:76] tracepoint tcp_probe called
12:02:48 [INFO] tcc_trace: [src/main.rs:77] sport 54806 dport 443 mark 0 data len 31
12:02:48 [INFO] tcc_trace: [src/main.rs:78] snd_nxt 610998340 snd_una 610998309 snd_cwnd 10 ssthresh 2147483647
```

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
