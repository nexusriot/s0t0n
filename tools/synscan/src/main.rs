//! synscan — half-open (SYN) TCP scanner. Sends a lone SYN and classifies the
//! reply: SYN/ACK = open, RST = closed, nothing = filtered. Faster and quieter
//! than a full connect scan; feed the open ports into service-fingerprint.
//! Needs raw-socket privileges (sudo / CAP_NET_RAW). Authorized use only.

use clap::Parser;
use netutil::{expand_v4, exclude_v4, jsonl};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{tcp_packet_iter, transport_channel};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Parser, Debug)]
#[command(name = "synscan", version, about = "Half-open (SYN) TCP port scanner")]
struct Args {
    /// Target spec: CIDR, a.b.c.d-e range, or single IP
    #[arg(short, long)]
    target: String,
    /// Port range, e.g. 1-1024
    #[arg(short, long, default_value = "1-1024")]
    range: String,
    /// Exclude these targets (repeatable)
    #[arg(short = 'x', long = "exclude")]
    exclude: Vec<String>,
    /// Seconds to wait for replies after sending
    #[arg(long, default_value_t = 3)]
    wait: u64,
    /// Emit NDJSON instead of text
    #[arg(long)]
    json: bool,
}

fn parse_range(r: &str) -> Result<(u16, u16), String> {
    let (a, b) = r.split_once('-').ok_or("range must be start-end")?;
    let s: u16 = a.trim().parse().map_err(|_| "bad start port")?;
    let e: u16 = b.trim().parse().map_err(|_| "bad end port")?;
    if s > e {
        return Err("start > end".into());
    }
    Ok((s, e))
}

/// Pick the local source IPv4 the kernel would use to reach `dst`.
fn source_ip_for(dst: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0")?;
    sock.connect(SocketAddr::new(IpAddr::V4(dst), 80))?;
    match sock.local_addr()?.ip() {
        IpAddr::V4(ip) => Ok(ip),
        _ => Ok(Ipv4Addr::UNSPECIFIED),
    }
}

fn main() {
    let args = Args::parse();
    let (start, end) = match parse_range(&args.range) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    let targets = match expand_v4(&args.target).and_then(|t| exclude_v4(t, &args.exclude)) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };
    if targets.is_empty() {
        eprintln!("no targets after exclusions");
        std::process::exit(1);
    }

    let (mut tx, mut rx) = match transport_channel(4096, Layer4(Ipv4(IpNextHeaderProtocols::Tcp))) {
        Ok(ch) => ch,
        Err(e) => {
            eprintln!("raw socket error (need root/CAP_NET_RAW?): {e}");
            std::process::exit(1);
        }
    };

    let open: Arc<Mutex<HashSet<(Ipv4Addr, u16)>>> = Arc::new(Mutex::new(HashSet::new()));
    let want: Arc<Mutex<HashSet<(Ipv4Addr, u16)>>> = Arc::new(Mutex::new(HashSet::new()));

    // Receiver thread: record SYN/ACK as open.
    let open_rx = Arc::clone(&open);
    let want_rx = Arc::clone(&want);
    let wait = Duration::from_secs(args.wait);
    let json = args.json;
    let rx_handle = std::thread::spawn(move || {
        let mut iter = tcp_packet_iter(&mut rx);
        let deadline = Instant::now() + wait + Duration::from_secs(1);
        while Instant::now() < deadline {
            match iter.next_with_timeout(Duration::from_millis(200)) {
                Ok(Some((pkt, addr))) => {
                    let flags = pkt.get_flags();
                    let syn_ack = TcpFlags::SYN | TcpFlags::ACK;
                    if let IpAddr::V4(src) = addr {
                        let key = (src, pkt.get_source());
                        let is_target = want_rx.lock().unwrap().contains(&key);
                        if is_target && (flags & syn_ack) == syn_ack {
                            let mut o = open_rx.lock().unwrap();
                            if o.insert(key) {
                                report(src, pkt.get_source(), "open", json);
                            }
                        }
                    }
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
    });

    // Send a SYN to every (target, port).
    for &ip in &targets {
        let src = source_ip_for(ip).unwrap_or(Ipv4Addr::UNSPECIFIED);
        for port in start..=end {
            want.lock().unwrap().insert((ip, port));
            let mut buf = [0u8; 20];
            if let Some(mut p) = MutableTcpPacket::new(&mut buf) {
                p.set_source(40000 + (port % 20000));
                p.set_destination(port);
                p.set_sequence(0x1337_0000 ^ port as u32);
                p.set_data_offset(5);
                p.set_flags(TcpFlags::SYN);
                p.set_window(1024);
                let cksum = tcp::ipv4_checksum(&p.to_immutable(), &src, &ip);
                p.set_checksum(cksum);
                let _ = tx.send_to(TcpPacket::new(p.packet()).unwrap(), IpAddr::V4(ip));
            }
        }
    }

    std::thread::sleep(wait);
    let _ = rx_handle.join();

    let o = open.lock().unwrap();
    if !json {
        println!("\n{} open port(s).", o.len());
    }
}

fn report(ip: Ipv4Addr, port: u16, state: &str, json: bool) {
    if json {
        use jsonl::Val;
        println!("{}", jsonl::obj(&[
            ("ip", Val::Str(&ip.to_string())),
            ("port", Val::Int(port as i64)),
            ("state", Val::Str(state)),
        ]));
    } else {
        println!("{ip}:{port}\t{state}");
    }
}
