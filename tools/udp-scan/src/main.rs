//! udp-scan — probe common UDP services with protocol-specific payloads. A UDP
//! response marks the port open; silence is reported as open|filtered (UDP
//! gives no RST). Uses the shared scanengine. Authorized use only.

use clap::Parser;
use netutil::{exclude_v4, expand_v4, jsonl};
use scanengine::{run, Config};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

#[derive(Parser, Debug)]
#[command(name = "udp-scan", version, about = "UDP service scanner")]
struct Args {
    /// Target: CIDR, a.b.c.d-e range, or single IP
    #[arg(short, long)]
    target: String,
    /// Exclude these targets (repeatable)
    #[arg(short = 'x', long = "exclude")]
    exclude: Vec<String>,
    /// Only probe these UDP ports (comma-separated); default: all known
    #[arg(short, long)]
    ports: Option<String>,
    #[arg(long, default_value_t = 2)]
    timeout: u64,
    #[arg(long, default_value_t = 200)]
    concurrency: usize,
    /// Global probes per second (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    rate: u32,
    #[arg(long)]
    json: bool,
}

/// Known UDP probes: (port, service, payload).
fn probes() -> Vec<(u16, &'static str, Vec<u8>)> {
    vec![
        (53, "dns", dns_query()),
        (123, "ntp", ntp_query()),
        (161, "snmp", snmp_get()),
        (137, "netbios-ns", netbios_query()),
        (1900, "ssdp", ssdp_msearch()),
        (5353, "mdns", dns_query()),
        (500, "ike", ike_probe()),
    ]
}

fn dns_query() -> Vec<u8> {
    // Standard A query for "version.bind" CH would be ideal; use a simple
    // query for "." root NS to elicit a response from resolvers.
    let mut p = vec![0x13, 0x37, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    p.push(0x00); // root name
    p.extend_from_slice(&[0x00, 0x02, 0x00, 0x01]); // NS, IN
    p
}
fn ntp_query() -> Vec<u8> {
    let mut p = vec![0x1b];
    p.extend(std::iter::repeat(0u8).take(47));
    p
}
fn snmp_get() -> Vec<u8> {
    // SNMPv2c GET sysDescr.0, community "public"
    vec![0x30,0x26,0x02,0x01,0x01,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xa0,0x19,0x02,
         0x04,0x00,0x00,0x00,0x01,0x02,0x01,0x00,0x02,0x01,0x00,0x30,0x0b,0x30,0x09,0x06,
         0x05,0x2b,0x06,0x01,0x02,0x01,0x05,0x00]
}
fn netbios_query() -> Vec<u8> {
    let mut p = vec![0x13,0x37,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00];
    // Encoded '*' name query (node status)
    p.push(0x20);
    p.extend_from_slice(b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    p.extend_from_slice(&[0x00, 0x00, 0x21, 0x00, 0x01]);
    p
}
fn ssdp_msearch() -> Vec<u8> {
    b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n".to_vec()
}
fn ike_probe() -> Vec<u8> {
    // Minimal ISAKMP header with a zero responder cookie.
    let mut p = vec![0u8; 28];
    p[16] = 0x01; // next payload SA
    p[17] = 0x10; // version 1.0
    p[18] = 0x02; // exchange type: identity protection
    p
}

async fn probe(ip: IpAddr, port: u16, svc: &'static str, payload: Vec<u8>, to: Duration)
    -> Option<(IpAddr, u16, &'static str, bool)>
{
    let bind = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let sock = UdpSocket::bind(bind).await.ok()?;
    sock.connect(SocketAddr::new(ip, port)).await.ok()?;
    sock.send(&payload).await.ok()?;
    let mut buf = [0u8; 2048];
    match timeout(to, sock.recv(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => Some((ip, port, svc, true)),   // definitely open
        _ => Some((ip, port, svc, false)),                   // open|filtered
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let targets: Vec<IpAddr> = match expand_v4(&args.target).and_then(|t| exclude_v4(t, &args.exclude)) {
        Ok(t) => t.into_iter().map(IpAddr::V4).collect(),
        Err(e) => { eprintln!("error: {e}"); std::process::exit(1); }
    };

    let all = probes();
    let wanted: Option<Vec<u16>> = args.ports.as_ref().map(|s|
        s.split(',').filter_map(|p| p.trim().parse().ok()).collect());

    let mut jobs: Vec<(IpAddr, u16, &'static str, Vec<u8>)> = Vec::new();
    for ip in &targets {
        for (port, svc, payload) in &all {
            if let Some(w) = &wanted {
                if !w.contains(port) { continue; }
            }
            jobs.push((*ip, *port, *svc, payload.clone()));
        }
    }

    let to = Duration::from_secs(args.timeout);
    let cfg = Config { concurrency: args.concurrency, rate_per_sec: args.rate, retries: 0 };
    let results = run(jobs, cfg, move |(ip, port, svc, payload)| {
        probe(ip, port, svc, payload, to)
    }).await;

    let json = args.json;
    for r in results.into_iter().flatten() {
        let (ip, port, svc, responded) = r;
        let state = if responded { "open" } else { "open|filtered" };
        if json {
            use jsonl::Val;
            println!("{}", jsonl::obj(&[
                ("ip", Val::Str(&ip.to_string())),
                ("port", Val::Int(port as i64)),
                ("proto", Val::Str("udp")),
                ("service", Val::Str(svc)),
                ("state", Val::Str(state)),
            ]));
        } else if responded {
            println!("{ip}:{port}/udp\t{state} ({svc})");
        }
    }
}
