//! ipv6-sweep — liveness sweep across an IPv6 CIDR by TCP-connecting to a small
//! port list (ICMPv6 would need raw sockets). Closes netutil's IPv6-iteration
//! TODO. Uses the shared scanengine. Authorized use only.

use clap::Parser;
use netutil::Cidr6;
use scanengine::{run, Config};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Parser, Debug)]
#[command(name = "ipv6-sweep", version, about = "TCP-connect liveness sweep over an IPv6 CIDR")]
struct Args {
    /// IPv6 CIDR, e.g. 2001:db8::/120 (prefix must be >= 104 to bound the range)
    cidr: String,
    /// Ports to try per host (comma-separated)
    #[arg(short, long, default_value = "80,443,22")]
    ports: String,
    #[arg(long, default_value_t = 3)]
    timeout: u64,
    #[arg(long, default_value_t = 256)]
    concurrency: usize,
    #[arg(long, default_value_t = 0)]
    rate: u32,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let cidr = match Cidr6::parse(&args.cidr) {
        Ok(c) => c,
        Err(e) => { eprintln!("error: {e}"); std::process::exit(1); }
    };
    if cidr.prefix() < 104 {
        eprintln!("error: prefix /{} is too large to sweep; use /104 or longer", cidr.prefix());
        std::process::exit(1);
    }
    let n = cidr.len().unwrap_or(u128::MAX);
    let hosts: Vec<Ipv6Addr> = cidr.hosts().take(n as usize).collect();
    let ports: Vec<u16> = args.ports.split(',').filter_map(|p| p.trim().parse().ok()).collect();

    let mut jobs: Vec<(Ipv6Addr, u16)> = Vec::new();
    for h in &hosts {
        for p in &ports {
            jobs.push((*h, *p));
        }
    }

    let to = Duration::from_secs(args.timeout);
    let cfg = Config { concurrency: args.concurrency, rate_per_sec: args.rate, retries: 0 };
    eprintln!("Sweeping {} address(es) x {} port(s) ...", hosts.len(), ports.len());
    let results = run(jobs, cfg, move |(ip, port)| async move {
        let addr = SocketAddr::new(IpAddr::V6(ip), port);
        match timeout(to, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => Some((ip, port)),
            _ => None,
        }
    }).await;

    let mut up = 0;
    for (ip, port) in results.into_iter().flatten() {
        up += 1;
        println!("[{ip}]:{port}\topen");
    }
    eprintln!("\n{up} open endpoint(s).");
}
