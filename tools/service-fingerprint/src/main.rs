//! service-fingerprint — connect to TCP ports and send protocol-specific
//! probes instead of a single blind read, so banners are more informative.
//!
//! Authorized use only: run against hosts you own or are permitted to test.

use clap::Parser;
use netutil::{expand_v4, exclude_v4, jsonl};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Parser, Debug)]
#[command(name = "service-fingerprint", version, about = "Protocol-aware TCP service fingerprinter")]
struct Args {
    /// Target IP address or CIDR block (e.g. 10.0.0.5 or 10.0.0.0/28)
    #[arg(short, long)]
    target: String,

    /// Port range, e.g. 1-1024
    #[arg(short, long, default_value = "1-1024")]
    range: String,

    /// Per-connection timeout in seconds
    #[arg(long, default_value_t = 3)]
    timeout: u64,

    /// Max concurrent in-flight probes
    #[arg(long, default_value_t = 200)]
    concurrency: usize,

    /// Exclude these targets (repeatable)
    #[arg(short = 'x', long = "exclude")]
    exclude: Vec<String>,

    /// Emit NDJSON instead of text
    #[arg(long)]
    json: bool,
}

/// Return a probe to send for a given port, or None to just read the banner.
fn probe_for(port: u16, host: &str) -> Option<Vec<u8>> {
    match port {
        80 | 8080 | 8000 | 8888 => {
            Some(format!("HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: s0t0n-fp\r\n\r\n").into_bytes())
        }
        25 | 587 | 465 => Some(b"EHLO s0t0n.local\r\n".to_vec()),
        // SSH, FTP, POP3, IMAP, Redis, MySQL... all greet first: just read.
        _ => None,
    }
}

fn label(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 | 587 | 465 => "smtp",
        53 => "dns",
        80 | 8000 | 8080 | 8888 => "http",
        110 => "pop3",
        143 => "imap",
        443 | 8443 => "https(raw)",
        3306 => "mysql",
        5432 => "postgres",
        6379 => "redis",
        _ => "tcp",
    }
}

fn sanitize(buf: &[u8]) -> String {
    let text = String::from_utf8_lossy(buf);
    text.lines()
        .take(4)
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join(" | ")
}

async fn fingerprint(ip: IpAddr, port: u16, to: Duration) -> Option<(String, String)> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = timeout(to, TcpStream::connect(addr)).await.ok()?.ok()?;

    if let Some(payload) = probe_for(port, &ip.to_string()) {
        let _ = timeout(to, stream.write_all(&payload)).await;
    }

    let mut buf = vec![0u8; 2048];
    let n = match timeout(to, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => n,
        _ => return Some((label(port).to_string(), String::new())),
    };
    Some((label(port).to_string(), sanitize(&buf[..n])))
}

fn parse_range(range: &str) -> Result<(u16, u16), String> {
    let (a, b) = range.split_once('-').ok_or("range must be start-end")?;
    let start: u16 = a.trim().parse().map_err(|_| "invalid start port")?;
    let end: u16 = b.trim().parse().map_err(|_| "invalid end port")?;
    if start > end {
        return Err("start port must be <= end port".into());
    }
    Ok((start, end))
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let (start, end) = match parse_range(&args.range) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    // CIDR, a.b.c.d-e range, or single IP, with optional exclusions.
    let targets: Vec<IpAddr> = match expand_v4(&args.target).and_then(|t| exclude_v4(t, &args.exclude)) {
        Ok(t) => t.into_iter().map(IpAddr::V4).collect(),
        Err(e) => {
            eprintln!("error: invalid target '{}': {e}", args.target);
            std::process::exit(1);
        }
    };

    let to = Duration::from_secs(args.timeout);
    let sem = Arc::new(Semaphore::new(args.concurrency));
    let mut handles = Vec::new();

    for ip in targets {
        for port in start..=end {
            let sem = Arc::clone(&sem);
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.unwrap();
                fingerprint(ip, port, to).await.map(|(svc, banner)| (ip, port, svc, banner))
            }));
        }
    }

    let json = args.json;
    for h in handles {
        if let Ok(Some((ip, port, svc, banner))) = h.await {
            if json {
                use jsonl::Val;
                println!("{}", jsonl::obj(&[
                    ("ip", Val::Str(&ip.to_string())),
                    ("port", Val::Int(port as i64)),
                    ("service", Val::Str(&svc)),
                    ("banner", Val::Str(&banner)),
                ]));
            } else if banner.is_empty() {
                println!("{ip}:{port}\topen ({svc}) — no banner");
            } else {
                println!("{ip}:{port}\topen ({svc}) — {banner}");
            }
        }
    }
}
