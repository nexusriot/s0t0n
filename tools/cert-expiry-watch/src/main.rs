//! cert-expiry-watch — check the leaf certificate of each host in a list and
//! exit non-zero if any is already expired or expires within --days. Built on
//! the tls-inspect library; cron-friendly. Authorized use only.
//!
//! Host list: one `host` or `host:port` per line ('#' comments ignored).

use clap::Parser;
use std::time::Duration;
use tls_inspect::{inspect, now_secs};

#[derive(Parser, Debug)]
#[command(name = "cert-expiry-watch", version, about = "Warn on soon-to-expire TLS certs")]
struct Args {
    /// File with one host or host:port per line
    hosts_file: String,
    /// Warn/fail threshold in days
    #[arg(short, long, default_value_t = 30)]
    days: i64,
    /// Per-host timeout (seconds)
    #[arg(long, default_value_t = 8)]
    timeout: u64,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let content = match std::fs::read_to_string(&args.hosts_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot read {}: {e}", args.hosts_file);
            std::process::exit(2);
        }
    };

    let now = now_secs();
    let mut breaching = 0;
    let mut errors = 0;

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (host, port) = match line.split_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().unwrap_or(443)),
            None => (line.to_string(), 443u16),
        };

        match inspect(&host, port, &host, Duration::from_secs(args.timeout)).await {
            Ok(insp) => match insp.certs.first() {
                Some(leaf) => {
                    let days = leaf.days_until_expiry(now);
                    let flag = if leaf.is_expired(now) {
                        breaching += 1;
                        "EXPIRED"
                    } else if days <= args.days {
                        breaching += 1;
                        "WARN"
                    } else {
                        "OK"
                    };
                    println!("{:<7} {}:{}  {} days  [{}]", flag, host, port, days, leaf.subject);
                }
                None => {
                    errors += 1;
                    println!("ERROR   {host}:{port}  no certificate presented");
                }
            },
            Err(e) => {
                errors += 1;
                println!("ERROR   {host}:{port}  {e}");
            }
        }
    }

    println!("\n{breaching} cert(s) within {} days, {errors} error(s).", args.days);
    if breaching > 0 {
        std::process::exit(1);
    }
}
