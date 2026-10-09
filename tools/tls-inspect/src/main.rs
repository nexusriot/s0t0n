//! tls-inspect CLI — print the certificate chain of a TLS service.

use anyhow::Result;
use clap::Parser;
use std::time::Duration;
use tls_inspect::{inspect, now_secs};

#[derive(Parser, Debug)]
#[command(name = "tls-inspect", version, about = "Dump a server's TLS certificate chain")]
struct Args {
    /// Host to connect to (also used as SNI unless --sni given)
    host: String,
    #[arg(short, long, default_value_t = 443)]
    port: u16,
    #[arg(long)]
    sni: Option<String>,
    #[arg(long, default_value_t = 8)]
    timeout: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let sni = args.sni.clone().unwrap_or_else(|| args.host.clone());
    let insp = inspect(&args.host, args.port, &sni, Duration::from_secs(args.timeout)).await?;
    let now = now_secs();

    println!("Connected to {}:{} (SNI: {sni})", args.host, args.port);
    if let Some(p) = &insp.protocol {
        println!("Protocol : {p}");
    }
    if let Some(c) = &insp.cipher {
        println!("Cipher   : {c}");
    }
    if let Some(a) = &insp.alpn {
        println!("ALPN     : {a}");
    }
    println!("Chain    : {} certificate(s)", insp.certs.len());
    for (i, c) in insp.certs.iter().enumerate() {
        println!("  [{i}] subject : {}", c.subject);
        println!("      issuer  : {}", c.issuer);
        println!("      serial  : {}", c.serial);
        println!("      valid   : {} -> {} ({} days left)",
                 c.not_before, c.not_after, c.days_until_expiry(now));
        if c.is_expired(now) {
            println!("      status  : EXPIRED");
        }
        if !c.sans.is_empty() {
            println!("      SAN     : {}", c.sans.join(", "));
        }
    }
    Ok(())
}
