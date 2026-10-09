//! os-fingerprint — send an ICMP echo and guess the remote OS family from the
//! reply's IP TTL (hosts start the TTL at a well-known value and routers
//! decrement it). A coarse heuristic, not a substitute for nmap -O. Needs
//! raw-socket privileges (sudo / CAP_NET_RAW). Authorized use only.

use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Map an observed TTL to the most likely initial TTL and OS family.
fn classify(ttl: u8) -> (u8, &'static str, u8) {
    // (initial_ttl, family, hops_away)
    let candidates = [(64u8, "Linux/Unix/macOS"), (128, "Windows"), (255, "network device/BSD"), (32, "legacy/Windows 9x")];
    let mut best = (255u8, "unknown", 0u8);
    let mut best_dist = u16::MAX;
    for (init, fam) in candidates {
        if ttl <= init {
            let dist = (init - ttl) as u16;
            if dist < best_dist {
                best_dist = dist;
                best = (init, fam, (init - ttl));
            }
        }
    }
    best
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += ((data[i] as u32) << 8) | data[i + 1] as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

fn build_echo(id: u16, seq: u16) -> Vec<u8> {
    let mut pkt = vec![8u8, 0, 0, 0, (id >> 8) as u8, id as u8, (seq >> 8) as u8, seq as u8];
    pkt.extend_from_slice(b"s0t0n-osfp");
    let c = checksum(&pkt);
    pkt[2] = (c >> 8) as u8;
    pkt[3] = c as u8;
    pkt
}

fn probe(target: Ipv4Addr, timeout: Duration) -> std::io::Result<Option<u8>> {
    let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
    sock.set_read_timeout(Some(timeout))?;
    let dst: SocketAddr = SocketAddr::new(IpAddr::V4(target), 0);
    let pkt = build_echo(0xBEEF, 1);
    sock.send_to(&pkt, &dst.into())?;

    let deadline = Instant::now() + timeout;
    let mut buf = [MaybeUninit::<u8>::uninit(); 1500];
    while Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) if n >= 20 => {
                let data: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
                // Raw IPv4 socket delivers the IP header; TTL is byte 8,
                // ICMP type is at the start of the payload (ihl*4).
                let ihl = ((data[0] & 0x0f) as usize) * 4;
                if n >= ihl + 1 && data[ihl] == 0 {
                    // ICMP Echo Reply (type 0)
                    return Ok(Some(data[8]));
                }
            }
            Ok(_) => continue,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e),
        }
    }
    Ok(None)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: sudo {} <ipv4>", args[0]);
        std::process::exit(1);
    }
    let target: Ipv4Addr = match args[1].parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("invalid IPv4: {}", args[1]);
            std::process::exit(1);
        }
    };

    match probe(target, Duration::from_secs(3)) {
        Ok(Some(ttl)) => {
            let (init, fam, hops) = classify(ttl);
            println!("{target}: TTL={ttl}  ~initial={init}  hops≈{hops}  guess: {fam}");
        }
        Ok(None) => {
            eprintln!("{target}: no ICMP reply (filtered or down)");
            std::process::exit(2);
        }
        Err(e) => {
            eprintln!("error (need root/CAP_NET_RAW?): {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ttl_classification() {
        assert_eq!(classify(64).1, "Linux/Unix/macOS");
        assert_eq!(classify(57).1, "Linux/Unix/macOS"); // 7 hops
        assert_eq!(classify(128).1, "Windows");
        assert_eq!(classify(120).1, "Windows");
        assert_eq!(classify(250).1, "network device/BSD");
    }
    #[test]
    fn checksum_nonzero() {
        assert_ne!(checksum(&[8, 0, 0, 0, 1, 2, 3, 4]), 0);
    }
}
