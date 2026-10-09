//! tls-ciphers — enumerate which TLS protocol versions and cipher suites a
//! server actually accepts, by sending one ClientHello per candidate and
//! reading the ServerHello. Flags weak/legacy suites. The TLS analogue of
//! ssh-audit-lite. Raw sockets (no TLS library). Authorized use only.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// (id bytes, name, weak-reason or "")
struct Suite(u16, &'static str, &'static str);

const SUITES: &[Suite] = &[
    // TLS 1.3
    Suite(0x1301, "TLS_AES_128_GCM_SHA256", ""),
    Suite(0x1302, "TLS_AES_256_GCM_SHA384", ""),
    Suite(0x1303, "TLS_CHACHA20_POLY1305_SHA256", ""),
    // TLS 1.2 AEAD (good)
    Suite(0xc02b, "ECDHE-ECDSA-AES128-GCM-SHA256", ""),
    Suite(0xc02f, "ECDHE-RSA-AES128-GCM-SHA256", ""),
    Suite(0xc02c, "ECDHE-ECDSA-AES256-GCM-SHA384", ""),
    Suite(0xc030, "ECDHE-RSA-AES256-GCM-SHA384", ""),
    Suite(0xcca9, "ECDHE-ECDSA-CHACHA20-POLY1305", ""),
    Suite(0xcca8, "ECDHE-RSA-CHACHA20-POLY1305", ""),
    // CBC / RSA kx (legacy/weak)
    Suite(0xc027, "ECDHE-RSA-AES128-SHA256", "CBC mode"),
    Suite(0xc013, "ECDHE-RSA-AES128-SHA", "CBC + SHA-1"),
    Suite(0xc014, "ECDHE-RSA-AES256-SHA", "CBC + SHA-1"),
    Suite(0x009c, "AES128-GCM-SHA256", "static RSA kx (no PFS)"),
    Suite(0x009d, "AES256-GCM-SHA384", "static RSA kx (no PFS)"),
    Suite(0x002f, "AES128-SHA", "static RSA + CBC + SHA-1"),
    Suite(0x0035, "AES256-SHA", "static RSA + CBC + SHA-1"),
    Suite(0x000a, "DES-CBC3-SHA", "3DES (weak)"),
    Suite(0x0005, "RC4-SHA", "RC4 (broken)"),
    Suite(0x0004, "RC4-MD5", "RC4 + MD5 (broken)"),
];

fn u16b(n: usize) -> [u8; 2] { [(n >> 8) as u8, n as u8] }

fn client_hello(host: &str, hello_ver: [u8; 2], ciphers: &[u16], tls13: bool) -> Vec<u8> {
    let mut ch = Vec::new();
    ch.extend_from_slice(&hello_ver);
    ch.extend_from_slice(&[0x11; 32]); // client random (fixed is fine)
    ch.push(0x00); // session id len

    let mut cb = Vec::new();
    for c in ciphers {
        cb.extend_from_slice(&c.to_be_bytes());
    }
    ch.extend_from_slice(&u16b(cb.len()));
    ch.extend(cb);
    ch.extend_from_slice(&[0x01, 0x00]); // compression null

    // Extensions
    let mut ext = Vec::new();
    // SNI
    let h = host.as_bytes();
    let mut sni = vec![0x00, 0x00];
    sni.extend_from_slice(&u16b(h.len() + 5));
    sni.extend_from_slice(&u16b(h.len() + 3));
    sni.push(0x00);
    sni.extend_from_slice(&u16b(h.len()));
    sni.extend_from_slice(h);
    ext.extend(sni);
    // supported_groups
    ext.extend_from_slice(&[0x00,0x0a,0x00,0x08,0x00,0x06,0x00,0x1d,0x00,0x17,0x00,0x18]);
    // ec_point_formats
    ext.extend_from_slice(&[0x00,0x0b,0x00,0x02,0x01,0x00]);
    // signature_algorithms
    ext.extend_from_slice(&[0x00,0x0d,0x00,0x0a,0x00,0x08,0x04,0x03,0x08,0x04,0x04,0x01,0x02,0x01]);
    if tls13 {
        // supported_versions = TLS1.3
        ext.extend_from_slice(&[0x00,0x2b,0x00,0x03,0x02,0x03,0x04]);
        // key_share: ext_type(00 33) ext_len { client_shares_len { entry } }
        let mut entry = vec![0x00, 0x1d, 0x00, 0x20]; // group x25519, key len 32
        entry.extend_from_slice(&[0x22; 32]);
        let mut shares = u16b(entry.len()).to_vec(); // client_shares length
        shares.extend(entry);
        let mut ks = vec![0x00, 0x33];
        ks.extend_from_slice(&u16b(shares.len()));
        ks.extend(shares);
        ext.extend(ks);
    }
    let mut ext_block = u16b(ext.len()).to_vec();
    ext_block.extend(ext);
    ch.extend(ext_block);

    // Handshake + record
    let mut hs = vec![0x01, 0x00];
    hs.extend_from_slice(&u16b(ch.len()));
    hs.extend(ch);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&u16b(hs.len()));
    rec.extend(hs);
    rec
}

/// Returns the cipher the server chose, if it replied with a ServerHello.
fn negotiate(host: &str, port: u16, hello_ver: [u8; 2], ciphers: &[u16], tls13: bool) -> Option<u16> {
    let hello = client_hello(host, hello_ver, ciphers, tls13);
    let mut s = TcpStream::connect((host, port)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
    s.write_all(&hello).ok()?;
    let mut buf = vec![0u8; 2048];
    let n = s.read(&mut buf).ok()?;
    let d = &buf[..n];
    if n < 46 || d[0] != 0x16 || d[5] != 0x02 {
        return None; // alert or non-ServerHello
    }
    let counter = d[43] as usize;
    if n < counter + 46 {
        return None;
    }
    Some(((d[counter + 44] as u16) << 8) | d[counter + 45] as u16)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <host> [port]", args[0]);
        std::process::exit(1);
    }
    let host = &args[1];
    let port: u16 = args.get(2).and_then(|p| p.parse().ok()).unwrap_or(443);

    println!("Scanning {host}:{port}\n");

    // Version support: offer all non-1.3 ciphers at each hello version.
    let legacy: Vec<u16> = SUITES.iter().filter(|s| s.0 >> 8 != 0x13).map(|s| s.0).collect();
    println!("Protocol versions:");
    for (name, ver) in [("TLS 1.0", [0x03, 0x01]), ("TLS 1.1", [0x03, 0x02]), ("TLS 1.2", [0x03, 0x03])] {
        let ok = negotiate(host, port, ver, &legacy, false).is_some();
        println!("  {name}: {}", if ok { "supported" } else { "no" });
    }
    let tls13 = negotiate(host, port, [0x03, 0x03], &[0x1301, 0x1302, 0x1303], true)
        .map(|c| c >> 8 == 0x13)
        .unwrap_or(false);
    println!("  TLS 1.3: {}", if tls13 { "supported" } else { "no" });

    // Cipher enumeration: one suite at a time.
    println!("\nAccepted cipher suites:");
    let mut weak = Vec::new();
    for s in SUITES {
        let is13 = s.0 >> 8 == 0x13;
        let accepted = negotiate(host, port, [0x03, 0x03], &[s.0], is13).map(|c| c == s.0).unwrap_or(false);
        if accepted {
            let tag = if s.2.is_empty() { String::new() } else { format!("  [WEAK: {}]", s.2) };
            println!("  0x{:04x}  {}{}", s.0, s.1, tag);
            if !s.2.is_empty() {
                weak.push(s.1);
            }
        }
    }
    if weak.is_empty() {
        println!("\nNo weak suites accepted.");
    } else {
        println!("\n{} weak suite(s): {}", weak.len(), weak.join(", "));
    }
}
