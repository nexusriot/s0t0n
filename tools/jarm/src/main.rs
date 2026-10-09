//! jarm — active TLS-server fingerprinting via the JARM algorithm: send 10
//! deliberately varied TLS ClientHellos and hash the servers' responses into a
//! 62-char fingerprint for clustering / identification.
//!
//! Independent Rust reimplementation of the public JARM algorithm
//! (salesforce/jarm, Apache-2.0). Cross-validated against the reference
//! scanner. Authorized use only.

use rand::RngCore;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

struct Spec {
    version: &'static str,   // TLS_1.2 / TLS_1.1 / TLS_1.3
    ciphers: &'static str,   // ALL / NO1.3
    order: &'static str,     // FORWARD/REVERSE/TOP_HALF/BOTTOM_HALF/MIDDLE_OUT
    grease: bool,
    alpn: &'static str,      // APLN / RARE_APLN
    support: &'static str,   // NO_SUPPORT / 1.2_SUPPORT / 1.3_SUPPORT
    ext_order: &'static str, // FORWARD / REVERSE
}

const SPECS: [Spec; 10] = [
    Spec { version: "TLS_1.2", ciphers: "ALL",   order: "FORWARD",     grease: false, alpn: "APLN",      support: "1.2_SUPPORT", ext_order: "REVERSE" },
    Spec { version: "TLS_1.2", ciphers: "ALL",   order: "REVERSE",     grease: false, alpn: "APLN",      support: "1.2_SUPPORT", ext_order: "FORWARD" },
    Spec { version: "TLS_1.2", ciphers: "ALL",   order: "TOP_HALF",    grease: false, alpn: "APLN",      support: "NO_SUPPORT",  ext_order: "FORWARD" },
    Spec { version: "TLS_1.2", ciphers: "ALL",   order: "BOTTOM_HALF", grease: false, alpn: "RARE_APLN", support: "NO_SUPPORT",  ext_order: "FORWARD" },
    Spec { version: "TLS_1.2", ciphers: "ALL",   order: "MIDDLE_OUT",  grease: true,  alpn: "RARE_APLN", support: "NO_SUPPORT",  ext_order: "REVERSE" },
    Spec { version: "TLS_1.1", ciphers: "ALL",   order: "FORWARD",     grease: false, alpn: "APLN",      support: "NO_SUPPORT",  ext_order: "FORWARD" },
    Spec { version: "TLS_1.3", ciphers: "ALL",   order: "FORWARD",     grease: false, alpn: "APLN",      support: "1.3_SUPPORT", ext_order: "REVERSE" },
    Spec { version: "TLS_1.3", ciphers: "ALL",   order: "REVERSE",     grease: false, alpn: "APLN",      support: "1.3_SUPPORT", ext_order: "FORWARD" },
    Spec { version: "TLS_1.3", ciphers: "NO1.3", order: "FORWARD",     grease: false, alpn: "APLN",      support: "1.3_SUPPORT", ext_order: "FORWARD" },
    Spec { version: "TLS_1.3", ciphers: "ALL",   order: "MIDDLE_OUT",  grease: true,  alpn: "APLN",      support: "1.3_SUPPORT", ext_order: "REVERSE" },
];

// ClientHello cipher list ("ALL").
const CIPHERS: [[u8; 2]; 69] = [
    [0x00,0x16],[0x00,0x33],[0x00,0x67],[0xc0,0x9e],[0xc0,0xa2],[0x00,0x9e],[0x00,0x39],[0x00,0x6b],
    [0xc0,0x9f],[0xc0,0xa3],[0x00,0x9f],[0x00,0x45],[0x00,0xbe],[0x00,0x88],[0x00,0xc4],[0x00,0x9a],
    [0xc0,0x08],[0xc0,0x09],[0xc0,0x23],[0xc0,0xac],[0xc0,0xae],[0xc0,0x2b],[0xc0,0x0a],[0xc0,0x24],
    [0xc0,0xad],[0xc0,0xaf],[0xc0,0x2c],[0xc0,0x72],[0xc0,0x73],[0xcc,0xa9],[0x13,0x02],[0x13,0x01],
    [0xcc,0x14],[0xc0,0x07],[0xc0,0x12],[0xc0,0x13],[0xc0,0x27],[0xc0,0x2f],[0xc0,0x14],[0xc0,0x28],
    [0xc0,0x30],[0xc0,0x60],[0xc0,0x61],[0xc0,0x76],[0xc0,0x77],[0xcc,0xa8],[0x13,0x05],[0x13,0x04],
    [0x13,0x03],[0xcc,0x13],[0xc0,0x11],[0x00,0x0a],[0x00,0x2f],[0x00,0x3c],[0xc0,0x9c],[0xc0,0xa0],
    [0x00,0x9c],[0x00,0x35],[0x00,0x3d],[0xc0,0x9d],[0xc0,0xa1],[0x00,0x9d],[0x00,0x41],[0x00,0xba],
    [0x00,0x84],[0x00,0xc0],[0x00,0x07],[0x00,0x04],[0x00,0x05],
];

// Separate SORTED list used only for the fuzzy-hash index of the chosen cipher.
const CIPHER_INDEX: [[u8; 2]; 69] = [
    [0x00,0x04],[0x00,0x05],[0x00,0x07],[0x00,0x0a],[0x00,0x16],[0x00,0x2f],[0x00,0x33],[0x00,0x35],
    [0x00,0x39],[0x00,0x3c],[0x00,0x3d],[0x00,0x41],[0x00,0x45],[0x00,0x67],[0x00,0x6b],[0x00,0x84],
    [0x00,0x88],[0x00,0x9a],[0x00,0x9c],[0x00,0x9d],[0x00,0x9e],[0x00,0x9f],[0x00,0xba],[0x00,0xbe],
    [0x00,0xc0],[0x00,0xc4],[0xc0,0x07],[0xc0,0x08],[0xc0,0x09],[0xc0,0x0a],[0xc0,0x11],[0xc0,0x12],
    [0xc0,0x13],[0xc0,0x14],[0xc0,0x23],[0xc0,0x24],[0xc0,0x27],[0xc0,0x28],[0xc0,0x2b],[0xc0,0x2c],
    [0xc0,0x2f],[0xc0,0x30],[0xc0,0x60],[0xc0,0x61],[0xc0,0x72],[0xc0,0x73],[0xc0,0x76],[0xc0,0x77],
    [0xc0,0x9c],[0xc0,0x9d],[0xc0,0x9e],[0xc0,0x9f],[0xc0,0xa0],[0xc0,0xa1],[0xc0,0xa2],[0xc0,0xa3],
    [0xc0,0xac],[0xc0,0xad],[0xc0,0xae],[0xc0,0xaf],[0xcc,0x13],[0xcc,0x14],[0xcc,0xa8],[0xcc,0xa9],
    [0x13,0x01],[0x13,0x02],[0x13,0x03],[0x13,0x04],[0x13,0x05],
];

fn grease_value() -> [u8; 2] {
    const G: [u8; 16] = [0x0a,0x1a,0x2a,0x3a,0x4a,0x5a,0x6a,0x7a,0x8a,0x9a,0xaa,0xba,0xca,0xda,0xea,0xfa];
    let mut r = [0u8; 1];
    rand::thread_rng().fill_bytes(&mut r);
    let v = G[(r[0] as usize) % 16];
    [v, v]
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

fn u16b(n: usize) -> [u8; 2] {
    [(n >> 8) as u8, n as u8]
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// Faithful port of the reference `cipher_mung`.
fn mung<T: Copy>(v: &[T], order: &str) -> Vec<T> {
    let n = v.len();
    match order {
        "REVERSE" => v.iter().rev().copied().collect(),
        "BOTTOM_HALF" => {
            if n % 2 == 1 {
                v[n / 2 + 1..].to_vec()
            } else {
                v[n / 2..].to_vec()
            }
        }
        "TOP_HALF" => {
            let mut out = Vec::new();
            if n % 2 == 1 {
                out.push(v[n / 2]);
            }
            let rev = mung(v, "REVERSE");
            out.extend(mung(&rev, "BOTTOM_HALF"));
            out
        }
        "MIDDLE_OUT" => {
            let mut out = Vec::with_capacity(n);
            let middle = n / 2;
            if n % 2 == 1 {
                out.push(v[middle]);
                for i in 1..=middle {
                    out.push(v[middle + i]);
                    out.push(v[middle - i]);
                }
            } else {
                for i in 1..=middle {
                    out.push(v[middle - 1 + i]);
                    out.push(v[middle - i]);
                }
            }
            out
        }
        _ => v.to_vec(),
    }
}

fn cipher_list(spec: &Spec) -> Vec<[u8; 2]> {
    let mut list: Vec<[u8; 2]> = if spec.ciphers == "NO1.3" {
        CIPHERS.iter().filter(|c| c[0] != 0x13).copied().collect()
    } else {
        CIPHERS.to_vec()
    };
    if spec.order != "FORWARD" {
        list = mung(&list, spec.order);
    }
    if spec.grease {
        list.insert(0, grease_value());
    }
    list
}

fn ext_server_name(host: &str) -> Vec<u8> {
    let h = host.as_bytes();
    let mut e = vec![0x00, 0x00];
    e.extend_from_slice(&u16b(h.len() + 5));
    e.extend_from_slice(&u16b(h.len() + 3));
    e.push(0x00);
    e.extend_from_slice(&u16b(h.len()));
    e.extend_from_slice(h);
    e
}

fn ext_alpn(spec: &Spec) -> Vec<u8> {
    let rare: Vec<&[u8]> = vec![
        b"\x08http/0.9", b"\x08http/1.0", b"\x06spdy/1", b"\x06spdy/2",
        b"\x06spdy/3", b"\x03h2c", b"\x02hq",
    ];
    let normal: Vec<&[u8]> = vec![
        b"\x08http/0.9", b"\x08http/1.0", b"\x08http/1.1", b"\x06spdy/1",
        b"\x06spdy/2", b"\x06spdy/3", b"\x02h2", b"\x03h2c", b"\x02hq",
    ];
    let mut alpns = if spec.alpn == "RARE_APLN" { rare } else { normal };
    if spec.ext_order != "FORWARD" {
        alpns = mung(&alpns, spec.ext_order);
    }
    let mut body = Vec::new();
    for a in &alpns {
        body.extend_from_slice(a);
    }
    let mut e = vec![0x00, 0x10];
    e.extend_from_slice(&u16b(body.len() + 2));
    e.extend_from_slice(&u16b(body.len()));
    e.extend(body);
    e
}

fn ext_key_share(grease: bool) -> Vec<u8> {
    let mut share = Vec::new();
    if grease {
        share.extend_from_slice(&grease_value());
        share.extend_from_slice(&[0x00, 0x01, 0x00]);
    }
    share.extend_from_slice(&[0x00, 0x1d]); // group x25519
    share.extend_from_slice(&[0x00, 0x20]); // key exchange length 32
    share.extend_from_slice(&rand32());
    let mut e = vec![0x00, 0x33];
    e.extend_from_slice(&u16b(share.len() + 2));
    e.extend_from_slice(&u16b(share.len()));
    e.extend(share);
    e
}

fn ext_supported_versions(spec: &Spec, grease: bool) -> Vec<u8> {
    let base: Vec<[u8; 2]> = if spec.support == "1.2_SUPPORT" {
        vec![[0x03, 0x01], [0x03, 0x02], [0x03, 0x03]]
    } else {
        vec![[0x03, 0x01], [0x03, 0x02], [0x03, 0x03], [0x03, 0x04]]
    };
    let tls = if spec.ext_order != "FORWARD" {
        mung(&base, spec.ext_order)
    } else {
        base
    };
    let mut versions = Vec::new();
    if grease {
        versions.extend_from_slice(&grease_value());
    }
    for v in &tls {
        versions.extend_from_slice(v);
    }
    let mut e = vec![0x00, 0x2b];
    e.extend_from_slice(&u16b(versions.len() + 1));
    e.push(versions.len() as u8);
    e.extend(versions);
    e
}

fn extensions(spec: &Spec, host: &str) -> Vec<u8> {
    let mut all = Vec::new();
    if spec.grease {
        all.extend_from_slice(&grease_value());
        all.extend_from_slice(&[0x00, 0x00]);
    }
    all.extend(ext_server_name(host));
    all.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
    all.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x01]);
    all.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
    all.extend_from_slice(&[0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19]);
    all.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
    all.extend_from_slice(&[0x00, 0x23, 0x00, 0x00]);
    all.extend(ext_alpn(spec));
    all.extend_from_slice(&[0x00, 0x0d, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08, 0x06, 0x06, 0x01, 0x02, 0x01]);
    all.extend(ext_key_share(spec.grease));
    all.extend_from_slice(&[0x00, 0x2d, 0x00, 0x02, 0x01, 0x01]);
    if spec.version == "TLS_1.3" || spec.support == "1.2_SUPPORT" {
        all.extend(ext_supported_versions(spec, spec.grease));
    }
    let mut out = u16b(all.len()).to_vec();
    out.extend(all);
    out
}

fn build_client_hello(spec: &Spec, host: &str) -> Vec<u8> {
    let (rec_ver, ch_ver): ([u8; 2], [u8; 2]) = match spec.version {
        "TLS_1.3" => ([0x03, 0x01], [0x03, 0x03]),
        "TLS_1.1" => ([0x03, 0x02], [0x03, 0x02]),
        _ => ([0x03, 0x03], [0x03, 0x03]),
    };

    let mut ch = Vec::new();
    ch.extend_from_slice(&ch_ver);
    ch.extend_from_slice(&rand32());
    let sid = rand32();
    ch.push(sid.len() as u8);
    ch.extend_from_slice(&sid);

    let ciphers = cipher_list(spec);
    let mut cbytes = Vec::new();
    for c in &ciphers {
        cbytes.extend_from_slice(c);
    }
    ch.extend_from_slice(&u16b(cbytes.len()));
    ch.extend(cbytes);
    ch.extend_from_slice(&[0x01, 0x00]);
    ch.extend(extensions(spec, host));

    let mut hs = vec![0x01, 0x00];
    hs.extend_from_slice(&u16b(ch.len()));
    hs.extend(ch);

    let mut rec = vec![0x16];
    rec.extend_from_slice(&rec_ver);
    rec.extend_from_slice(&u16b(hs.len()));
    rec.extend(hs);
    rec
}

fn parse_server_hello(data: &[u8]) -> String {
    if data.len() < 6 || data[0] == 21 {
        return "|||".into();
    }
    if !(data[0] == 22 && data[5] == 2) {
        return "|||".into();
    }
    let server_hello_length = ((data[3] as usize) << 8) | data[4] as usize;
    let counter = data[43] as usize;
    let cipher_off = counter + 44;
    if data.len() < cipher_off + 2 {
        return "|||".into();
    }
    let cipher = &data[cipher_off..cipher_off + 2];
    let version = &data[9..11];
    format!("{}|{}|{}", hex(cipher), hex(version), extract_extensions(data, counter, server_hello_length))
}

fn extract_extensions(data: &[u8], counter: usize, server_hello_length: usize) -> String {
    let bail = "|".to_string();
    if data.len() < counter + 49 {
        return bail;
    }
    if data[counter + 47] == 11 {
        return bail;
    }
    if counter + 53 <= data.len() && &data[counter + 50..counter + 53] == b"\x0e\xac\x0b" {
        return bail;
    }
    if data.len() >= 85 && &data[82..85] == b"\x0f\xf0\x0b" {
        return bail;
    }
    if counter + 42 >= server_hello_length {
        return bail;
    }
    let count0 = counter + 49;
    let ext_len = ((data[counter + 47] as usize) << 8) | data[counter + 48] as usize;
    let maximum = ext_len + count0 - 1;
    let mut count = count0;
    let mut types: Vec<String> = Vec::new();
    let mut alpn = String::new();
    while count < maximum && count + 4 <= data.len() {
        let t = [data[count], data[count + 1]];
        let l = ((data[count + 2] as usize) << 8) | data[count + 3] as usize;
        let vstart = count + 4;
        if t == [0x00, 0x10] && vstart + l <= data.len() && l > 3 {
            alpn = String::from_utf8_lossy(&data[vstart + 3..vstart + l]).into_owned();
        }
        types.push(hex(&t));
        if l == 0 {
            count += 4;
        } else {
            count += l + 4;
        }
    }
    format!("{}|{}", alpn, types.join("-"))
}

fn cipher_index(cipher: &str) -> String {
    if cipher.is_empty() {
        return "00".into();
    }
    let mut count = 1usize;
    for c in CIPHER_INDEX.iter() {
        if hex(c) == cipher {
            break;
        }
        count += 1;
    }
    let h = format!("{:x}", count);
    if h.len() < 2 {
        format!("0{h}")
    } else {
        h
    }
}

fn version_byte(version: &str) -> char {
    if version.is_empty() {
        return '0';
    }
    let opts = ['a', 'b', 'c', 'd', 'e', 'f'];
    let n = version.chars().nth(3).and_then(|c| c.to_digit(10)).unwrap_or(0) as usize;
    *opts.get(n).unwrap_or(&'0')
}

fn jarm_hash(raw: &[String]) -> String {
    if raw.iter().all(|h| h == "|||") {
        return "0".repeat(62);
    }
    let mut fuzzy = String::new();
    let mut alpns_ext = String::new();
    for h in raw {
        let parts: Vec<&str> = h.split('|').collect();
        fuzzy.push_str(&cipher_index(parts.first().copied().unwrap_or("")));
        fuzzy.push(version_byte(parts.get(1).copied().unwrap_or("")));
        alpns_ext.push_str(parts.get(2).copied().unwrap_or(""));
        alpns_ext.push_str(parts.get(3).copied().unwrap_or(""));
    }
    let digest = Sha256::digest(alpns_ext.as_bytes());
    fuzzy.push_str(&hex(&digest)[..32]);
    fuzzy
}

fn probe_once(host: &str, port: u16, spec: &Spec) -> String {
    let hello = build_client_hello(spec, host);
    let mut stream = match TcpStream::connect(format!("{host}:{port}")) {
        Ok(s) => s,
        Err(_) => return "|||".into(),
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
    if stream.write_all(&hello).is_err() {
        return "|||".into();
    }
    let mut buf = vec![0u8; 1484];
    match stream.read(&mut buf) {
        Ok(n) if n > 0 => parse_server_hello(&buf[..n]),
        _ => "|||".into(),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <host> [port]", args[0]);
        std::process::exit(1);
    }
    let host = &args[1];
    let port: u16 = args.get(2).and_then(|p| p.parse().ok()).unwrap_or(443);

    let raw: Vec<String> = SPECS.iter().map(|s| probe_once(host, port, s)).collect();
    println!("{host}:{port}\t{}", jarm_hash(&raw));
}
