//! Small, dependency-free network helpers shared across the s0t0n tools.
//!
//! - [`Cidr`]    — IPv4 CIDR parsing + host/address iteration
//! - [`Cidr6`]   — IPv6 CIDR parsing + bounded host iteration
//! - [`expand_v4`] / [`exclude_v4`] — target specs: CIDR, `a.b.c.d-e` ranges,
//!   single IPs, with exclusion lists
//! - [`jsonl`]   — tiny allocation-light NDJSON record builder so every tool
//!   can emit `--json` output that pipes into `jq`

use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// A parsed IPv4 CIDR block (network address + prefix length).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    network: u32,
    prefix: u8,
}

impl Cidr {
    /// Parse a CIDR such as `192.168.1.0/24`. A bare address (no `/`) is a `/32`.
    pub fn parse(s: &str) -> Result<Cidr, String> {
        let (addr_part, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                let prefix: u8 = p.parse().map_err(|_| format!("invalid prefix: {p}"))?;
                if prefix > 32 {
                    return Err(format!("prefix out of range: /{prefix}"));
                }
                (a, prefix)
            }
            None => (s, 32),
        };
        let ip = Ipv4Addr::from_str(addr_part).map_err(|_| format!("invalid IPv4: {addr_part}"))?;
        let mask = Self::mask_for(prefix);
        Ok(Cidr { network: u32::from(ip) & mask, prefix })
    }

    fn mask_for(prefix: u8) -> u32 {
        if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) }
    }

    pub fn network(&self) -> Ipv4Addr { Ipv4Addr::from(self.network) }
    pub fn broadcast(&self) -> Ipv4Addr { Ipv4Addr::from(self.network | !Self::mask_for(self.prefix)) }
    pub fn len(&self) -> u64 { 1u64 << (32 - self.prefix) }
    pub fn is_empty(&self) -> bool { false }

    /// Every address in the block, including network and broadcast.
    pub fn addresses(&self) -> impl Iterator<Item = Ipv4Addr> {
        let start = self.network;
        (0..self.len()).map(move |i| Ipv4Addr::from(start.wrapping_add(i as u32)))
    }

    /// Usable hosts: for `/0`..=`/30` skips network+broadcast; `/31`,`/32` yield all.
    pub fn hosts(&self) -> impl Iterator<Item = Ipv4Addr> {
        let (skip, take) = if self.prefix <= 30 {
            (1u64, self.len().saturating_sub(2))
        } else {
            (0u64, self.len())
        };
        self.addresses().skip(skip as usize).take(take as usize)
    }
}

/// A parsed IPv6 CIDR block. Iteration is bounded by the caller (v6 blocks are
/// astronomically large); use [`Cidr6::hosts`] with `.take(n)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr6 {
    network: u128,
    prefix: u8,
}

impl Cidr6 {
    pub fn parse(s: &str) -> Result<Cidr6, String> {
        let (addr_part, prefix) = match s.split_once('/') {
            Some((a, p)) => {
                let prefix: u8 = p.parse().map_err(|_| format!("invalid prefix: {p}"))?;
                if prefix > 128 {
                    return Err(format!("prefix out of range: /{prefix}"));
                }
                (a, prefix)
            }
            None => (s, 128),
        };
        let ip = Ipv6Addr::from_str(addr_part).map_err(|_| format!("invalid IPv6: {addr_part}"))?;
        let mask = Self::mask_for(prefix);
        Ok(Cidr6 { network: u128::from(ip) & mask, prefix })
    }

    fn mask_for(prefix: u8) -> u128 {
        if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) }
    }

    pub fn network(&self) -> Ipv6Addr { Ipv6Addr::from(self.network) }
    pub fn prefix(&self) -> u8 { self.prefix }

    /// Number of addresses in the block, or `None` if it exceeds `u128`
    /// (only `/0`, which is not representable as a count).
    pub fn len(&self) -> Option<u128> { 1u128.checked_shl((128 - self.prefix) as u32) }
    pub fn is_empty(&self) -> bool { false }

    /// Addresses starting at the network address. Unbounded for small prefixes —
    /// always constrain with `.take(n)`.
    pub fn hosts(&self) -> impl Iterator<Item = Ipv6Addr> {
        let start = self.network;
        (0u128..).map(move |i| Ipv6Addr::from(start.wrapping_add(i)))
    }
}

/// Expand an IPv4 target spec into concrete addresses. Accepts:
/// - CIDR: `10.0.0.0/28`
/// - last-octet range: `10.0.0.10-50`
/// - full range: `10.0.0.10-10.0.0.50`
/// - single: `10.0.0.5`
pub fn expand_v4(spec: &str) -> Result<Vec<Ipv4Addr>, String> {
    let spec = spec.trim();
    if spec.contains('/') {
        return Ok(Cidr::parse(spec)?.hosts().collect());
    }
    if let Some((lo, hi)) = spec.split_once('-') {
        let start = Ipv4Addr::from_str(lo.trim()).map_err(|_| format!("invalid IPv4: {lo}"))?;
        let end = if hi.contains('.') {
            Ipv4Addr::from_str(hi.trim()).map_err(|_| format!("invalid IPv4: {hi}"))?
        } else {
            // last-octet shorthand: keep the first three octets of `start`.
            let last: u8 = hi.trim().parse().map_err(|_| format!("invalid range end: {hi}"))?;
            let o = start.octets();
            Ipv4Addr::new(o[0], o[1], o[2], last)
        };
        let (s, e) = (u32::from(start), u32::from(end));
        if s > e {
            return Err("range start must be <= end".into());
        }
        return Ok((s..=e).map(Ipv4Addr::from).collect());
    }
    Ok(vec![Ipv4Addr::from_str(spec).map_err(|_| format!("invalid IPv4: {spec}"))?])
}

/// Remove every address matched by any exclusion spec (each an [`expand_v4`] spec).
pub fn exclude_v4(base: Vec<Ipv4Addr>, excludes: &[String]) -> Result<Vec<Ipv4Addr>, String> {
    use std::collections::HashSet;
    let mut drop: HashSet<u32> = HashSet::new();
    for ex in excludes {
        for ip in expand_v4(ex)? {
            drop.insert(u32::from(ip));
        }
    }
    Ok(base.into_iter().filter(|ip| !drop.contains(&u32::from(*ip))).collect())
}

/// Minimal NDJSON record builder (one JSON object per line). Avoids a serde
/// dependency; values are escaped for the JSON string/number/bool grammar.
pub mod jsonl {
    /// A single JSON value.
    pub enum Val<'a> {
        Str(&'a str),
        Num(f64),
        Int(i64),
        Bool(bool),
    }

    fn esc(s: &str, out: &mut String) {
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('"');
    }

    /// Build a one-line JSON object from key/value pairs.
    pub fn obj(pairs: &[(&str, Val)]) -> String {
        let mut s = String::from("{");
        for (i, (k, v)) in pairs.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            esc(k, &mut s);
            s.push(':');
            match v {
                Val::Str(x) => esc(x, &mut s),
                Val::Num(x) => s.push_str(&x.to_string()),
                Val::Int(x) => s.push_str(&x.to_string()),
                Val::Bool(x) => s.push_str(if *x { "true" } else { "false" }),
            }
        }
        s.push('}');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_masks() {
        let c = Cidr::parse("192.168.1.42/24").unwrap();
        assert_eq!(c.network(), Ipv4Addr::new(192, 168, 1, 0));
        assert_eq!(c.broadcast(), Ipv4Addr::new(192, 168, 1, 255));
        assert_eq!(c.len(), 256);
    }

    #[test]
    fn hosts_skip_net_and_broadcast() {
        let c = Cidr::parse("10.0.0.0/30").unwrap();
        assert_eq!(c.hosts().collect::<Vec<_>>(),
                   vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]);
    }

    #[test]
    fn slash32_single_host() {
        let c = Cidr::parse("8.8.8.8").unwrap();
        assert_eq!(c.hosts().collect::<Vec<_>>(), vec![Ipv4Addr::new(8, 8, 8, 8)]);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(Cidr::parse("999.0.0.1/24").is_err());
        assert!(Cidr::parse("10.0.0.0/33").is_err());
    }

    #[test]
    fn ipv6_cidr() {
        let c = Cidr6::parse("2001:db8::/126").unwrap();
        assert_eq!(c.len(), Some(4));
        let hosts: Vec<_> = c.hosts().take(4).collect();
        assert_eq!(hosts[0], "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(hosts[3], "2001:db8::3".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn expand_ranges() {
        assert_eq!(expand_v4("10.0.0.10-12").unwrap(),
                   vec![Ipv4Addr::new(10,0,0,10), Ipv4Addr::new(10,0,0,11), Ipv4Addr::new(10,0,0,12)]);
        assert_eq!(expand_v4("10.0.0.10-10.0.0.11").unwrap().len(), 2);
        assert_eq!(expand_v4("10.0.0.5").unwrap(), vec![Ipv4Addr::new(10,0,0,5)]);
        assert!(expand_v4("10.0.0.50-10").is_err());
    }

    #[test]
    fn exclusions() {
        let base = expand_v4("10.0.0.0/29").unwrap();
        let kept = exclude_v4(base, &["10.0.0.1".into(), "10.0.0.5-6".into()]).unwrap();
        assert!(!kept.contains(&Ipv4Addr::new(10,0,0,1)));
        assert!(!kept.contains(&Ipv4Addr::new(10,0,0,5)));
        assert!(kept.contains(&Ipv4Addr::new(10,0,0,2)));
    }

    #[test]
    fn jsonl_build() {
        use jsonl::Val;
        let line = jsonl::obj(&[("ip", Val::Str("10.0.0.1")), ("port", Val::Int(22)), ("open", Val::Bool(true))]);
        assert_eq!(line, r#"{"ip":"10.0.0.1","port":22,"open":true}"#);
    }
}
