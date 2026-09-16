//! FireHOL parsed IP target and entry representations.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Network target representing either an exact IP or a CIDR subnet.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FireholIpTarget {
    /// Exact IPv4 address (stored in network byte order)
    ExactV4([u8; 4]),
    /// Exact IPv6 address (stored in network byte order)
    ExactV6([u8; 16]),
    /// IPv4 CIDR subnet: (prefix_length, network_address_bytes)
    CidrV4(u32, [u8; 4]),
    /// IPv6 CIDR subnet: (prefix_length, network_address_bytes)
    CidrV6(u32, [u8; 16]),
}

impl FireholIpTarget {
    /// Existing RocksDB target key, encoded on the stack without IPv4 padding.
    pub(crate) fn context_key<'a>(&self, buffer: &'a mut [u8; 18]) -> &'a [u8] {
        use crate::cache_rocksdb::{
            ctx_key_v4_exact, ctx_key_v4_lpm, ctx_key_v6_exact, ctx_key_v6_lpm,
        };
        let len = match self {
            Self::ExactV4(ip) => {
                buffer[..5].copy_from_slice(&ctx_key_v4_exact(ip));
                5
            }
            Self::ExactV6(ip) => {
                buffer[..17].copy_from_slice(&ctx_key_v6_exact(ip));
                17
            }
            Self::CidrV4(prefix, ip) => {
                buffer[..6].copy_from_slice(&ctx_key_v4_lpm(*prefix as u8, ip));
                6
            }
            Self::CidrV6(prefix, ip) => {
                buffer.copy_from_slice(&ctx_key_v6_lpm(*prefix as u8, ip));
                18
            }
        };
        &buffer[..len]
    }

    pub(crate) fn contains_ip(&self, ip: &std::net::IpAddr) -> bool {
        use std::net::IpAddr;
        match (self, ip) {
            (Self::ExactV4(a), IpAddr::V4(b)) => *a == b.octets(),
            (Self::ExactV6(a), IpAddr::V6(b)) => *a == b.octets(),
            (Self::CidrV4(p, a), IpAddr::V4(b)) => {
                let mask = u32::MAX.checked_shl(32 - p).unwrap_or(0);
                (u32::from(*b) & mask) == u32::from_be_bytes(*a)
            }
            (Self::CidrV6(p, a), IpAddr::V6(b)) => {
                let mask = u128::MAX.checked_shl(128 - p).unwrap_or(0);
                (u128::from(*b) & mask) == u128::from_be_bytes(*a)
            }
            _ => false,
        }
    }

    /// Check whether this target is an exact single-host match.
    pub fn is_exact(&self) -> bool {
        matches!(self, Self::ExactV4(_) | Self::ExactV6(_))
    }

    /// IP protocol version (4 or 6).
    pub fn ip_version(&self) -> u8 {
        match self {
            Self::ExactV4(_) | Self::CidrV4(_, _) => 4,
            Self::ExactV6(_) | Self::CidrV6(_, _) => 6,
        }
    }

    /// Entry type label ("exact" or "cidr") for Prometheus metrics.
    pub fn entry_type(&self) -> &'static str {
        if self.is_exact() {
            "exact"
        } else {
            "cidr"
        }
    }

    /// CIDR prefix length (32 for IPv4 exact, 128 for IPv6 exact).
    pub fn prefix_len(&self) -> u8 {
        match self {
            Self::ExactV4(_) => 32,
            Self::ExactV6(_) => 128,
            Self::CidrV4(len, _) => *len as u8,
            Self::CidrV6(len, _) => *len as u8,
        }
    }

    /// Format as standard IP or CIDR string.
    pub fn to_string_repr(&self) -> String {
        match self {
            Self::ExactV4(octets) => Ipv4Addr::from(*octets).to_string(),
            Self::ExactV6(octets) => Ipv6Addr::from(*octets).to_string(),
            Self::CidrV4(len, octets) => format!("{}/{}", Ipv4Addr::from(*octets), len),
            Self::CidrV6(len, octets) => format!("{}/{}", Ipv6Addr::from(*octets), len),
        }
    }
}

/// A parsed FireHOL entry linked to its assigned rule ID, metadata ID, and source line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FireholEntry {
    pub target: FireholIpTarget,
    pub rule_id: u32,
    pub metadata_id: u32,
    /// 1-based line number in the source blocklist file where this entry was defined.
    pub line: u32,
}

impl FireholEntry {
    pub fn new(target: FireholIpTarget, rule_id: u32, metadata_id: u32, line: u32) -> Self {
        Self {
            target,
            rule_id,
            metadata_id,
            line,
        }
    }

    pub fn is_exact(&self) -> bool {
        self.target.is_exact()
    }

    pub fn ip_version(&self) -> u8 {
        self.target.ip_version()
    }

    pub fn entry_type(&self) -> &'static str {
        self.target.entry_type()
    }

    pub fn prefix_len(&self) -> u8 {
        self.target.prefix_len()
    }
}

impl FireholEntry {
    pub(crate) fn encode(&self) -> [u8; 30] {
        let mut out = [0; 30];
        match self.target {
            FireholIpTarget::ExactV4(ip) => {
                out[0] = 1;
                out[2..6].copy_from_slice(&ip);
            }
            FireholIpTarget::ExactV6(ip) => {
                out[0] = 2;
                out[2..18].copy_from_slice(&ip);
            }
            FireholIpTarget::CidrV4(p, ip) => {
                out[0] = 3;
                out[1] = p as u8;
                out[2..6].copy_from_slice(&ip);
            }
            FireholIpTarget::CidrV6(p, ip) => {
                out[0] = 4;
                out[1] = p as u8;
                out[2..18].copy_from_slice(&ip);
            }
        }
        out[18..22].copy_from_slice(&self.rule_id.to_be_bytes());
        out[22..26].copy_from_slice(&self.metadata_id.to_be_bytes());
        out[26..30].copy_from_slice(&self.line.to_be_bytes());
        out
    }

    pub(crate) fn decode(bytes: &[u8]) -> crate::error::Result<Self> {
        use crate::error::FirewallError;
        if bytes.len() != 30 {
            return Err(FirewallError::Cache("Invalid FireHOL entry length".into()));
        }
        let target = match bytes[0] {
            1 => FireholIpTarget::ExactV4(bytes[2..6].try_into().unwrap()),
            2 => FireholIpTarget::ExactV6(bytes[2..18].try_into().unwrap()),
            3 if bytes[1] <= 32 => {
                FireholIpTarget::CidrV4(bytes[1] as u32, bytes[2..6].try_into().unwrap())
            }
            4 if bytes[1] <= 128 => {
                FireholIpTarget::CidrV6(bytes[1] as u32, bytes[2..18].try_into().unwrap())
            }
            _ => return Err(FirewallError::Cache("Invalid FireHOL entry target".into())),
        };
        Ok(Self::new(
            target,
            u32::from_be_bytes(bytes[18..22].try_into().unwrap()),
            u32::from_be_bytes(bytes[22..26].try_into().unwrap()),
            u32::from_be_bytes(bytes[26..30].try_into().unwrap()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_target_exact_v4() {
        let ip = [192, 0, 2, 1];
        let target = FireholIpTarget::ExactV4(ip);
        assert!(target.is_exact());
        assert_eq!(target.ip_version(), 4);
        assert_eq!(target.entry_type(), "exact");
        assert_eq!(target.prefix_len(), 32);
        assert_eq!(target.to_string_repr(), "192.0.2.1");

        let mut buf = [0u8; 18];
        let key = target.context_key(&mut buf);
        assert_eq!(key.len(), 5);

        assert!(target.contains_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert!(!target.contains_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))));
        assert!(!target.contains_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_target_exact_v6() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let target = FireholIpTarget::ExactV6(ip.octets());
        assert!(target.is_exact());
        assert_eq!(target.ip_version(), 6);
        assert_eq!(target.entry_type(), "exact");
        assert_eq!(target.prefix_len(), 128);
        assert_eq!(target.to_string_repr(), "2001:db8::1");

        let mut buf = [0u8; 18];
        let key = target.context_key(&mut buf);
        assert_eq!(key.len(), 17);

        assert!(target.contains_ip(&IpAddr::V6(ip)));
        assert!(!target.contains_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!target.contains_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn test_target_cidr_v4() {
        let target = FireholIpTarget::CidrV4(24, [192, 0, 2, 0]);
        assert!(!target.is_exact());
        assert_eq!(target.ip_version(), 4);
        assert_eq!(target.entry_type(), "cidr");
        assert_eq!(target.prefix_len(), 24);
        assert_eq!(target.to_string_repr(), "192.0.2.0/24");

        let mut buf = [0u8; 18];
        let key = target.context_key(&mut buf);
        assert_eq!(key.len(), 6);

        assert!(target.contains_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))));
        assert!(!target.contains_ip(&IpAddr::V4(Ipv4Addr::new(192, 0, 3, 1))));
        assert!(!target.contains_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
    }

    #[test]
    fn test_target_cidr_v6() {
        let base: Ipv6Addr = "2001:db8::".parse().unwrap();
        let target = FireholIpTarget::CidrV6(48, base.octets());
        assert!(!target.is_exact());
        assert_eq!(target.ip_version(), 6);
        assert_eq!(target.entry_type(), "cidr");
        assert_eq!(target.prefix_len(), 48);
        assert_eq!(target.to_string_repr(), "2001:db8::/48");

        let mut buf = [0u8; 18];
        let key = target.context_key(&mut buf);
        assert_eq!(key.len(), 18);

        let test_v6: Ipv6Addr = "2001:db8:0:1::42".parse().unwrap();
        assert!(target.contains_ip(&IpAddr::V6(test_v6)));
        let test_v6_out: Ipv6Addr = "2001:db9::1".parse().unwrap();
        assert!(!target.contains_ip(&IpAddr::V6(test_v6_out)));
        assert!(!target.contains_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn test_firehol_entry_roundtrip_and_errors() {
        let entries = vec![
            FireholEntry::new(FireholIpTarget::ExactV4([10, 0, 0, 1]), 100, 200, 15),
            FireholEntry::new(
                FireholIpTarget::ExactV6("2001:db8::cafe".parse::<Ipv6Addr>().unwrap().octets()),
                101,
                201,
                25,
            ),
            FireholEntry::new(FireholIpTarget::CidrV4(16, [172, 16, 0, 0]), 102, 202, 35),
            FireholEntry::new(
                FireholIpTarget::CidrV6(64, "2001:db8:ffff::".parse::<Ipv6Addr>().unwrap().octets()),
                103,
                203,
                45,
            ),
        ];

        for entry in entries {
            assert_eq!(entry.is_exact(), entry.target.is_exact());
            assert_eq!(entry.ip_version(), entry.target.ip_version());
            assert_eq!(entry.entry_type(), entry.target.entry_type());
            assert_eq!(entry.prefix_len(), entry.target.prefix_len());

            let encoded = entry.encode();
            assert_eq!(encoded.len(), 30);
            let decoded = FireholEntry::decode(&encoded).expect("decode should succeed");
            assert_eq!(entry, decoded);
        }

        // Invalid lengths
        assert!(FireholEntry::decode(&[0u8; 29]).is_err());
        assert!(FireholEntry::decode(&[0u8; 31]).is_err());

        // Invalid target discriminator
        let mut invalid_target = [0u8; 30];
        invalid_target[0] = 99;
        assert!(FireholEntry::decode(&invalid_target).is_err());

        // Invalid prefix len > 32 for v4
        let mut invalid_p_v4 = [0u8; 30];
        invalid_p_v4[0] = 3;
        invalid_p_v4[1] = 33;
        assert!(FireholEntry::decode(&invalid_p_v4).is_err());

        // Invalid prefix len > 128 for v6
        let mut invalid_p_v6 = [0u8; 30];
        invalid_p_v6[0] = 4;
        invalid_p_v6[1] = 129;
        assert!(FireholEntry::decode(&invalid_p_v6).is_err());
    }
}
