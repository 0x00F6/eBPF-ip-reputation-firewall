//! High-speed deterministic IP generation and protocol distribution selectors.

use std::net::Ipv4Addr;
use std::str::FromStr;

/// Layer 4 protocol categories for traffic generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketProtocol {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other,
}

impl PacketProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            PacketProtocol::Tcp => "tcp",
            PacketProtocol::Udp => "udp",
            PacketProtocol::Icmp => "icmp",
            PacketProtocol::Icmpv6 => "icmpv6",
            PacketProtocol::Other => "other",
        }
    }
}

/// Configurable protocol choice for the benchmark and traffic tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtocolChoice {
    #[default]
    Mixed,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other,
}

impl FromStr for ProtocolChoice {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().trim() {
            "mixed" | "all" => Ok(ProtocolChoice::Mixed),
            "tcp" => Ok(ProtocolChoice::Tcp),
            "udp" => Ok(ProtocolChoice::Udp),
            "icmp" | "ping" => Ok(ProtocolChoice::Icmp),
            "icmpv6" | "ping6" => Ok(ProtocolChoice::Icmpv6),
            "other" | "raw" => Ok(ProtocolChoice::Other),
            _ => Err(format!(
                "Unknown protocol '{}'. Valid choices: mixed, tcp, udp, icmp, icmpv6, other",
                s
            )),
        }
    }
}

impl ProtocolChoice {
    /// Selects an individual protocol based on the configuration and PRNG state.
    #[inline(always)]
    pub fn select(&self, prng: &mut FastPrng) -> PacketProtocol {
        match self {
            ProtocolChoice::Tcp => PacketProtocol::Tcp,
            ProtocolChoice::Udp => PacketProtocol::Udp,
            ProtocolChoice::Icmp => PacketProtocol::Icmp,
            ProtocolChoice::Icmpv6 => PacketProtocol::Icmpv6,
            ProtocolChoice::Other => PacketProtocol::Other,
            ProtocolChoice::Mixed => {
                // Realistic distribution: 40% TCP, 35% UDP, 15% ICMP, 5% ICMPv6, 5% Other
                let roll = prng.gen_range(0, 99);
                if roll < 40 {
                    PacketProtocol::Tcp
                } else if roll < 75 {
                    PacketProtocol::Udp
                } else if roll < 90 {
                    PacketProtocol::Icmp
                } else if roll < 95 {
                    PacketProtocol::Icmpv6
                } else {
                    PacketProtocol::Other
                }
            }
        }
    }
}

/// Ultra-fast Xorshift64* pseudo-random number generator (1 cycle per call, zero allocations).
#[derive(Clone)]
pub struct FastPrng {
    state: u64,
}

impl Default for FastPrng {
    fn default() -> Self {
        Self::new(0x853c49e6748fea9b)
    }
}

impl FastPrng {
    #[inline(always)]
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x853c49e6748fea9b } else { seed },
        }
    }

    #[inline(always)]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545f4914f6cdd1d)
    }

    #[inline(always)]
    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    #[inline(always)]
    pub fn next_u16(&mut self) -> u16 {
        (self.next_u64() >> 48) as u16
    }

    /// Generates a random u32 in range `[min, max]`.
    #[inline(always)]
    pub fn gen_range(&mut self, min: u32, max: u32) -> u32 {
        if min >= max {
            return min;
        }
        min + (self.next_u32() % (max - min + 1))
    }
}

/// Known standard blocked IP addresses and CIDR subnets matching repository firewall rules.
pub const EXACT_BLOCKED_IPV4: [Ipv4Addr; 5] = [
    Ipv4Addr::new(198, 51, 100, 14),
    Ipv4Addr::new(192, 0, 2, 1),
    Ipv4Addr::new(203, 0, 113, 50),
    Ipv4Addr::new(198, 51, 100, 200),
    Ipv4Addr::new(192, 0, 2, 100),
];

pub const LEGITIMATE_CONTAINER_IPV4: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 10);
pub const DEFAULT_FIREWALL_IPV4: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 2);

/// Generator and pool of IP addresses for benchmarking.
#[derive(Clone)]
pub struct IpPool {
    ips: Vec<Ipv4Addr>,
    index: usize,
}

impl IpPool {
    /// Creates an IP pool containing `count` distinct blocked IPv4 addresses.
    /// Addresses are guaranteed to match either an Exact rule (like 198.51.100.14)
    /// or a CIDR rule (10.0.0.0/8, 198.51.100.0/24, etc.) in the firewall rules.
    pub fn new_blocked_pool(count: usize) -> Self {
        let mut ips = Vec::with_capacity(count.max(1));

        // Start with exact known blocked IPs
        for &exact in &EXACT_BLOCKED_IPV4 {
            if ips.len() < count {
                ips.push(exact);
            }
        }

        // Fill remainder with IPs in the 10.0.0.0/8 blocked CIDR subnet
        let mut current_offset: u32 = 1;
        while ips.len() < count {
            let b1 = 10u8;
            let b2 = ((current_offset >> 16) & 0xFF) as u8;
            let b3 = ((current_offset >> 8) & 0xFF) as u8;
            let b4 = (current_offset & 0xFF).max(1) as u8;

            let ip = Ipv4Addr::new(b1, b2, b3, b4);
            if !ips.contains(&ip) {
                ips.push(ip);
            }
            current_offset += 1;
        }

        Self { ips, index: 0 }
    }

    /// Selects the next IP in round-robin fashion.
    #[inline(always)]
    pub fn next_round_robin(&mut self) -> Ipv4Addr {
        let ip = self.ips[self.index];
        self.index = (self.index + 1) % self.ips.len();
        ip
    }

    /// Selects a random IP from the pool.
    #[inline(always)]
    pub fn next_random(&self, prng: &mut FastPrng) -> Ipv4Addr {
        let idx = (prng.next_u32() as usize) % self.ips.len();
        self.ips[idx]
    }

    /// Total number of unique IPs in this pool.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.ips.len()
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty()
    }

    pub fn ips(&self) -> &[Ipv4Addr] {
        &self.ips
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fast_prng_distribution() {
        let mut prng = FastPrng::new(42);
        for _ in 0..1000 {
            let val = prng.gen_range(10, 50);
            assert!(val >= 10 && val <= 50);
        }
    }

    #[test]
    fn test_packet_protocol_as_str() {
        assert_eq!(PacketProtocol::Tcp.as_str(), "tcp");
        assert_eq!(PacketProtocol::Udp.as_str(), "udp");
        assert_eq!(PacketProtocol::Icmp.as_str(), "icmp");
        assert_eq!(PacketProtocol::Icmpv6.as_str(), "icmpv6");
        assert_eq!(PacketProtocol::Other.as_str(), "other");
    }

    #[test]
    fn test_fast_prng_default_and_next_u16() {
        let mut default_prng = FastPrng::default();
        let mut seeded_prng = FastPrng::new(0x853c49e6748fea9b);
        assert_eq!(default_prng.next_u64(), seeded_prng.next_u64());

        let value = default_prng.next_u16();
        assert!(value <= u16::MAX);
        assert_eq!(value, (seeded_prng.next_u64() >> 48) as u16);
    }

    #[test]
    fn test_fast_prng_gen_range_edges() {
        let mut prng = FastPrng::new(7);
        // min >= max: returned value is `min` regardless of PRNG state
        assert_eq!(prng.gen_range(5, 5), 5);
        assert_eq!(prng.gen_range(10, 9), 10);
        // Inclusive range stays within bounds
        for _ in 0..500 {
            let v = prng.gen_range(3, 6);
            assert!(v >= 3 && v <= 6);
        }
    }

    #[test]
    fn test_ip_pool_round_robin_wraparound() {
        let mut pool = IpPool::new_blocked_pool(2);
        assert_eq!(pool.len(), 2);
        assert!(!pool.is_empty());
        let first = pool.next_round_robin();
        let second = pool.next_round_robin();
        // Wrap-around returns the first element again.
        assert_eq!(pool.next_round_robin(), first);
        assert_ne!(first, second);
    }

    #[test]
    fn test_protocol_choice_parsing() {
        assert_eq!(
            ProtocolChoice::from_str("tcp").unwrap(),
            ProtocolChoice::Tcp
        );
        assert_eq!(
            ProtocolChoice::from_str("UDP").unwrap(),
            ProtocolChoice::Udp
        );
        assert_eq!(
            ProtocolChoice::from_str("icmp").unwrap(),
            ProtocolChoice::Icmp
        );
        assert_eq!(
            ProtocolChoice::from_str("icmpv6").unwrap(),
            ProtocolChoice::Icmpv6
        );
        assert_eq!(
            ProtocolChoice::from_str("other").unwrap(),
            ProtocolChoice::Other
        );
        assert_eq!(
            ProtocolChoice::from_str("mixed").unwrap(),
            ProtocolChoice::Mixed
        );
        assert!(ProtocolChoice::from_str("invalid").is_err());
    }

    #[test]
    fn test_protocol_mixed_distribution() {
        let mut prng = FastPrng::new(12345);
        let choice = ProtocolChoice::Mixed;

        let mut tcp = 0;
        let mut udp = 0;
        let mut icmp = 0;
        let mut icmpv6 = 0;
        let mut other = 0;

        let iterations = 10_000;
        for _ in 0..iterations {
            match choice.select(&mut prng) {
                PacketProtocol::Tcp => tcp += 1,
                PacketProtocol::Udp => udp += 1,
                PacketProtocol::Icmp => icmp += 1,
                PacketProtocol::Icmpv6 => icmpv6 += 1,
                PacketProtocol::Other => other += 1,
            }
        }

        // Check approximate proportions (40%, 35%, 15%, 5%, 5%)
        assert!(tcp > 3500 && tcp < 4500, "TCP count: {}", tcp);
        assert!(udp > 3000 && udp < 4000, "UDP count: {}", udp);
        assert!(icmp > 1100 && icmp < 1900, "ICMP count: {}", icmp);
        assert!(icmpv6 > 250 && icmpv6 < 750, "ICMPv6 count: {}", icmpv6);
        assert!(other > 250 && other < 750, "Other count: {}", other);
    }

    #[test]
    fn test_ip_pool_generation_count() {
        let pool = IpPool::new_blocked_pool(100);
        assert_eq!(pool.len(), 100);

        // Verify uniqueness
        let mut set = std::collections::HashSet::new();
        for &ip in pool.ips() {
            assert!(set.insert(ip), "Duplicate IP found: {}", ip);
        }

        // Verify known exact IPs are present
        for &exact in &EXACT_BLOCKED_IPV4 {
            assert!(set.contains(&exact), "Missing exact IP: {}", exact);
        }
    }
}
