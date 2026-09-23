use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::resolver::ResolvedAddr;

/// The status of a configuration
#[derive(Debug, PartialEq)]
pub enum ConfigStatus {
    Present,
    Absent,
    Partial,
}

// pf/nft normalize ranges; compare coverage, not printed rule text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AddressRange {
    V4(u32, u32),
    V6(u128, u128),
}

impl AddressRange {
    pub fn host(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => {
                let addr = u32::from(addr);
                Self::V4(addr, addr)
            }
            IpAddr::V6(addr) => {
                let addr = u128::from(addr);
                Self::V6(addr, addr)
            }
        }
    }

    pub fn network(addr: IpAddr, prefix: u8) -> Option<Self> {
        match addr {
            IpAddr::V4(addr) if prefix <= 32 => {
                let addr = u32::from(addr);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                let start = addr & mask;
                Some(Self::V4(start, start | !mask))
            }
            IpAddr::V6(addr) if prefix <= 128 => {
                let addr = u128::from(addr);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                let start = addr & mask;
                Some(Self::V6(start, start | !mask))
            }
            _ => None,
        }
    }

    pub fn between(start: IpAddr, end: IpAddr) -> Option<Self> {
        match (start, end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                let (start, end) = (u32::from(start), u32::from(end));
                (start <= end).then_some(Self::V4(start, end))
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                let (start, end) = (u128::from(start), u128::from(end));
                (start <= end).then_some(Self::V6(start, end))
            }
            _ => None,
        }
    }

    pub fn is_ipv6(self) -> bool {
        matches!(self, Self::V6(_, _))
    }
}

pub fn normalize_address_ranges(mut ranges: Vec<AddressRange>) -> Vec<AddressRange> {
    ranges.sort_unstable();

    let mut normalized: Vec<AddressRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match (normalized.last_mut(), range) {
            (Some(AddressRange::V4(_, previous_end)), AddressRange::V4(start, end))
                if start <= previous_end.saturating_add(1) =>
            {
                *previous_end = (*previous_end).max(end);
            }
            (Some(AddressRange::V6(_, previous_end)), AddressRange::V6(start, end))
                if start <= previous_end.saturating_add(1) =>
            {
                *previous_end = (*previous_end).max(end);
            }
            (_, range) => normalized.push(range),
        }
    }

    normalized
}

pub fn resolved_address_ranges(addrs: &BTreeSet<ResolvedAddr>) -> Option<Vec<AddressRange>> {
    let mut ranges = Vec::with_capacity(addrs.len());

    for addr in addrs {
        let range = match addr {
            ResolvedAddr::Host(addr) => AddressRange::host(*addr),
            ResolvedAddr::Network(addr, prefix) => AddressRange::network(*addr, *prefix)?,
        };
        ranges.push(range);
    }

    Some(normalize_address_ranges(ranges))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn networks_are_masked_to_their_effective_coverage() {
        assert_eq!(
            AddressRange::network(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)), 24),
            Some(AddressRange::V4(
                u32::from(Ipv4Addr::new(192, 0, 2, 0)),
                u32::from(Ipv4Addr::new(192, 0, 2, 255))
            ))
        );

        let addr = "2001:db8::1234".parse::<Ipv6Addr>().unwrap();
        let start = "2001:db8::".parse::<Ipv6Addr>().unwrap();
        let end = "2001:db8::ffff".parse::<Ipv6Addr>().unwrap();
        assert_eq!(
            AddressRange::network(IpAddr::V6(addr), 112),
            Some(AddressRange::V6(u128::from(start), u128::from(end)))
        );
    }

    #[test]
    fn adjacent_and_overlapping_ranges_are_coalesced_by_family() {
        let ranges = vec![
            AddressRange::V4(12, 20),
            AddressRange::V6(1, 2),
            AddressRange::V4(1, 10),
            AddressRange::V4(11, 11),
            AddressRange::V6(3, 4),
        ];

        assert_eq!(
            normalize_address_ranges(ranges),
            [AddressRange::V4(1, 20), AddressRange::V6(1, 4)]
        );
    }

    #[test]
    fn maximum_addresses_do_not_overflow_during_coalescing() {
        assert_eq!(
            normalize_address_ranges(vec![
                AddressRange::V4(u32::MAX, u32::MAX),
                AddressRange::V4(u32::MAX, u32::MAX),
                AddressRange::V6(u128::MAX, u128::MAX),
            ]),
            [
                AddressRange::V4(u32::MAX, u32::MAX),
                AddressRange::V6(u128::MAX, u128::MAX)
            ]
        );
    }

    #[test]
    fn invalid_prefix_lengths_are_rejected() {
        assert_eq!(
            AddressRange::network(IpAddr::V4(Ipv4Addr::LOCALHOST), 33),
            None
        );
        assert_eq!(
            AddressRange::network(IpAddr::V6(Ipv6Addr::LOCALHOST), 129),
            None
        );
    }
}
