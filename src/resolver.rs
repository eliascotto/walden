// DNS resolution for firewall layers; literals are parsed without lookup.

use std::collections::{BTreeSet, HashSet};
use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;

const MIN_RESOLVE_WORKERS: usize = 4;
const MAX_RESOLVE_WORKERS: usize = 64;
const MAX_DNS_RESPONSE: usize = 65_535;
const DNS_TYPE_A: i32 = 1;
const DNS_TYPE_AAAA: i32 = 28;

unsafe extern "C" {
    fn walden_dns_query(
        name: *const libc::c_char,
        record_type: libc::c_int,
        answer: *mut u8,
        answer_capacity: libc::c_int,
    ) -> libc::c_int;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolvedAddr {
    Host(IpAddr),        // A DNS-resolved IP address
    Network(IpAddr, u8), // A literal CIDR block
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResolveProgress {
    pub completed: usize,
    pub total: usize,
    pub resolved_addresses: usize,
    pub failed_lookups: usize,
}

#[derive(Default)]
struct Resolution {
    addresses: Vec<ResolvedAddr>,
    failed: bool,
}

type ResolverFn = dyn Fn(&str, &str) -> Resolution + Send + Sync;

fn resolve_worker_count(jobs: usize) -> usize {
    if jobs == 0 {
        return 0;
    }

    let parallelism = thread::available_parallelism()
        .map(std::num::NonZero::get)
        .unwrap_or(MIN_RESOLVE_WORKERS)
        .clamp(MIN_RESOLVE_WORKERS, MAX_RESOLVE_WORKERS);

    parallelism.min(jobs)
}

fn dns_number(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        packet.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn skip_dns_name(packet: &[u8], mut offset: usize) -> Option<usize> {
    loop {
        let label = *packet.get(offset)?;
        if label & 0xc0 == 0xc0 {
            packet.get(offset + 1)?;
            return Some(offset + 2);
        }
        if label & 0xc0 != 0 {
            return None;
        }
        offset += 1;
        if label == 0 {
            return Some(offset);
        }
        offset = offset.checked_add(usize::from(label))?;
        packet.get(offset - 1)?;
    }
}

fn addresses_from_dns_response(packet: &[u8], record_type: i32) -> Option<Vec<IpAddr>> {
    if packet.len() < 12 || packet[2] & 0x80 == 0 || packet[2] & 0x02 != 0 || packet[3] & 0x0f != 0
    {
        return None;
    }

    let questions = usize::from(dns_number(packet, 4)?);
    let answers = usize::from(dns_number(packet, 6)?);
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_dns_name(packet, offset)?.checked_add(4)?;
        packet.get(offset - 1)?;
    }

    let mut addresses = Vec::new();
    for _ in 0..answers {
        offset = skip_dns_name(packet, offset)?;
        let kind = dns_number(packet, offset)?;
        let class = dns_number(packet, offset + 2)?;
        let length = usize::from(dns_number(packet, offset + 8)?);
        offset = offset.checked_add(10)?;
        let data = packet.get(offset..offset.checked_add(length)?)?;
        if class == 1 && i32::from(kind) == record_type {
            match data {
                [a, b, c, d] if record_type == DNS_TYPE_A => {
                    addresses.push(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)));
                }
                bytes if bytes.len() == 16 && record_type == DNS_TYPE_AAAA => {
                    addresses.push(IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(bytes).ok()?,
                    )));
                }
                _ => return None,
            }
        }
        offset += length;
    }
    Some(addresses)
}

fn dns_query(name: &CStr, record_type: i32) -> Option<Vec<IpAddr>> {
    let mut packet = vec![0u8; MAX_DNS_RESPONSE];
    // SAFETY: name is NUL-terminated and packet is writable for its full
    // capacity. The C wrapper creates a separate resolver state per call.
    let length = unsafe {
        walden_dns_query(
            name.as_ptr(),
            record_type,
            packet.as_mut_ptr(),
            MAX_DNS_RESPONSE as libc::c_int,
        )
    };
    if length <= 0 {
        return None;
    }
    addresses_from_dns_response(packet.get(..usize::try_from(length).ok()?)?, record_type)
}

// Query DNS rather than the host-name service. The latter consults Walden's
// /etc/hosts section and would only return its 0.0.0.0 and :: entries.
fn resolve_via_dns(hostname: &str) -> anyhow::Result<Vec<IpAddr>> {
    let name = CString::new(hostname)?;
    let mut addrs = HashSet::new();
    for record_type in [DNS_TYPE_A, DNS_TYPE_AAAA] {
        if let Some(addresses) = dns_query(&name, record_type) {
            addrs.extend(
                addresses
                    .into_iter()
                    .filter(|address| !address.is_unspecified()),
            );
        }
    }
    anyhow::ensure!(!addrs.is_empty(), "no DNS addresses for {hostname}");
    let mut addrs: Vec<IpAddr> = addrs.into_iter().collect();
    addrs.sort();
    Ok(addrs)
}

fn parse_entry(entry: &str) -> (&str, Option<u8>) {
    let (head, mask) = entry
        .rsplit_once('/')
        .map(|(h, m)| (h, m.parse::<u8>().ok()))
        .unwrap_or((entry, None));

    let host = head.split(':').next().unwrap_or(head);

    (host, mask)
}

fn resolve_one(_entry: &str, host: &str) -> Resolution {
    // Direct resolver calls have no portable cancellation API. Do not create another
    // thread for every lookup just to impose a timeout: a large catalog then
    // creates tens of thousands of detached resolver threads, exhausting the
    // daemon precisely while it is trying to start a block.  The bounded
    // worker pool below is the concurrency limit; a slow system resolver can
    // occupy at most MAX_RESOLVE_WORKERS threads and never blocks IPC.
    match resolve_via_dns(host) {
        Ok(addresses) => Resolution {
            addresses: addresses.into_iter().map(ResolvedAddr::Host).collect(),
            failed: false,
        },
        Err(_) => Resolution {
            addresses: Vec::new(),
            failed: true,
        },
    }
}

fn resolve_hostnames_concurrently(
    hosts: Vec<(String, String)>,
    progress: &mut dyn FnMut(ResolveProgress) -> bool,
    resolve: Arc<ResolverFn>,
) -> Vec<ResolvedAddr> {
    let jobs = hosts.len();
    let workers = resolve_worker_count(jobs);
    if workers == 0 {
        let _ = progress(ResolveProgress {
            completed: 0,
            total: 0,
            resolved_addresses: 0,
            failed_lookups: 0,
        });
        return Vec::new();
    }

    if !progress(ResolveProgress {
        completed: 0,
        total: jobs,
        resolved_addresses: 0,
        failed_lookups: 0,
    }) {
        return Vec::new();
    }

    let jobs = Arc::new(hosts);
    let next_job = Arc::new(AtomicUsize::new(0));
    let cancelled = Arc::new(AtomicBool::new(false));
    let (result_tx, result_rx) = mpsc::channel();

    for _ in 0..workers {
        let jobs = Arc::clone(&jobs);
        let next_job = Arc::clone(&next_job);
        let cancelled = Arc::clone(&cancelled);
        let result_tx = result_tx.clone();
        let resolve = Arc::clone(&resolve);
        thread::spawn(move || {
            loop {
                if cancelled.load(Ordering::Acquire) {
                    break;
                }
                let index = next_job.fetch_add(1, Ordering::Relaxed);
                let Some((entry, host)) = jobs.get(index) else {
                    break;
                };
                if result_tx.send(resolve(entry, host)).is_err() {
                    break;
                }
            }
        });
    }

    drop(result_tx);

    let mut completed = 0;
    let mut failed = 0;
    let mut resolved = Vec::new();
    for result in result_rx {
        completed += 1;
        failed += usize::from(result.failed);
        resolved.extend(result.addresses);
        if !progress(ResolveProgress {
            completed,
            total: jobs.len(),
            resolved_addresses: resolved.len(),
            failed_lookups: failed,
        }) {
            cancelled.store(true, Ordering::Release);
            break;
        }
    }
    cancelled.store(true, Ordering::Release);
    if completed == jobs.len() && failed > 0 {
        eprintln!(
            "walden: {failed}/{} hostnames could not be resolved; hosts blocking remains active and firewall rules will cover the resolved addresses",
            jobs.len()
        );
    }
    resolved
}

pub fn resolve_all_with_progress(
    hosts: &[String],
    progress: &mut dyn FnMut(ResolveProgress) -> bool,
) -> BTreeSet<ResolvedAddr> {
    let mut results = BTreeSet::new();
    let mut pending = Vec::new();

    for entry in hosts {
        let (host, prefix_len) = parse_entry(entry);
        match IpAddr::from_str(host) {
            // Literal IP or CIDR block -- no DNS lookup needed at all.
            Ok(addr) => {
                let resolved = match prefix_len {
                    Some(len) => ResolvedAddr::Network(addr, len),
                    None => ResolvedAddr::Host(addr),
                };
                results.insert(resolved);
            }
            // Hostname -- still needs an actual lookup.
            Err(_) => {
                if prefix_len.is_some() {
                    eprintln!("walden: ignoring CIDR mask on hostname entry {entry}");
                }
                pending.push((entry.clone(), host.to_string()));
            }
        }
    }

    results.extend(resolve_hostnames_concurrently(
        pending,
        progress,
        Arc::new(resolve_one),
    ));
    results
}

pub fn resolve_all(hosts: &[String]) -> BTreeSet<ResolvedAddr> {
    resolve_all_with_progress(hosts, &mut |_| true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn dns_answer(record_type: u16, address: &[u8]) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x81, 0x80, // response, no error
            0, 1, // one question
            0, 1, // one answer
            0, 0, 0, 0, // no authority or additional records
        ];
        packet.extend_from_slice(b"\x07example\x03com\0");
        packet.extend_from_slice(&record_type.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&[0xc0, 0x0c]); // answer name points to question
        packet.extend_from_slice(&record_type.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&(address.len() as u16).to_be_bytes());
        packet.extend_from_slice(address);
        packet
    }

    #[test]
    fn dns_answers_supply_real_addresses_for_firewall_rules() {
        let v4 = dns_answer(1, &[203, 0, 113, 7]);
        let v6 = dns_answer(28, &Ipv6Addr::LOCALHOST.octets());

        assert_eq!(
            addresses_from_dns_response(&v4, DNS_TYPE_A),
            Some(vec!["203.0.113.7".parse().unwrap()])
        );
        assert_eq!(
            addresses_from_dns_response(&v6, DNS_TYPE_AAAA),
            Some(vec![IpAddr::V6(Ipv6Addr::LOCALHOST)])
        );
        assert!(addresses_from_dns_response(&v4[..v4.len() - 1], DNS_TYPE_A).is_none());
    }

    #[test]
    fn resolve_worker_count_is_bounded_and_no_larger_than_the_job_list() {
        assert_eq!(resolve_worker_count(0), 0);
        assert_eq!(resolve_worker_count(1), 1);
        assert!(resolve_worker_count(10_000) <= MAX_RESOLVE_WORKERS);
        assert!(resolve_worker_count(10_000) >= MIN_RESOLVE_WORKERS);
    }

    #[test]
    fn resolve_all_parses_literals_without_dns() {
        let resolved = resolve_all(&["127.0.0.1".to_string(), "10.0.0.0/8".to_string()]);

        assert_eq!(
            resolved,
            BTreeSet::from([
                ResolvedAddr::Host(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                ResolvedAddr::Network(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8),
            ])
        );
    }

    #[test]
    fn cancellation_stops_dequeuing_a_large_resolution_batch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls = Arc::clone(&calls);
        let resolver: Arc<ResolverFn> = Arc::new(move |_, _| {
            resolver_calls.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(1));
            Resolution::default()
        });
        let jobs = (0..50_000)
            .map(|index| {
                let host = format!("host-{index}.example");
                (host.clone(), host)
            })
            .collect();
        let mut last = ResolveProgress {
            completed: 0,
            total: 0,
            resolved_addresses: 0,
            failed_lookups: 0,
        };

        resolve_hostnames_concurrently(
            jobs,
            &mut |progress| {
                last = progress;
                progress.completed < 25
            },
            resolver,
        );

        assert_eq!(last.total, 50_000);
        assert_eq!(last.completed, 25);
        assert!(calls.load(Ordering::SeqCst) < 500);
    }
}
