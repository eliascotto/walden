// DNS resolution for firewall layers; literals are parsed without lookup.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::ffi::{CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

pub const POSITIVE_TTL: Duration = Duration::from_secs(15 * 60);
const NEGATIVE_TTL: Duration = Duration::from_secs(5 * 60);
const TEMPORARY_RETRY: Duration = Duration::from_secs(30);

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
        failure_kind: *mut libc::c_int,
    ) -> libc::c_int;
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolvedAddr {
    Host(IpAddr),        // A DNS-resolved IP address
    Network(IpAddr, u8), // A literal CIDR block
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ResolveProgress {
    pub completed: usize,
    pub total: usize,
    pub resolved_addresses: usize,
    pub failed_lookups: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LookupFailure {
    NoRecords,
    Temporary,
}

#[derive(Clone, Default)]
struct Resolution {
    addresses: Vec<ResolvedAddr>,
    failed: bool,
    failure: Option<LookupFailure>,
}

struct CachedResolution {
    result: Resolution,
    expires: Instant,
    failures: u32,
}

#[derive(Default)]
pub struct ResolutionCache {
    entries: BTreeMap<String, CachedResolution>,
}

impl ResolutionCache {
    pub fn next_refresh(&self) -> Option<Instant> {
        self.entries.values().map(|entry| entry.expires).min()
    }

    fn store(&mut self, hostname: String, mut result: Resolution) {
        let previous = self.entries.get(&hostname);
        let failures = if result.failure == Some(LookupFailure::Temporary) {
            previous.map_or(1, |entry| entry.failures.saturating_add(1))
        } else {
            0
        };
        if result.failure == Some(LookupFailure::Temporary)
            && let Some(previous) = previous
        {
            // A failed address-family refresh must not discard working answers.
            result
                .addresses
                .extend(previous.result.addresses.iter().cloned());
            result.addresses.sort();
            result.addresses.dedup();
        }
        let ttl = match result.failure {
            None => POSITIVE_TTL,
            Some(LookupFailure::NoRecords) => NEGATIVE_TTL,
            Some(LookupFailure::Temporary) => TEMPORARY_RETRY
                .saturating_mul(1_u32 << failures.saturating_sub(1).min(4))
                .min(NEGATIVE_TTL),
        };
        self.entries.insert(
            hostname,
            CachedResolution {
                result,
                expires: Instant::now() + ttl,
                failures,
            },
        );
    }
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

fn dns_query(name: &CStr, record_type: i32) -> Result<Vec<IpAddr>, LookupFailure> {
    let mut packet = vec![0u8; MAX_DNS_RESPONSE];
    // SAFETY: name is NUL-terminated and packet is writable for its full
    // capacity. The C wrapper creates a separate resolver state per call.
    let mut failure_kind = 2;
    let length = unsafe {
        walden_dns_query(
            name.as_ptr(),
            record_type,
            packet.as_mut_ptr(),
            MAX_DNS_RESPONSE as libc::c_int,
            &mut failure_kind,
        )
    };
    if length <= 0 {
        return Err(if failure_kind == 1 {
            LookupFailure::NoRecords
        } else {
            LookupFailure::Temporary
        });
    }
    addresses_from_dns_response(&packet[..length as usize], record_type)
        .ok_or(LookupFailure::Temporary)
}

// Query DNS rather than the host-name service. The latter consults Walden's
// /etc/hosts section and would only return its 0.0.0.0 and :: entries.
fn resolve_via_dns(hostname: &str) -> Resolution {
    let Ok(name) = CString::new(hostname) else {
        return Resolution {
            addresses: Vec::new(),
            failed: true,
            failure: Some(LookupFailure::NoRecords),
        };
    };
    let mut addrs = HashSet::new();
    let mut temporary_failure = false;
    for record_type in [DNS_TYPE_A, DNS_TYPE_AAAA] {
        match dns_query(&name, record_type) {
            Ok(addresses) => addrs.extend(
                addresses
                    .into_iter()
                    .filter(|address| !address.is_unspecified()),
            ),
            Err(LookupFailure::Temporary) => temporary_failure = true,
            Err(LookupFailure::NoRecords) => {}
        }
    }
    let failure = if temporary_failure {
        Some(LookupFailure::Temporary)
    } else if addrs.is_empty() {
        Some(LookupFailure::NoRecords)
    } else {
        None
    };
    let mut addrs: Vec<IpAddr> = addrs.into_iter().collect();
    addrs.sort();
    Resolution {
        addresses: addrs.into_iter().map(ResolvedAddr::Host).collect(),
        failed: failure.is_some(),
        failure,
    }
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
    resolve_via_dns(host)
}

fn resolve_results_concurrently(
    hosts: Vec<(String, String)>,
    consume: &mut dyn FnMut(String, Resolution) -> bool,
    resolve: Arc<ResolverFn>,
) {
    let workers = resolve_worker_count(hosts.len());
    let jobs = Arc::new(hosts);
    let next_job = Arc::new(AtomicUsize::new(0));
    let cancelled = Arc::new(AtomicBool::new(false));
    let (result_tx, result_rx) = mpsc::channel();
    let mut handles = Vec::new();
    for _ in 0..workers {
        let jobs = Arc::clone(&jobs);
        let next_job = Arc::clone(&next_job);
        let cancelled = Arc::clone(&cancelled);
        let result_tx = result_tx.clone();
        let resolve = Arc::clone(&resolve);
        handles.push(thread::spawn(move || {
            while !cancelled.load(Ordering::Acquire) {
                let index = next_job.fetch_add(1, Ordering::Relaxed);
                let Some((entry, host)) = jobs.get(index) else {
                    break;
                };
                if result_tx
                    .send((entry.clone(), resolve(entry, host)))
                    .is_err()
                {
                    break;
                }
            }
        }));
    }
    drop(result_tx);
    for (entry, result) in &result_rx {
        if !consume(entry, result) {
            break;
        }
    }
    cancelled.store(true, Ordering::Release);
    drop(result_rx);
    // Drain bounded in-flight calls before allowing another apply or cleanup.
    // C resolver state limits each query's wait and retry count.
    for handle in handles {
        let _ = handle.join();
    }
}

pub fn resolve_cached(
    hosts: &[String],
    cache: &mut ResolutionCache,
    progress: &mut dyn FnMut(ResolveProgress) -> bool,
) -> BTreeSet<ResolvedAddr> {
    resolve_cached_with(hosts, cache, progress, Arc::new(resolve_one))
}

fn resolve_cached_with(
    hosts: &[String],
    cache: &mut ResolutionCache,
    progress: &mut dyn FnMut(ResolveProgress) -> bool,
    resolve: Arc<ResolverFn>,
) -> BTreeSet<ResolvedAddr> {
    let selected: BTreeSet<&str> = hosts.iter().map(String::as_str).collect();
    cache
        .entries
        .retain(|hostname, _| selected.contains(hostname.as_str()));
    let mut results = BTreeSet::new();
    let mut pending = Vec::new();
    let mut completed = 0;
    let mut failed = 0;
    let mut total = 0;
    let now = Instant::now();
    for entry in hosts {
        let (host, prefix_len) = parse_entry(entry);
        match IpAddr::from_str(host) {
            Ok(addr) => {
                results.insert(match prefix_len {
                    Some(len) => ResolvedAddr::Network(addr, len),
                    None => ResolvedAddr::Host(addr),
                });
            }
            Err(_) => {
                total += 1;
                if let Some(cached) = cache
                    .entries
                    .get(entry)
                    .filter(|cached| cached.expires > now)
                {
                    completed += 1;
                    failed += usize::from(cached.result.failed);
                    results.extend(cached.result.addresses.iter().cloned());
                } else {
                    pending.push((entry.clone(), host.to_string()));
                }
            }
        }
    }
    if !progress(ResolveProgress {
        completed,
        total,
        resolved_addresses: results.len(),
        failed_lookups: failed,
    }) {
        return BTreeSet::new();
    }
    resolve_results_concurrently(
        pending,
        &mut |entry, result| {
            completed += 1;
            failed += usize::from(result.failed);
            cache.store(entry.clone(), result);
            results.extend(cache.entries[&entry].result.addresses.iter().cloned());
            progress(ResolveProgress {
                completed,
                total,
                resolved_addresses: results.len(),
                failed_lookups: failed,
            })
        },
        resolve,
    );
    if completed == total && failed > 0 {
        crate::daemon_log!(
            "walden: {failed}/{total} hostnames have missing or incomplete DNS answers; hosts blocking remains active"
        );
    }
    results
}

pub fn resolve_all_with_progress(
    hosts: &[String],
    progress: &mut dyn FnMut(ResolveProgress) -> bool,
) -> BTreeSet<ResolvedAddr> {
    resolve_cached(hosts, &mut ResolutionCache::default(), progress)
}

#[cfg(test)]
fn resolve_hostnames_concurrently(
    hosts: Vec<(String, String)>,
    progress: &mut dyn FnMut(ResolveProgress) -> bool,
    resolve: Arc<ResolverFn>,
) -> Vec<ResolvedAddr> {
    let total = hosts.len();
    let mut completed = 0;
    let mut failed = 0;
    let mut addresses = Vec::new();
    if !progress(ResolveProgress {
        completed,
        total,
        resolved_addresses: 0,
        failed_lookups: 0,
    }) {
        return addresses;
    }
    resolve_results_concurrently(
        hosts,
        &mut |_, result| {
            completed += 1;
            failed += usize::from(result.failed);
            addresses.extend(result.addresses);
            progress(ResolveProgress {
                completed,
                total,
                resolved_addresses: addresses.len(),
                failed_lookups: failed,
            })
        },
        resolve,
    );
    addresses
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

    #[test]
    fn only_expired_temporary_failures_are_queried_again() {
        use std::sync::Mutex;
        let calls = Arc::new(Mutex::new(BTreeMap::<String, usize>::new()));
        let observed = calls.clone();
        let resolve: Arc<ResolverFn> = Arc::new(move |_, host| {
            *observed.lock().unwrap().entry(host.into()).or_default() += 1;
            match host {
                "good.test" => Resolution {
                    addresses: vec![ResolvedAddr::Host("203.0.113.1".parse().unwrap())],
                    ..Resolution::default()
                },
                "missing.test" => Resolution {
                    failed: true,
                    failure: Some(LookupFailure::NoRecords),
                    ..Resolution::default()
                },
                _ => Resolution {
                    failed: true,
                    failure: Some(LookupFailure::Temporary),
                    ..Resolution::default()
                },
            }
        });
        let hosts = vec![
            "good.test".into(),
            "missing.test".into(),
            "slow.test".into(),
        ];
        let mut cache = ResolutionCache::default();
        let first = resolve_cached_with(&hosts, &mut cache, &mut |_| true, resolve.clone());
        let second = resolve_cached_with(&hosts, &mut cache, &mut |_| true, resolve.clone());
        assert_eq!(first, second);
        assert!(calls.lock().unwrap().values().all(|count| *count == 1));
        assert!(cache.entries["missing.test"].expires > cache.entries["slow.test"].expires);
        cache.entries.get_mut("slow.test").unwrap().expires =
            Instant::now() - Duration::from_secs(1);
        let mut summary = None;
        resolve_cached_with(
            &hosts,
            &mut cache,
            &mut |progress| {
                summary = Some(progress);
                true
            },
            resolve,
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls["good.test"], 1);
        assert_eq!(calls["missing.test"], 1);
        assert_eq!(calls["slow.test"], 2);
        assert_eq!(summary.unwrap().completed, 3);
        assert_eq!(summary.unwrap().failed_lookups, 2);
    }

    #[test]
    fn transient_family_failure_preserves_previous_answers_and_backs_off() {
        let mut cache = ResolutionCache::default();
        cache.store(
            "host.test".into(),
            Resolution {
                addresses: vec![
                    ResolvedAddr::Host("203.0.113.1".parse().unwrap()),
                    ResolvedAddr::Host("2001:db8::1".parse().unwrap()),
                ],
                ..Resolution::default()
            },
        );
        for _ in 0..2 {
            cache.store(
                "host.test".into(),
                Resolution {
                    addresses: vec![ResolvedAddr::Host("203.0.113.1".parse().unwrap())],
                    failed: true,
                    failure: Some(LookupFailure::Temporary),
                },
            );
        }
        assert_eq!(cache.entries["host.test"].result.addresses.len(), 2);
        assert!(cache.entries["host.test"].expires > Instant::now() + Duration::from_secs(55));
    }

    #[test]
    fn cancellation_drains_in_flight_workers_before_returning() {
        let active = Arc::new(AtomicUsize::new(0));
        let observed = active.clone();
        let resolver: Arc<ResolverFn> = Arc::new(move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(20));
            observed.fetch_sub(1, Ordering::SeqCst);
            Resolution::default()
        });
        let jobs = (0..1000)
            .map(|index| (format!("host-{index}.test"), format!("host-{index}.test")))
            .collect();
        resolve_results_concurrently(jobs, &mut |_, _| false, resolver);
        assert_eq!(active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn native_dns_query_has_a_bounded_wait_for_a_nonresponding_local_server() {
        unsafe extern "C" {
            fn walden_dns_query_test(
                name: *const libc::c_char,
                kind: libc::c_int,
                answer: *mut u8,
                capacity: libc::c_int,
                failure: *mut libc::c_int,
                port: u16,
            ) -> libc::c_int;
        }
        let server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut answer = vec![0u8; MAX_DNS_RESPONSE];
        let mut failure = 0;
        let started = Instant::now();
        // SAFETY: all buffers and pointers remain valid for this synchronous
        // call; the server is a private local blackhole, never a system change.
        let result = unsafe {
            walden_dns_query_test(
                c"timeout.test".as_ptr(),
                DNS_TYPE_A,
                answer.as_mut_ptr(),
                answer.len() as libc::c_int,
                &mut failure,
                server.local_addr().unwrap().port(),
            )
        };
        assert!(result < 0);
        assert_eq!(failure, 2);
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "DNS query exceeded its bounded wait: {:?}",
            started.elapsed()
        );
    }
}
