// Website-entry validation shared by configuration loading and privileged
// start validation. Walden blocks hostnames, not individual URL paths, so an
// HTTP(S) URL is reduced to its host while malformed input is rejected.

use std::net::Ipv4Addr;

use anyhow::{bail, ensure};

/// Shared label rules for dotted hostnames. Callers choose whether underscores
/// are permitted and whether a trailing dot is rejected.
fn valid_dotted_name(name: &str, allow_underscore: bool, reject_trailing_dot: bool) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    if reject_trailing_dot && name.ends_with('.') {
        return false;
    }

    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || byte == b'-'
                    || (allow_underscore && byte == b'_')
            })
    })
}

/// Hostname for a user-configured website entry (RFC 1123 labels; no underscores).
pub(crate) fn valid_user_hostname(host: &str) -> bool {
    valid_dotted_name(host, false, false)
}

/// Domain line in a walden-list `domains-v1` category file. Upstream lists
/// sometimes include underscores: they are not legal in an RFC 1123 hostname,
/// but they resolve and Walden must not treat them as nonexistent.
pub(crate) fn valid_catalog_domain(domain: &str) -> bool {
    valid_dotted_name(domain, true, true)
}

/// Converts a hostname or HTTP(S) URL into the exact hostname Walden blocks.
/// A bare hostname also accepts a path or port, which are discarded because
/// the blocking backends operate at hostname/address level.
pub fn normalize_website(input: &str) -> anyhow::Result<String> {
    let input = input.trim();
    ensure!(!input.is_empty(), "website is empty");
    ensure!(
        !input.chars().any(char::is_whitespace),
        "website contains whitespace"
    );

    let (authority_and_path, had_scheme) = match input.split_once("://") {
        Some((scheme, rest)) => {
            ensure!(
                scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https"),
                "unsupported URL scheme {scheme:?}; only http and https are accepted"
            );
            (rest, true)
        }
        None => (input, false),
    };

    let authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    ensure!(!authority.is_empty(), "website has no hostname");

    let authority = if had_scheme {
        authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host)
    } else {
        ensure!(
            !authority.contains('@'),
            "credentials require an http(s) URL"
        );
        authority
    };

    ensure!(
        !authority.starts_with('['),
        "IPv6 literals are not supported as website entries"
    );
    ensure!(
        authority.matches(':').count() <= 1,
        "website contains an invalid hostname or port"
    );

    let host = match authority.rsplit_once(':') {
        Some((host, port)) => {
            ensure!(!host.is_empty(), "website has no hostname");
            let port: u16 = port
                .parse()
                .map_err(|_| anyhow::anyhow!("website has invalid port {port:?}"))?;
            ensure!(port > 0, "website port must be greater than zero");
            host
        }
        None => authority,
    };

    let host = host.trim_end_matches('.').to_ascii_lowercase();
    ensure!(!host.is_empty(), "website has no hostname");
    ensure!(
        host.is_ascii(),
        "internationalized hostnames must be written in ASCII form"
    );

    if host
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        && host.parse::<Ipv4Addr>().is_err()
    {
        bail!("website contains an invalid IPv4 address {host:?}");
    }

    ensure!(
        valid_user_hostname(&host),
        "website contains invalid hostname {host:?}"
    );
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_urls_without_changing_the_hostname() {
        assert_eq!(
            normalize_website(" HTTPS://www.Example.com:443/a/path?q=1 ").unwrap(),
            "www.example.com"
        );
        assert_eq!(
            normalize_website("example.com/path").unwrap(),
            "example.com"
        );
        assert_eq!(normalize_website("example.com.").unwrap(), "example.com");
    }

    #[test]
    fn rejects_input_instead_of_deleting_invalid_characters() {
        assert!(normalize_website("exam!ple.com").is_err());
        assert!(normalize_website("https://").is_err());
        assert!(normalize_website("ftp://example.com").is_err());
        assert!(normalize_website("999.1.1.1").is_err());
        assert!(normalize_website("*.example.com").is_err());
    }

    #[test]
    fn credentials_are_only_accepted_as_part_of_a_url() {
        assert_eq!(
            normalize_website("https://user:pass@example.com/private").unwrap(),
            "example.com"
        );
        assert!(normalize_website("user@example.com").is_err());
    }
}
