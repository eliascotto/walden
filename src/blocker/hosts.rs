// Blocking using /etc/hosts

use anyhow::Context;
use std::fs;
use std::process::{Command, Stdio};

use crate::blocker::common::ConfigStatus;
use crate::common::{self, IS_LINUX, IS_MACOS};

const HOSTS_FILE: &str = "/etc/hosts";
const HOSTS_MODE: u32 = 0o644;

// Hosts file markers
const WALDEN_START: &str = "#<walden>";
const WALDEN_END: &str = "#</walden>";

fn read_hosts() -> anyhow::Result<String> {
    fs::read_to_string(HOSTS_FILE).with_context(|| format!("failed to read {HOSTS_FILE}"))
}

fn write_hosts(lines: &[String]) -> anyhow::Result<()> {
    let contents = lines.join("\n") + "\n";

    common::write_atomically_with_mode(HOSTS_FILE, contents.as_bytes(), HOSTS_MODE)
        .with_context(|| format!("failed to update {HOSTS_FILE}"))
}

// Both families, or an AAAA-only lookup walks straight past the v4 entry.
fn push_null_routes(lines: &mut Vec<String>, name: &str) {
    lines.push(format!("0.0.0.0 {name}"));
    lines.push(format!(":: {name}"));
}

fn walden_section(block_list: &[String]) -> Vec<String> {
    let mut lines = vec![WALDEN_START.to_string()];

    for entry in block_list {
        push_null_routes(&mut lines, entry);
        // Entries already carrying a www. prefix are left alone
        if !entry.starts_with("www.") {
            push_null_routes(&mut lines, &format!("www.{entry}"));
        }
    }

    lines.push(WALDEN_END.to_string());
    lines
}

fn split_walden_section(contents: &str) -> (Vec<&str>, Vec<&str>) {
    let mut kept = Vec::new();
    let mut section = Vec::new();
    let mut inside = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        let is_end = trimmed == WALDEN_END;

        if trimmed == WALDEN_START {
            inside = true;
        }

        if inside || is_end {
            section.push(line);
        } else {
            kept.push(line);
        }

        if is_end {
            inside = false;
        }
    }

    (kept, section)
}

// Partial means the section drifted -- edited, truncated, or written for
// another block list -- and is repaired like Absent, by replacing it wholesale.
fn section_status(section: &[&str], expected: &[String]) -> ConfigStatus {
    if section.is_empty() {
        ConfigStatus::Absent
    } else if section == expected {
        ConfigStatus::Present
    } else {
        ConfigStatus::Partial
    }
}

// A resolver caching in front of /etc/hosts keeps serving the answer it already
// has, and neither platform has a single cache to clear. Best effort: one that
// is not installed has nothing to flush, and the block is already applied, so a
// failure here must not fail it.
fn flush_dns_caches() {
    fn run_quietly(program: &str, args: &[&str]) {
        let _ = Command::new(program)
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    if IS_MACOS {
        run_quietly("dscacheutil", &["-flushcache"]);
        // SIGHUP reloads mDNSResponder rather than restarting it.
        run_quietly("killall", &["-HUP", "mDNSResponder"]);
    }

    if IS_LINUX {
        // systemd-resolved, then the caches that front glibc on setups without it.
        run_quietly("resolvectl", &["flush-caches"]);
        run_quietly("nscd", &["--invalidate=hosts"]);
        run_quietly("killall", &["-HUP", "dnsmasq"]);
    }
}

pub fn hosts_status(block_list: &[String]) -> anyhow::Result<ConfigStatus> {
    let contents = read_hosts()?;
    let (_, section) = split_walden_section(&contents);

    Ok(section_status(&section, &walden_section(block_list)))
}

// Whether a section is there at all, whatever it holds. Answers the startup
// question `hosts_status` cannot: whether an earlier block left entries behind,
// at a point where the block list they were written for is unknown.
pub fn has_section() -> anyhow::Result<bool> {
    let contents = read_hosts()?;
    let (_, section) = split_walden_section(&contents);

    Ok(!section.is_empty())
}

// Any existing section is dropped before the new one is appended, so calling
// this again -- on daemon restart, after a reboot, or on a timer -- re-asserts
// the same state instead of stacking another copy of it.
pub fn block(block_list: &[String]) -> anyhow::Result<()> {
    let contents = read_hosts()?;
    let (kept, section) = split_walden_section(&contents);
    let expected = walden_section(block_list);

    if section_status(&section, &expected) == ConfigStatus::Present {
        return Ok(());
    }

    let mut lines: Vec<String> = kept.into_iter().map(str::to_string).collect();
    lines.push(String::new()); // new-line
    lines.extend(expected);

    write_hosts(&lines)?;
    flush_dns_caches();
    Ok(())
}

pub fn unblock() -> anyhow::Result<()> {
    let contents = read_hosts()?;
    let (kept, section) = split_walden_section(&contents);

    if section.is_empty() {
        return Ok(());
    }

    let kept: Vec<String> = kept.into_iter().map(str::to_string).collect();

    write_hosts(&kept)?;
    flush_dns_caches();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block_list() -> Vec<String> {
        vec!["example.com".to_string()]
    }

    #[test]
    fn absent_when_the_file_has_no_section() {
        let (_, section) = split_walden_section("127.0.0.1 localhost\n");

        assert_eq!(
            section_status(&section, &walden_section(&block_list())),
            ConfigStatus::Absent
        );
    }

    #[test]
    fn present_when_the_section_matches_the_block_list() {
        let contents = format!(
            "127.0.0.1 localhost\n{}\n",
            walden_section(&block_list()).join("\n")
        );
        let (kept, section) = split_walden_section(&contents);

        assert_eq!(kept, ["127.0.0.1 localhost"]);
        assert_eq!(
            section_status(&section, &walden_section(&block_list())),
            ConfigStatus::Present
        );
    }

    #[test]
    fn partial_when_the_section_was_written_for_another_block_list() {
        let contents = format!(
            "{}\n",
            walden_section(&["other.com".to_string()]).join("\n")
        );
        let (_, section) = split_walden_section(&contents);

        assert_eq!(
            section_status(&section, &walden_section(&block_list())),
            ConfigStatus::Partial
        );
    }

    #[test]
    fn an_unterminated_section_is_claimed_to_the_end_of_the_file() {
        let contents = "127.0.0.1 localhost\n#<walden>\n0.0.0.0 example.com\n";
        let (kept, section) = split_walden_section(contents);

        assert_eq!(kept, ["127.0.0.1 localhost"]);
        assert_eq!(section, ["#<walden>", "0.0.0.0 example.com"]);
    }

    #[test]
    fn an_orphan_end_marker_is_claimed_on_its_own() {
        let (kept, section) = split_walden_section("127.0.0.1 localhost\n#</walden>\n");

        assert_eq!(kept, ["127.0.0.1 localhost"]);
        assert_eq!(section, ["#</walden>"]);
    }

    #[test]
    fn entries_already_prefixed_with_www_are_not_prefixed_again() {
        let section = walden_section(&["www.example.com".to_string()]);

        assert!(!section.iter().any(|line| line.contains("www.www.")));
    }
}
