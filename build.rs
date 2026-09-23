use std::env;
use std::fs;
use std::path::Path;
use std::process::Command;

fn watch_rust_sources(path: &Path) {
    for entry in fs::read_dir(path).expect("failed to list Rust sources") {
        let entry = entry.expect("failed to inspect Rust source");
        let path = entry.path();
        if path.is_dir() {
            watch_rust_sources(&path);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
}

fn main() {
    watch_rust_sources(Path::new("src"));
    for path in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "scripts/source-fingerprint.sh",
        "src/dns_query.c",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    cc::Build::new()
        .file("src/dns_query.c")
        .compile("walden_dns_query");
    println!("cargo:rustc-link-lib=resolv");

    let output = Command::new("sh")
        .arg("scripts/source-fingerprint.sh")
        .output()
        .expect("failed to calculate the Walden source fingerprint");
    assert!(
        output.status.success(),
        "source fingerprint command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let build_id = String::from_utf8(output.stdout)
        .expect("source fingerprint is not UTF-8")
        .trim()
        .to_string();
    assert_eq!(build_id.len(), 64, "source fingerprint is not SHA-256");

    println!("cargo:rustc-env=WALDEN_BUILD_ID={build_id}");
    println!(
        "cargo:rustc-env=WALDEN_BUILD_TARGET={}",
        env::var("TARGET").expect("Cargo did not provide TARGET")
    );
    println!(
        "cargo:rustc-env=WALDEN_BUILD_PROFILE={}",
        env::var("PROFILE").expect("Cargo did not provide PROFILE")
    );
    println!(
        "cargo:rustc-env=WALDEN_BUILD_EPOCH={}",
        env::var("SOURCE_DATE_EPOCH").unwrap_or_else(|_| "not-set".to_string())
    );
}
