// Shared library used by both the `walden` CLI (the controller) and the
// `waldend` daemon binary (the privileged background process it manages).
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
compile_error!("Walden supports macOS and systemd-based Linux only");

pub mod blocker;
pub mod build_info;
pub mod catalog;
pub mod common;
pub mod entry;
mod fetch;
pub mod ipc;
pub mod lifecycle;
pub mod protocol;
pub mod resolver;
pub mod service;
pub mod settings;
pub mod user_config;
