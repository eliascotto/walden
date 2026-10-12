//! Daemon diagnostics: native macOS system logging, journal stderr on Linux.

use std::sync::atomic::{AtomicBool, Ordering};

static DAEMON: AtomicBool = AtomicBool::new(false);

pub fn init_daemon() {
    DAEMON.store(true, Ordering::Relaxed);
    #[cfg(target_os = "macos")]
    // SAFETY: the identifier has static lifetime and is NUL terminated.
    unsafe {
        libc::openlog(c"waldend".as_ptr(), libc::LOG_PID, libc::LOG_DAEMON);
    }
}

pub fn message(message: &str) {
    #[cfg(target_os = "macos")]
    if DAEMON.load(Ordering::Relaxed) {
        let message =
            std::ffi::CString::new(message.replace('\0', "\\0")).expect("NULs were escaped");
        // SAFETY: a fixed format string prevents formatting input as code;
        // the message remains valid for this synchronous call.
        unsafe {
            libc::syslog(libc::LOG_ERR, c"%s".as_ptr(), message.as_ptr());
        }
        return;
    }
    eprintln!("{message}");
}

#[macro_export]
macro_rules! daemon_log {
    ($($arg:tt)*) => { $crate::logging::message(&format!($($arg)*)) };
}
