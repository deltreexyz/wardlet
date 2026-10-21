//! Step logging for `--debug`. Off unless that flag is set.
//!
//! Lines go to stderr. They name the step. They do not include the master
//! key, PINs, or recovery codes.

use std::sync::atomic::{AtomicBool, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);

pub fn set(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

pub fn log(message: &str) {
    if enabled() {
        eprintln!("debug: {message}");
    }
}
