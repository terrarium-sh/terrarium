//! Guest agent entrypoint: PID 1.

// unwrap/expect/panic are denied workspace-wide via Cargo.toml; tests opt back in.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![allow(unsafe_code)]

mod daemon;
mod exec;
mod files;
mod idmap;
mod init;
mod reap;
mod term;
mod vsock;

fn main() {
    let ending = init::boot();
    if let Err(e) = &ending.outcome {
        eprintln!("terra-agent: init failed: {e:#}");
    }
    let failed = ending.report();
    std::process::exit(i32::from(failed));
}
