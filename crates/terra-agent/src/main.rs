//! Guest agent entrypoint: PID 1.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#[cfg(target_os = "linux")]
mod daemon;
#[cfg(target_os = "linux")]
mod exec;
#[cfg(target_os = "linux")]
mod files;
#[cfg(target_os = "linux")]
mod idmap;
#[cfg(target_os = "linux")]
mod init;
#[cfg(target_os = "linux")]
mod mutex;
#[cfg(target_os = "linux")]
mod reap;
#[cfg(target_os = "linux")]
mod term {
    pub mod session;
    pub mod tty;
}
#[cfg(target_os = "linux")]
mod vsock;

#[cfg(target_os = "linux")]
fn main() {
    let failed = init::boot();
    std::process::exit(i32::from(failed));
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("terra-agent only runs on Linux");
    std::process::exit(1);
}
