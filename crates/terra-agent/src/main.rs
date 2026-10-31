//! Guest agent entrypoint: PID 1.

#[cfg(target_os = "linux")]
fn main() -> ! {
    terra_agent::run()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("terra-agent only runs on Linux");
    std::process::exit(1);
}
