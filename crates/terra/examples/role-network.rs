//! The network broker role alone, for seccomp policy analysis.

fn main() -> std::process::ExitCode {
    terra::role::network()
}
