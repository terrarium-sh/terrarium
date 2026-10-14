//! The box supervisor role alone, for seccomp policy analysis.

fn main() -> std::process::ExitCode {
    terra::role::supervisor()
}
