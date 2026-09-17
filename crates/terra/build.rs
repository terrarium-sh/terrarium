fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
    println!("cargo:rerun-if-changed=../../.git/refs/tags");

    let Some(hash) = git(&["rev-parse", "--short", "HEAD"]) else {
        println!(
            "cargo:rustc-env=TERRA_VERSION={}",
            env!("CARGO_PKG_VERSION")
        );
        return;
    };

    let version = match git(&["describe", "--tags", "--exact-match"]) {
        Some(tag) => tag.strip_prefix('v').unwrap_or(&tag).to_owned(),
        None => "dev".to_owned(),
    };

    println!("cargo:rustc-env=TERRA_VERSION={version}+{hash}");
}

fn git(args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git").args(args).output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (output.status.success() && !stdout.is_empty()).then_some(stdout)
}
