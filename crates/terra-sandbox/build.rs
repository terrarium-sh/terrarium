use terra_build::seccomp::{Architecture, Role, compile_allowlist, compile_role_filter};
use terra_build::seccomp_policy::{Policy, policy_path, read_policy};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CARGO_CFG_TARGET_OS")? != "linux" {
        return Ok(());
    }
    let target = std::env::var("TARGET")?;
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH")?;
    let architecture =
        Architecture::from_target(&arch, &std::env::var("CARGO_CFG_TARGET_ENDIAN")?)?;
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR is missing")?);
    // Only the static musl targets terra ships have a scannable libc, so only they carry policies.
    let path = policy_path(std::path::Path::new(env!("CARGO_MANIFEST_DIR")), &target);
    println!("cargo:rerun-if-changed={}", path.display());
    let policy = if std::env::var("CARGO_CFG_TARGET_ENV")? != "musl" {
        Policy::new()
    } else if path.exists() {
        read_policy(&path, &target)?
    } else {
        // The first policy for a target is generated from binaries built without one;
        // `make policy-check` keeps a release from shipping that way.
        println!("cargo:warning=no seccomp policy for {target}; run `make policy`");
        Policy::new()
    };
    for role in Role::ALL {
        let role_filter = compile_role_filter(architecture, role)?;
        std::fs::write(
            output.join(format!("{}-role-filter.bpf", role.name())),
            role_filter,
        )?;
        let allowlist = match policy.get(&role) {
            Some(policy) => compile_allowlist(architecture, policy)?,
            None => Vec::new(),
        };
        std::fs::write(
            output.join(format!("{}-allowlist.bpf", role.name())),
            allowlist,
        )?;
    }
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bwrap = terra_build::bwrap::locate_built_bwrap(&workspace_root, &arch)?;
    println!("cargo:rerun-if-changed={}", bwrap.display());
    println!("cargo:rustc-env=TERRA_BWRAP_BIN={}", bwrap.display());
    Ok(())
}
