use terra_build::seccomp::{Architecture, Role, compile_fallback_seccomp};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::var("TARGET")?;
    println!("cargo:rustc-env=TERRA_BUILD_TARGET={target}");
    if std::env::var("CARGO_CFG_TARGET_OS")? != "linux" {
        return Ok(());
    }
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH")?;
    let architecture =
        Architecture::from_target(&arch, &std::env::var("CARGO_CFG_TARGET_ENDIAN")?)?;
    let output = std::path::PathBuf::from(std::env::var_os("OUT_DIR").ok_or("OUT_DIR is missing")?);
    for role in Role::ALL {
        let filter = compile_fallback_seccomp(architecture, role)?;
        std::fs::write(output.join(format!("{}-seccomp.bpf", role.name())), filter)?;
    }
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let bwrap = terra_build::bwrap::locate_built_bwrap(&workspace_root, &arch)?;
    println!("cargo:rerun-if-changed={}", bwrap.display());
    println!("cargo:rustc-env=TERRA_BWRAP_BIN={}", bwrap.display());
    Ok(())
}
