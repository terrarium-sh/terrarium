fn main() -> Result<(), std::env::VarError> {
    let target = std::env::var("TARGET")?;
    println!("cargo:rustc-env=TERRA_BUILD_TARGET={target}");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
    println!("cargo:rerun-if-changed=../../.git/refs/tags");
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let version =
        terra_build::version::describe_version(&workspace_root, env!("CARGO_PKG_VERSION"));
    println!("cargo:rustc-env=TERRA_VERSION={version}");
    Ok(())
}
