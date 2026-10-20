fn main() {
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/refs/heads");
    println!("cargo:rerun-if-changed=../../.git/refs/tags");
    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let version =
        terra_build::version::describe_version(&workspace_root, env!("CARGO_PKG_VERSION"));
    println!("cargo:rustc-env=TERRA_VERSION={version}");
    // Embedded artifacts run in place from the image's file pages; PE's default 512-byte
    // file alignment would leave them off page boundaries in the file, so they could not be shared.
    // Only MSVC builds ship; elsewhere the artifact still runs in place, from unshared pages.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc")
    {
        println!("cargo:rustc-link-arg=/FILEALIGN:4096");
    }
}
