use std::path::{Path, PathBuf};

/// Returns the Bubblewrap executable `make` built for `arch` under `workspace_root/build`.
pub fn locate_built_bwrap(workspace_root: &Path, arch: &str) -> std::io::Result<PathBuf> {
    let asset = workspace_root.join(format!("build/bwrap-{arch}"));
    let make_hint = format!("run `make ARCH={arch} build/bwrap-{arch}`");
    let metadata = std::fs::metadata(&asset).map_err(|error| {
        std::io::Error::new(
            error.kind(),
            format!("{} is missing; {make_hint}: {error}", asset.display()),
        )
    })?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(std::io::Error::other(format!(
            "{} is not a built Bubblewrap executable; {make_hint}",
            asset.display()
        )));
    }
    Ok(asset)
}
