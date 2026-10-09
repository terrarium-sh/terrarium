use std::path::Path;

/// Returns `<tag>+<hash>` on a tagged commit, `dev+<hash>` otherwise, and `package_version` outside git.
#[must_use]
pub fn describe_version(workspace_root: &Path, package_version: &str) -> String {
    let Some(hash) = git(workspace_root, &["rev-parse", "--short", "HEAD"]) else {
        return package_version.to_owned();
    };
    let version = match git(workspace_root, &["describe", "--tags", "--exact-match"]) {
        Some(tag) => tag.strip_prefix('v').unwrap_or(&tag).to_owned(),
        None => "dev".to_owned(),
    };
    format!("{version}+{hash}")
}

fn git(workspace_root: &Path, args: &[&str]) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(workspace_root)
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    (output.status.success() && !stdout.is_empty()).then_some(stdout)
}
