//! What may name a box: the name alphabet, the words terra's CLI keeps for
//! itself, and how arbitrary text is reduced to that alphabet.

use anyhow::{Result, bail};
use std::ffi::OsStr;
use std::path::Path;

pub(crate) const RESERVED_NAMES: &[&str] = &[
    "detach", "exec", "get", "help", "logs", "ls", "ps", "put", "rm", "sessions", "setup", "show",
    "stop", "storage",
];

pub(crate) fn is_recipe_ext(extension: &OsStr) -> bool {
    extension == "yaml" || extension == "yml"
}

/// Refuse a name that could not be a state subdirectory or fit a socket path,
/// before anything is built under it.
pub fn validate_box_name(name: &str) -> Result<()> {
    if RESERVED_NAMES.contains(&name) {
        bail!("'{name}' cannot name a box: it is a terra command");
    }
    if Path::new(name).extension().is_some_and(is_recipe_ext) {
        bail!("'{name}' cannot name a box: it names a recipe file (try './{name}')");
    }
    // A leading `_` is reserved for terra's own argv words (`__vm`).
    let ok = !name.is_empty()
        && name.len() <= 32
        && !name.starts_with(['.', '-', '_'])
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');
    if !ok {
        bail!(
            "'{name}' cannot name a box: a name is 1-32 characters of [a-z A-Z 0-9 . - _], \
             not starting with '.', '-' or '_'"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_names_are_validated() {
        for ok in ["dev", "ci-arm.v2", "A_b", "x", "path", "name", "sandbox"] {
            assert!(validate_box_name(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            ".hidden",
            "-flag",
            "_reserved",
            "__vm",
            "a/b",
            "a b",
            "é",
            &"x".repeat(33),
        ] {
            assert!(validate_box_name(bad).is_err(), "{bad}");
        }
        // Terra's own words are reserved: the bare form would shadow the box
        // (the full list is pinned against the CLI in `cli::tests`).
        for word in ["ls", "stop", "logs", "ps", "help"] {
            assert!(validate_box_name(word).is_err(), "{word}");
        }
        // A recipe-file spelling is a path, never a name - one argument must
        // not mean a file to `setup` and a box to everything else.
        for file in ["ci.yaml", "ci.yml", "a.b.yaml"] {
            let err = validate_box_name(file).unwrap_err().to_string();
            assert!(err.contains("recipe file"), "{file}: {err}");
        }
        // The origin label sits outside the name alphabet, so no name can
        // collide with the file beside the box directories.
        assert!(validate_box_name(crate::state::ORIGIN_FILE).is_err());
    }
}
