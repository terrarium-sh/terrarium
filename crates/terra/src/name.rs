//! Storage names and the additional restrictions on box names.

use anyhow::{Result, bail};
use std::ffi::OsStr;
use std::path::Path;

pub(crate) const RESERVED_NAMES: &[&str] = &[
    "completions",
    "detach",
    "exec",
    "help",
    "logs",
    "ls",
    "ps",
    "rm",
    "sessions",
    "setup",
    "show",
    "stop",
    "storage",
    "sync",
];

pub(crate) fn is_recipe_ext(extension: &OsStr) -> bool {
    extension == "yaml" || extension == "yml"
}

pub(crate) fn validate_storage_name(name: &str) -> Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 255
            && !name.ends_with('.')
            && !is_windows_device_name(name)
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'_')),
        "invalid storage name '{}': use 1-255 ASCII letters, digits, '.', '-', or '_', \
         without a trailing dot or a Windows device name",
        crate::render::escape_printable(name)
    );
    Ok(())
}

/// Refuse a name that could not be a state subdirectory or fit a socket path,
/// before anything is built under it.
pub fn validate_box_name(name: &str) -> Result<()> {
    if RESERVED_NAMES.contains(&name) {
        bail!(
            "'{}' cannot name a box: it is a terra command",
            crate::render::escape_printable(name)
        );
    }
    if Path::new(name).extension().is_some_and(is_recipe_ext) {
        bail!(
            "'{}' cannot name a box: it names a recipe file (try './{}')",
            crate::render::escape_printable(name),
            crate::render::escape_printable(name)
        );
    }
    // A leading `_` is reserved for terra's own argv words (`__vm`).
    let ok = validate_storage_name(name).is_ok()
        && name.len() <= 32
        && !name.starts_with(['.', '-', '_']);
    if !ok {
        bail!(
            "'{}' cannot name a box: a name is 1-32 characters of [a-z A-Z 0-9 . - _], \
             not starting with '.', '-' or '_', ending with '.', or a Windows device name",
            crate::render::escape_printable(name)
        );
    }
    Ok(())
}

fn is_windows_device_name(name: &str) -> bool {
    matches!(
        name.split('.')
            .next()
            .map(str::to_ascii_uppercase)
            .as_deref(),
        Some(
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_names_have_one_alphabet_on_every_platform() {
        for name in ["data", "DATA", ".gitignore", "a-b_c.txt", &"x".repeat(255)] {
            assert!(validate_storage_name(name).is_ok(), "{name}");
        }
        for name in [
            "",
            ".",
            "..",
            "café",
            "cafe\u{301}",
            "ß",
            "ſ",
            "CON",
            "con.txt",
            "LPT9",
            "COM1.log",
            "a/b",
            "a\\b",
            "a:stream",
            "a b",
            "a.",
            "a ",
            "LONGFI~1",
            "a\0b",
            &"x".repeat(256),
        ] {
            assert!(validate_storage_name(name).is_err(), "{name}");
        }
    }

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
            "dev.",
            "CON",
            "lpt9.log",
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

    #[test]
    fn invalid_box_names_escape_terminal_controls() {
        let error = validate_box_name("bad\x1b\x07").unwrap_err().to_string();
        assert!(!error.contains(['\x1b', '\x07']), "{error:?}");
    }
}
