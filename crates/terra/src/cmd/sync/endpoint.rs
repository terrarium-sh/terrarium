use anyhow::{Context, Result};
use std::path::PathBuf;
use terra_protocol::SyncDirection;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Endpoint {
    Guest {
        path: String,
        has_trailing_separator: bool,
    },
    Host {
        path: PathBuf,
        has_trailing_separator: bool,
    },
}

fn parse_endpoint(raw: &str) -> Result<Endpoint> {
    if let Some(rest) = raw.strip_prefix("box:").or_else(|| raw.strip_prefix(':')) {
        anyhow::ensure!(
            rest.starts_with('/'),
            "the box's side of sync is an absolute path, and '{raw}' is not (use 'box:/path' or ':/path')"
        );
        let path = if rest == "/" {
            rest
        } else {
            rest.trim_end_matches('/')
        };
        anyhow::ensure!(
            !path.is_empty(),
            "guest path is empty after removing trailing separators; use 'box:/' or ':/' for the guest root"
        );
        return Ok(Endpoint::Guest {
            path: path.to_owned(),
            has_trailing_separator: raw.ends_with('/'),
        });
    }

    let is_windows_drive =
        raw.len() >= 2 && raw.as_bytes()[0].is_ascii_alphabetic() && raw.as_bytes()[1] == b':';

    if !is_windows_drive
        && let Some(colon_pos) = raw.find(':')
        && colon_pos > 0
        && !raw[..colon_pos].contains(['/', '\\'])
        && raw[colon_pos..].starts_with(":/")
    {
        let box_name = &raw[..colon_pos];
        let rest = &raw[colon_pos + 1..];
        anyhow::bail!(
            "'{raw}' looks like a named box endpoint; terra selects the box on the CLI: terra {box_name} sync ... box:{rest}"
        );
    }

    let has_trailing_separator = raw.ends_with('/') || (cfg!(windows) && raw.ends_with('\\'));
    Ok(Endpoint::Host {
        path: PathBuf::from(raw).components().collect(),
        has_trailing_separator,
    })
}

pub(super) fn parse_endpoints(src: &str, dst: &str) -> Result<(Endpoint, Endpoint, SyncDirection)> {
    let src_endpoint = parse_endpoint(src).context("parsing source endpoint")?;
    let dst_endpoint = parse_endpoint(dst).context("parsing destination endpoint")?;

    match (&src_endpoint, &dst_endpoint) {
        (Endpoint::Guest { .. }, Endpoint::Guest { .. }) => {
            anyhow::bail!(
                "sync operates between host and a box; both source and destination cannot be inside the box"
            );
        }
        (Endpoint::Host { .. }, Endpoint::Host { .. }) => {
            anyhow::bail!(
                "sync operates between host and a box; exactly one of source and destination must be inside the box ('box:/path' or ':/path')"
            );
        }
        (Endpoint::Host { .. }, Endpoint::Guest { .. }) => {
            Ok((src_endpoint, dst_endpoint, SyncDirection::HostToGuest))
        }
        (Endpoint::Guest { .. }, Endpoint::Host { .. }) => {
            Ok((src_endpoint, dst_endpoint, SyncDirection::GuestToHost))
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct SourcePlacement<'a> {
    pub(super) name: &'a str,
    pub(super) is_dir: bool,
    pub(super) has_trailing: bool,
}

#[derive(Clone, Copy)]
pub(super) struct DestinationPlacement<'a> {
    pub(super) path: &'a str,
    pub(super) is_existing_dir: bool,
    pub(super) has_trailing: bool,
}

pub(super) fn resolve_placement(src: SourcePlacement<'_>, dst: DestinationPlacement<'_>) -> String {
    if src.is_dir {
        if src.has_trailing {
            dst.path.to_string()
        } else if dst.is_existing_dir {
            format!("{}/{}", dst.path.trim_end_matches('/'), src.name)
        } else {
            dst.path.to_string()
        }
    } else if dst.is_existing_dir || dst.has_trailing {
        format!("{}/{}", dst.path.trim_end_matches('/'), src.name)
    } else {
        dst.path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_endpoint_identifies_guest_and_host() {
        assert_eq!(
            parse_endpoint("box:/app/out").unwrap(),
            Endpoint::Guest {
                path: "/app/out".to_string(),
                has_trailing_separator: false,
            }
        );
        assert_eq!(
            parse_endpoint(":/app/out/").unwrap(),
            Endpoint::Guest {
                path: "/app/out".to_string(),
                has_trailing_separator: true,
            }
        );
        assert_eq!(
            parse_endpoint("./local/path/").unwrap(),
            Endpoint::Host {
                path: PathBuf::from("./local/path/"),
                has_trailing_separator: true,
            }
        );
    }

    #[test]
    fn relative_guest_path_is_rejected() {
        assert!(parse_endpoint("box:relative/path").is_err());
        assert!(parse_endpoint(":relative/path").is_err());
        for invalid in ["box://", "://", "box:////", ":////"] {
            assert!(
                parse_endpoint(invalid)
                    .unwrap_err()
                    .to_string()
                    .contains("guest path is empty")
            );
        }
        for root in ["box:/", ":/"] {
            assert_eq!(
                parse_endpoint(root).unwrap(),
                Endpoint::Guest {
                    path: "/".into(),
                    has_trailing_separator: true,
                }
            );
        }
    }

    #[test]
    fn named_box_prefix_suggests_cli_spelling() {
        let err = parse_endpoint("dev:/app").unwrap_err().to_string();
        assert!(err.contains("terra dev sync"), "{err}");
    }

    #[test]
    fn exactly_one_guest_endpoint_required() {
        assert!(parse_endpoints("box:/a", "box:/b").is_err());
        assert!(parse_endpoints("./a", "./b").is_err());
        assert!(parse_endpoints("./a", "box:/b").is_ok());
        assert!(parse_endpoints(":/a", "./b").is_ok());
    }

    #[test]
    fn placement_table_all_rows() {
        #[allow(clippy::fn_params_excessive_bools)]
        fn check(
            is_src_dir: bool,
            src_has_trailing: bool,
            src_name: &str,
            dst_path: &str,
            dst_has_trailing: bool,
            dst_is_existing_dir: bool,
        ) -> String {
            resolve_placement(
                SourcePlacement {
                    name: src_name,
                    is_dir: is_src_dir,
                    has_trailing: src_has_trailing || src_name.is_empty(),
                },
                DestinationPlacement {
                    path: dst_path,
                    is_existing_dir: dst_is_existing_dir,
                    has_trailing: dst_has_trailing,
                },
            )
        }

        // Row 1: file a -> existing directory dest/ -> dest/a
        assert_eq!(check(false, false, "a", "dest", true, true), "dest/a");
        assert_eq!(check(false, false, "a", "dest", false, true), "dest/a");

        // Row 2: file a -> file path or absent dest -> dest
        assert_eq!(check(false, false, "a", "dest", false, false), "dest");

        // Row 3: directory src/ -> directory or absent dest -> contents under dest/
        assert_eq!(check(true, true, "src", "dest", false, true), "dest");
        assert_eq!(check(true, true, "src", "dest", false, false), "dest");

        // Row 4: directory src -> existing directory dest -> subtree dest/src/
        assert_eq!(check(true, false, "src", "dest", false, true), "dest/src");

        // Row 5: directory src -> absent dest -> subtree rooted at dest/
        assert_eq!(check(true, false, "src", "dest", false, false), "dest");
    }
}
