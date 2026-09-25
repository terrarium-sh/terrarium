//! Rendering a recipe for a person to read: the boot banner and the pinning
//! prompt. Everything here escapes what it prints - a guest-written recipe
//! could otherwise repaint the very summary the `y` is being given to.

use crate::config;
use crate::policy::network;
use anyhow::Result;
use std::io;
use std::path::Path;

#[derive(Debug)]
pub(crate) struct StdoutBrokenPipe;

impl std::fmt::Display for StdoutBrokenPipe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("stdout reader closed")
    }
}

impl std::error::Error for StdoutBrokenPipe {}

pub(crate) fn finish_stdout_write(result: io::Result<()>) -> Result<()> {
    result.map_err(|error| {
        if error.kind() == io::ErrorKind::BrokenPipe {
            anyhow::Error::new(StdoutBrokenPipe)
        } else {
            anyhow::Error::new(error)
        }
    })
}

/// The three characters `escape_debug` escapes that say nothing about a
/// terminal.
const KEPT_AS_TYPED: [char; 3] = ['\'', '"', '\\'];

/// Control characters - and the format codepoints that reorder what they sit
/// in - come out as an escape; ordinary text, non-ASCII included, is
/// untouched.
#[must_use]
pub fn escape_printable(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(KEPT_AS_TYPED) {
        let (escaped, kept) = rest.split_at(at);
        out.extend(escaped.escape_debug());
        let mut kept = kept.chars();
        if let Some(c) = kept.next() {
            out.push(c);
        }
        rest = kept.as_str();
    }
    out.extend(rest.escape_debug());
    out
}

const REDACTED_ENV_VALUE: &str = "(set - value not printable)";

#[must_use]
pub fn redact_config_env(cfg: &config::Config) -> config::Config {
    let mut redacted = cfg.clone();
    for value in redacted.env.values_mut() {
        *value = REDACTED_ENV_VALUE.to_string();
    }
    redacted
}

pub fn render_config_yaml(cfg: &config::Config) -> Result<String, yaml_serde::Error> {
    yaml_serde::to_string(cfg)
}

pub fn render_config_json(cfg: &config::Config) -> Result<String, serde_json::Error> {
    let json = serde_json::to_string_pretty(cfg)?;
    Ok(format!("{json}\n"))
}

#[must_use]
pub fn escape_printable_path(path: &Path) -> String {
    escape_printable(&path.to_string_lossy())
}

/// Quoted where the shell would split or read it. Single quotes, which are
/// literal in every POSIX shell; an embedded one leaves the quoting, escapes
/// itself and re-enters.
#[must_use]
pub(crate) fn quote_shell_word(text: &str) -> String {
    let bare = |c: char| c.is_ascii_alphanumeric() || "._-/=:+@,".contains(c);
    if !text.is_empty() && text.chars().all(bare) {
        return text.to_string();
    }
    format!("'{}'", text.replace('\'', r"'\''"))
}

#[must_use]
pub(crate) fn format_mount_line(m: &config::Mount) -> String {
    let mode = if m.readonly { "ro" } else { "rw" };
    format!(
        "{} <- {} ({mode})",
        escape_printable_path(&m.guest),
        escape_printable_path(&m.host)
    )
}

/// The workload as one command line - for a screen, never for exec.
#[must_use]
pub fn format_workload_line(cfg: &config::Config) -> String {
    let mut line = escape_printable_path(&cfg.workload.entrypoint);
    for a in &cfg.workload.args {
        line.push(' ');
        line.push_str(&escape_printable(a));
    }
    line
}

#[must_use]
pub fn render_policy_summary(cfg: &config::Config) -> String {
    use std::fmt::Write as _;
    let config::Config {
        hw,
        components,
        mounts,
        volumes: _,
        network,
        hooks,
        daemons,
        workload: _,
        sudo,
        env: _,
        env_file,
    } = cfg;
    let config::Network {
        mode: _,
        allow,
        hosts,
        ports,
    } = network;
    let config::Hooks {
        on_create,
        on_start,
        pre_stop,
    } = hooks;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "  hardware: {} vCPU, {} MiB RAM, {} MiB rootfs",
        hw.cpus, hw.mem_mib, hw.rootfs_mib
    );
    let _ = writeln!(out, "  components: {} MiB each", components.memory_mib);
    if let Some(network) = &components.network {
        let _ = writeln!(out, "  network component: {} MiB", network.memory_mib);
    }
    let _ = writeln!(out, "  egress:   {}", network::describe(network));
    for rule in allow {
        let _ = writeln!(out, "  allow:    {}", escape_printable(rule));
    }
    if mounts.is_empty() {
        let _ = writeln!(out, "  mounts:   none");
    }
    for m in mounts {
        let _ = writeln!(out, "  mount:    {}", format_mount_line(m));
    }
    if let Some(file) = env_file {
        let _ = writeln!(out, "  env_file: {}", escape_printable_path(file));
    }
    for p in ports {
        let _ = writeln!(
            out,
            "  publish:  127.0.0.1 -> guest ({})",
            escape_printable(p)
        );
    }
    for h in hosts {
        let _ = writeln!(
            out,
            "  dns:      {} -> {}",
            escape_printable(&h.name),
            escape_printable(&h.addr)
        );
    }
    if !sudo.is_empty() {
        let _ = writeln!(out, "  sudo:     {}", escape_printable(&sudo.join(", ")));
    }
    for hook in on_create.iter().chain(on_start).chain(pre_stop) {
        let _ = writeln!(out, "  as root:  {}", escape_printable(hook));
    }
    for line in daemons {
        let _ = writeln!(out, "  daemon:   {}", escape_printable(line));
    }
    let _ = write!(out, "  workload: {}", format_workload_line(cfg));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_stdout_broken_pipes_get_the_stdout_marker() {
        let stdout =
            finish_stdout_write(Err(io::Error::from(io::ErrorKind::BrokenPipe))).unwrap_err();
        assert!(stdout.downcast_ref::<StdoutBrokenPipe>().is_some());
        let protocol = anyhow::Error::from(io::Error::from(io::ErrorKind::BrokenPipe));
        assert!(protocol.downcast_ref::<StdoutBrokenPipe>().is_none());
    }
    use std::path::PathBuf;

    /// The adoption prompt is printable so a person can judge a recipe a *guest* may
    /// have written - so the recipe must not be able to drive the terminal it is
    /// printable on. Only `sudo:` was already safe, and only because doas fails
    /// closed on a control character.
    #[test]
    fn a_recipe_cannot_drive_the_terminal_it_is_approved_on() {
        let cfg = config::Config {
            mounts: vec![config::Mount {
                // A guest path is only checked for being absolute.
                host: PathBuf::from("/srv/data"),
                guest: PathBuf::from("/work\x1b[2J\x1b[H  mount:    /innocent"),
                readonly: false,
            }],
            network: config::Network {
                allow: vec!["10.0.0.0/8\x1b[2J  egress:   none".to_string()],
                ports: vec!["8080\x1b]0;pwned\x07".to_string()],
                ..Default::default()
            },
            workload: config::Workload {
                entrypoint: PathBuf::from("/bin/sh"),
                args: vec!["-c\rterra: safe".to_string()],
                workdir: None,
            },
            hooks: config::Hooks {
                on_start: vec!["curl evil\x1b[A".to_string()],
                ..Default::default()
            },
            env_file: Some(PathBuf::from("/data/.env\x1b[2J  mount:    /innocent")),
            ..yaml_serde::from_str("{}").unwrap()
        };
        let summary = render_policy_summary(&cfg);
        for raw in ['\x1b', '\r', '\x07'] {
            assert!(
                !summary.contains(raw),
                "the summary still carries {raw:?}:\n{summary}"
            );
        }
        // …and ordinary text is untouched, or the page stops being readable.
        assert!(summary.contains("/srv/data"), "{summary}");
        assert!(summary.contains("8080"), "{summary}");
        assert!(summary.contains("10.0.0.0/8"), "{summary}");
        assert!(summary.contains("/bin/sh"), "{summary}");
    }

    /// What is escaped is what a terminal *acts on*, and a quote is not that.
    /// `escape_debug` printed `sh -c 'npm test'` - which is what half the hook
    /// lines in a recipe look like - as `sh -c \'npm test\'`, noise on the one
    /// page that has to be read carefully before a `y`.
    #[test]
    fn quotes_and_backslashes_reach_the_page_as_they_were_written() {
        for as_typed in [
            r"sh -c 'npm test'",
            r#"echo "hi""#,
            r"/home/o'brien/src",
            r"C:\srv\data",
        ] {
            assert_eq!(escape_printable(as_typed), as_typed);
        }

        // …and what a terminal does act on is still escaped, beside them.
        for driving in ["'\x1b[2J", "\"\r", "\\\x07", "a'b\x1b]0;t\x07"] {
            let shown = escape_printable(driving);
            assert!(
                !shown.contains(['\x1b', '\r', '\x07']),
                "{shown:?} still drives the terminal"
            );
        }
    }

    /// The recipe is printed where the values outlive the boot that set them:
    /// `terra show` is made to be redirected into a file and pasted into a bug
    /// report, and the box's own `/terra/README.md` is written into a
    /// filesystem that persists across boots. So the names stay - knowing
    /// `API_KEY` is set is the useful half - and the values go, unless the one
    /// flag that exists for them was written.
    #[test]
    fn the_printed_recipe_names_env_vars_without_their_values() {
        let cfg = config::Config {
            env: std::collections::BTreeMap::from([
                ("API_KEY".to_string(), "sk-super-secret".to_string()),
                ("MODEL".to_string(), "gpt-4o".to_string()),
            ]),
            ..yaml_serde::from_str("{}").unwrap()
        };
        let yaml = render_config_yaml(&redact_config_env(&cfg)).unwrap();
        for name in ["API_KEY", "MODEL"] {
            assert!(
                yaml.contains(name),
                "the name should still be printable: {yaml}"
            );
        }
        for (name, secret) in [("API_KEY", "sk-super-secret"), ("MODEL", "gpt-4o")] {
            assert!(
                !yaml.contains(secret),
                "the value of {name} was printed:\n{yaml}"
            );
        }
        // Only `env:` is redacted - the rest is what makes the output worth
        // printing at all.
        assert!(yaml.contains("workload:"), "{yaml}");

        // …and `terra show --with-env-values` is the one rendering that answers
        // with them, otherwise identical - a recipe read back from it has to be
        // the one a boot would run.
        let asked_for = render_config_yaml(&cfg).unwrap();
        for (name, secret) in [("API_KEY", "sk-super-secret"), ("MODEL", "gpt-4o")] {
            assert!(
                asked_for.contains(secret),
                "the value of {name} is missing:\n{asked_for}"
            );
        }
        assert!(!asked_for.contains(REDACTED_ENV_VALUE), "{asked_for}");
        assert_eq!(
            yaml_serde::from_str::<config::Config>(&asked_for).unwrap(),
            cfg,
            "what it prints is not the config it was given"
        );

        let json = render_config_json(&redact_config_env(&cfg)).unwrap();
        for name in ["API_KEY", "MODEL"] {
            assert!(
                json.contains(name),
                "the name should still be in json: {json}"
            );
        }
        for (name, secret) in [("API_KEY", "sk-super-secret"), ("MODEL", "gpt-4o")] {
            assert!(
                !json.contains(secret),
                "the value of {name} was printed in json:\n{json}"
            );
        }
        let asked_for_json = render_config_json(&cfg).unwrap();
        for (name, secret) in [("API_KEY", "sk-super-secret"), ("MODEL", "gpt-4o")] {
            assert!(
                asked_for_json.contains(secret),
                "the value of {name} is missing in json:\n{asked_for_json}"
            );
        }
        assert_eq!(
            serde_json::from_str::<config::Config>(&asked_for_json).unwrap(),
            cfg,
            "what it prints is not the config it was given"
        );
    }

    /// `terra show` prints the recipe as YAML rather than through [`escape_printable`], so
    /// what keeps a guest-authored one from driving that terminal is the YAML
    /// emitter: a scalar carrying a non-printable cannot be written plain or
    /// single-quoted, so it comes out double-quoted with the byte escaped.
    /// That is a property of the serializer, not of this crate - pinned here
    /// because `show`'s whole reason to exist is that it must hold. Both
    /// renderings are checked: `--with-env-values` prints a part of the recipe
    /// the redacted one replaces outright, so it is the only place an `env:`
    /// value ever reaches a terminal.
    #[test]
    fn the_recipe_terra_show_prints_cannot_drive_the_terminal_either() {
        let cfg = config::Config {
            hooks: config::Hooks {
                on_start: vec!["curl evil\x1b[2J\x1b[H  workload: /bin/true".to_string()],
                ..Default::default()
            },
            workload: config::Workload {
                entrypoint: PathBuf::from("/bin/sh"),
                args: vec!["-c\r  hooks: []".to_string(), "\x07".to_string()],
                workdir: None,
            },
            env: std::collections::BTreeMap::from([(
                "API_KEY".to_string(),
                "sk\x1b[2J\x1b[H  workload: /bin/true".to_string(),
            )]),
            ..yaml_serde::from_str("{}").unwrap()
        };
        for printed in [
            render_config_yaml(&redact_config_env(&cfg)).unwrap(),
            yaml_serde::to_string(&cfg).unwrap(),
        ] {
            for raw in ['\x1b', '\r', '\x07'] {
                assert!(
                    !printed.contains(raw),
                    "terra show would emit a raw {raw:?}:\n{printed}"
                );
            }
            // …and the text is still there to read, escaped rather than dropped.
            assert!(printed.contains("curl evil"), "{printed}");
        }
    }

    /// `env_file:` names a host file terra reads and exports into the guest -
    /// any file the launching user can read, `~/.aws/credentials` included. It
    /// is the only other line in a recipe that reaches out of the sandbox, so
    /// the page the pinning `y` is given to has to carry it: a recipe a guest
    /// authored could otherwise point it anywhere while the summary showed
    /// nothing but mounts and egress.
    #[test]
    fn the_approval_summary_names_the_host_file_a_recipe_reads() {
        let cfg = config::Config {
            env_file: Some(PathBuf::from("/home/me/.aws/credentials")),
            ..yaml_serde::from_str("{}").unwrap()
        };
        let summary = render_policy_summary(&cfg);
        assert!(
            summary.contains("/home/me/.aws/credentials"),
            "the file a recipe would read is not on the page it is approved on:\n{summary}"
        );

        // A recipe naming no file says nothing about one.
        let none = render_policy_summary(&yaml_serde::from_str("{}").unwrap());
        assert!(!none.contains("env_file"), "{none}");
    }

    /// A daemon runs as root for the box's lifetime, so the approving page
    /// carries every line - escaped like the hooks, and quiet when none.
    #[test]
    fn the_approval_summary_lists_every_daemon() {
        let cfg = config::Config {
            daemons: vec!["ascend --serve".to_string(), "evil\x1b[2J".to_string()],
            ..yaml_serde::from_str("{}").unwrap()
        };
        let summary = render_policy_summary(&cfg);
        assert!(summary.contains("daemon:   ascend --serve"), "{summary}");
        assert!(!summary.contains('\x1b'), "{summary}");
        let none = render_policy_summary(&yaml_serde::from_str("{}").unwrap());
        assert!(!none.contains("daemon:"), "{none}");
    }

    /// The egress *posture* is one phrase; an `allow:` rule is what opens the
    /// machine terra runs on and the LAN. Approving "allowlist active (deny by
    /// default)" over `HOST_LOOPBACK:22` reads as the opposite of what it
    /// grants, so every rule is listed on the screen the `y` is given to.
    #[test]
    fn the_approval_summary_lists_every_allow_rule() {
        let cfg = config::Config {
            network: config::Network {
                mode: config::NetworkMode::Allowlist,
                allow: vec!["HOST_LOOPBACK:22".to_string(), "10.0.0.0/8".to_string()],
                ..Default::default()
            },
            ..yaml_serde::from_str("{}").unwrap()
        };
        let summary = render_policy_summary(&cfg);
        for rule in ["HOST_LOOPBACK:22", "10.0.0.0/8"] {
            assert!(summary.contains(rule), "{rule} is not in:\n{summary}");
        }
    }

    #[test]
    fn the_approval_summary_lists_hardware_and_component_requirements() {
        let cfg = config::Config {
            components: config::Components {
                memory_mib: 32,
                network: Some(config::NetworkComponent { memory_mib: 64 }),
            },
            hw: config::Hw {
                cpus: 4,
                mem_mib: 4096,
                rootfs_mib: 2048,
            },
            ..yaml_serde::from_str("{}").unwrap()
        };
        let summary = render_policy_summary(&cfg);
        assert!(summary.contains("components: 32 MiB each"));
        assert!(summary.contains("network component: 64 MiB"));
        assert!(
            summary.contains("hardware: 4 vCPU, 4096 MiB RAM, 2048 MiB rootfs"),
            "{summary}"
        );
    }

    /// Every "look here" line terra prints is a command meant to be pasted, so
    /// a path the shell would split or expand has to come back out of it
    /// whole. Checked against a real shell rather than against a belief about
    /// quoting - which is the half that would go wrong unnoticed.
    #[cfg(unix)]
    #[test]
    fn a_word_of_a_printed_command_survives_the_shell_it_is_pasted_into() {
        for path in [
            "/p",
            "/home/me/My Projects/app",
            "/home/o'brien/src",
            "/a b$c`d",
            "/wild*card",
            "/quoted\"path",
            "",
        ] {
            let out = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("printf %s {}", quote_shell_word(path)))
                .output()
                .expect("running the shell the hint is pasted into");
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                path,
                "the shell did not hand back {path:?} whole"
            );
        }
        // A plain path is left alone: quoting every hint would be noise on the
        // overwhelmingly common one.
        assert_eq!(quote_shell_word("/home/me/src"), "/home/me/src");
    }
}
