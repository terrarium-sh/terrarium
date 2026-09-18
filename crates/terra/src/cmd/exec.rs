//! `terra <box> exec` - run one command in a running box, on a terminal of its
//! own. The pumping machinery it shares with sessions is [`crate::session`]'s.

use crate::resolve;
use crate::session::{self, pump_exec};
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;
use terra_protocol::{AgentService, ExecRequest, encode_frame};

pub fn run(
    args: &crate::cli::ExecArgs,
    name: Option<&str>,
    project_dir: &Path,
    is_at_a_terminal: bool,
) -> Result<ExitCode> {
    use std::io::Write;
    let bx = &resolve::resolve_pinned_box(project_dir, name)?;
    let stream = session::connect_to_running_agent(
        bx,
        "exec",
        AgentService::Exec,
        "exec service",
        args.agent.agent_timeout,
    )?;

    let env = resolve_exec_env(args.inherit_env, &args.env)?;

    let tty = args.wants_a_terminal(is_at_a_terminal);
    let req = ExecRequest {
        argv: args.command.clone(),
        as_root: args.root,
        tty: tty.then(|| session::read_terminal_size().unwrap_or(session::DEFAULT_TERMINAL_SIZE)),
        workdir: args.workdir.clone(),
        env,
    };
    (&stream)
        .write_all(&encode_frame(&req).context("encoding the exec request")?)
        .context("sending the exec request")?;
    Ok(ExitCode::from(crate::exit_status_byte(pump_exec(
        &stream, tty,
    )?)))
}

/// Host paths, shells, and session sockets would break or misconfigure the guest VM if inherited blindly.
fn is_host_identity_var(key: &str) -> bool {
    matches!(
        key,
        "HOME"
            | "PATH"
            | "USER"
            | "LOGNAME"
            | "SHELL"
            | "PWD"
            | "OLDPWD"
            | "_"
            | "DISPLAY"
            | "WAYLAND_DISPLAY"
            | "XAUTHORITY"
            | "DBUS_SESSION_BUS_ADDRESS"
            | "SSH_AUTH_SOCK"
    ) || key.starts_with("TERRA_")
}

fn resolve_exec_env(inherit_env: bool, entries: &[String]) -> Result<BTreeMap<String, String>> {
    resolve_exec_env_from(
        inherit_env,
        entries,
        |k| {
            std::env::var(k)
                .map_err(|_| anyhow::anyhow!("environment variable `{k}` is not set on the host"))
        },
        std::env::vars,
    )
}

fn resolve_exec_env_from<I>(
    inherit_env: bool,
    entries: &[String],
    lookup_host_var: impl Fn(&str) -> Result<String>,
    all_host_vars: impl FnOnce() -> I,
) -> Result<BTreeMap<String, String>>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut env = BTreeMap::new();
    if inherit_env {
        for (k, v) in all_host_vars() {
            if is_host_identity_var(&k)
                || k.is_empty()
                || k.contains(['=', '\0'])
                || v.contains('\0')
            {
                continue;
            }
            env.insert(k, v);
        }
    }

    for entry in entries {
        let (k, v) = if let Some((k, v)) = entry.split_once('=') {
            if k.is_empty() {
                bail!("invalid env `{entry}`: empty variable name");
            }
            if k.contains(['=', '\0']) || v.contains('\0') {
                bail!("invalid env `{entry}`: contains forbidden characters");
            }
            (k.to_string(), v.to_string())
        } else {
            if entry.is_empty() {
                bail!("invalid env `{entry}`: empty variable name");
            }
            if entry.contains(['=', '\0']) {
                bail!("invalid env `{entry}`: contains forbidden characters");
            }
            let v = lookup_host_var(entry)?;
            if v.contains('\0') {
                bail!("invalid env `{entry}`: contains forbidden characters");
            }
            (entry.clone(), v)
        };
        env.insert(k, v);
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_env_entries_are_refused() {
        let parse = |entries: &[&str]| {
            let entries: Vec<String> = entries.iter().map(ToString::to_string).collect();
            resolve_exec_env_from(
                false,
                &entries,
                |k| bail!("environment variable `{k}` is not set on the host"),
                std::iter::empty,
            )
        };

        assert!(parse(&["FOO=BAR"]).is_ok());
        assert!(parse(&["FOO=BAR=BAZ"]).is_ok());
        assert!(parse(&[""]).is_err());
        assert!(parse(&["=BAR"]).is_err());
        assert!(parse(&["NO_EQUALS"]).is_err());
        assert!(parse(&["FO\0O=BAR"]).is_err());
        assert!(parse(&["FOO=BA\0R"]).is_err());
        assert!(parse(&["FO\0O"]).is_err());
    }

    #[test]
    fn bare_keys_inherit_from_host_environment() {
        let host = BTreeMap::from([
            ("SET".to_string(), "val".to_string()),
            ("WITH_NUL".to_string(), "bad\0val".to_string()),
        ]);
        let parse = |entries: &[&str]| {
            let entries: Vec<String> = entries.iter().map(ToString::to_string).collect();
            resolve_exec_env_from(
                false,
                &entries,
                |k| {
                    host.get(k).cloned().ok_or_else(|| {
                        anyhow::anyhow!("environment variable `{k}` is not set on the host")
                    })
                },
                std::iter::empty,
            )
        };

        let env = parse(&["SET"]).unwrap();
        assert_eq!(env.get("SET").map(String::as_str), Some("val"));

        let err = parse(&["UNSET"]).unwrap_err();
        assert!(err.to_string().contains("is not set on the host"), "{err}");

        assert!(parse(&["WITH_NUL"]).is_err());
    }

    #[test]
    fn blanket_inherit_env_skips_host_identity_vars() {
        let host = [
            ("HOME", "/home/hostuser"),
            ("PATH", "/usr/bin:/bin"),
            ("USER", "hostuser"),
            ("LOGNAME", "hostuser"),
            ("SHELL", "/bin/zsh"),
            ("PWD", "/host/project"),
            ("OLDPWD", "/host"),
            ("_", "/usr/bin/terra"),
            ("DISPLAY", ":0"),
            ("WAYLAND_DISPLAY", "wayland-0"),
            ("SSH_AUTH_SOCK", "/tmp/ssh.sock"),
            ("TERRA_INTERNAL", "1"),
            ("APP_SECRET", "supersecret"),
            ("TERM", "xterm-256color"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect::<Vec<_>>();

        let env =
            resolve_exec_env_from(true, &[], |k| bail!("not found: {k}"), || host.clone()).unwrap();

        assert_eq!(
            env.get("APP_SECRET").map(String::as_str),
            Some("supersecret")
        );
        assert_eq!(env.get("TERM").map(String::as_str), Some("xterm-256color"));
        for filtered in [
            "HOME",
            "PATH",
            "USER",
            "LOGNAME",
            "SHELL",
            "PWD",
            "OLDPWD",
            "_",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "SSH_AUTH_SOCK",
            "TERRA_INTERNAL",
        ] {
            assert!(
                !env.contains_key(filtered),
                "{filtered} should have been filtered"
            );
        }
    }

    #[test]
    fn explicit_entries_override_blanket_inherit_and_allow_filtered_vars() {
        let host = [
            ("APP_VAR".to_string(), "original".to_string()),
            ("HOME".to_string(), "/home/hostuser".to_string()),
        ];
        let entries = vec![
            "APP_VAR=overridden".to_string(),
            "HOME".to_string(),
            "CUSTOM=value".to_string(),
        ];
        let env = resolve_exec_env_from(
            true,
            &entries,
            |k| {
                host.iter()
                    .find(|(name, _)| name == k)
                    .map(|(_, v)| v.clone())
                    .ok_or_else(|| anyhow::anyhow!("not found"))
            },
            || host.clone(),
        )
        .unwrap();

        assert_eq!(env.get("APP_VAR").map(String::as_str), Some("overridden"));
        assert_eq!(env.get("HOME").map(String::as_str), Some("/home/hostuser"));
        assert_eq!(env.get("CUSTOM").map(String::as_str), Some("value"));
    }
}
