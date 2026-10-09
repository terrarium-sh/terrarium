//! `terra <box> exec` - run one command in a running box, on a terminal of its
//! own. The pumping machinery it shares with sessions is [`crate::session`]'s.

use crate::resolve;
use crate::session::{self, pump_exec};
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;
use terra_protocol::{AgentService, ExecRequest, write_frame_async};

pub async fn run(
    args: &crate::cli::ExecArgs,
    name: Option<&str>,
    project_dir: &Path,
    is_at_a_terminal: bool,
) -> Result<ExitCode> {
    let bx = &resolve::resolve_pinned_box(project_dir, name)?;
    let mut stream = session::connect_to_running_agent(
        bx,
        "exec",
        AgentService::Exec,
        "exec service",
        args.agent.agent_timeout,
    )
    .await?;

    let env = resolve_exec_env(&args.env)?;

    let tty = args.wants_a_terminal(is_at_a_terminal);
    let req = ExecRequest {
        argv: args.command.clone(),
        as_root: args.root,
        tty: tty.then(|| session::read_terminal_size().unwrap_or(session::DEFAULT_TERMINAL_SIZE)),
        workdir: args.workdir.clone(),
        env,
    };
    write_frame_async(&mut stream, &req)
        .await
        .context("sending the exec request")?;
    Ok(ExitCode::from(crate::exit_status_byte(
        pump_exec(stream, tty).await?,
    )))
}

fn resolve_exec_env(entries: &[String]) -> Result<BTreeMap<String, String>> {
    resolve_exec_env_from(entries, |k| {
        std::env::var(k)
            .map_err(|_| anyhow::anyhow!("environment variable `{k}` is not set on the host"))
    })
}

fn resolve_exec_env_from(
    entries: &[String],
    lookup_host_var: impl Fn(&str) -> Result<String>,
) -> Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
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
            resolve_exec_env_from(&entries, |k| {
                bail!("environment variable `{k}` is not set on the host")
            })
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
            resolve_exec_env_from(&entries, |k| {
                host.get(k).cloned().ok_or_else(|| {
                    anyhow::anyhow!("environment variable `{k}` is not set on the host")
                })
            })
        };

        let env = parse(&["SET"]).unwrap();
        assert_eq!(env.get("SET").map(String::as_str), Some("val"));

        let err = parse(&["UNSET"]).unwrap_err();
        assert!(err.to_string().contains("is not set on the host"), "{err}");

        assert!(parse(&["WITH_NUL"]).is_err());
    }
}
