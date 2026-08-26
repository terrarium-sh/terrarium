//! `terra <box> exec` - run one command in a running box, on a terminal of its
//! own. The pumping machinery it shares with sessions is [`crate::session`]'s.

use crate::session::{self, pump_exec};
use crate::{exit_code, resolve};
use anyhow::{Context, Result};
use std::path::Path;
use std::process::ExitCode;

pub fn run(
    args: &crate::cli::ExecArgs,
    name: Option<&str>,
    project_dir: &Path,
    at_a_terminal: bool,
) -> Result<ExitCode> {
    use std::io::Write;
    let bx = &resolve::resolve_pinned_box(project_dir, name)?;
    let stream = session::connect_to_running_agent(
        bx,
        "exec",
        terra_shared::AgentService::Exec,
        "exec service",
        args.agent.agent_timeout,
    )?;

    let tty = args.wants_a_terminal(at_a_terminal);
    let req = terra_shared::ExecRequest {
        argv: args.command.clone(),
        as_root: args.root,
        tty: tty.then(|| session::terminal_size().unwrap_or(session::DEFAULT_TERMINAL_SIZE)),
    };
    (&stream)
        .write_all(&terra_shared::frame(&req).context("encoding the exec request")?)
        .context("sending the exec request")?;
    Ok(exit_code(pump_exec(&stream, tty)?))
}
