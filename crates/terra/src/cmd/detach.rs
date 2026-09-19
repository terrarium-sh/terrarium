//! `terra <box> detach` - drop one attached client of a running box's
//! session, or every one of them. The agent closes that client's connection,
//! so its terminal is restored wherever it hung.

use crate::resolve;
use crate::session;
use anyhow::Result;
use std::path::Path;
use std::process::ExitCode;

pub async fn run(
    args: &crate::cli::DetachArgs,
    name: Option<&str>,
    project_dir: &Path,
) -> Result<ExitCode> {
    let bx = &resolve::resolve_pinned_box(project_dir, name)?;
    if let Some(id) = args.id {
        session::detach_client(bx, id, args.agent.agent_timeout).await?;
        eprintln!("terra: detached client {id} from {bx}");
    } else {
        let detached = session::detach_all(bx, args.agent.agent_timeout).await?;
        if detached == 0 {
            eprintln!("terra: nobody was attached to {bx}");
        } else {
            eprintln!("terra: detached {detached} clients from {bx}");
        }
    }
    Ok(ExitCode::SUCCESS)
}
