//! `terra <box> sessions` - list the clients attached to a running box's
//! session, as the ids `terra <box> detach` takes.

use crate::resolve;
use crate::session::{self, SessionClient};
use anyhow::Result;
use std::path::Path;
use std::process::ExitCode;

pub fn run(
    args: &crate::cli::SessionsArgs,
    name: Option<&str>,
    project_dir: &Path,
) -> Result<ExitCode> {
    let bx = &resolve::resolve_pinned_box(project_dir, name)?;
    let clients = session::list_clients(bx, args.agent.agent_timeout)?;
    if clients.is_empty() {
        eprintln!("terra: nobody is attached to {bx}");
    }
    for client in clients {
        println!("{}", format_client_line(&client));
    }
    Ok(ExitCode::SUCCESS)
}

fn format_client_line(client: &SessionClient) -> String {
    let size = client
        .reported_term_size
        .map_or_else(|| "-".to_owned(), |s| format!("{}x{}", s.rows, s.cols));
    format!("{}\t{size}", client.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one line a script may rely on: id, then size, tab-separated, with
    /// `-` for a client that reported none. The human listing is the same line
    /// per client, so a script's parse works there too.
    #[test]
    fn a_client_line_is_id_then_size() {
        assert_eq!(
            format_client_line(&SessionClient {
                id: 3,
                reported_term_size: None
            }),
            "3\t-"
        );
        assert_eq!(
            format_client_line(&SessionClient {
                id: 7,
                reported_term_size: Some(terra_shared::contract::TermSize { rows: 24, cols: 80 })
            }),
            "7\t24x80"
        );
    }
}
