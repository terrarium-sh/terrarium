//! `terra <box> sessions` - list the clients attached to a running box's
//! session, as the ids `terra <box> detach` takes.

use crate::session::{self, SessionClient};
use crate::{render, resolve};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;
use std::process::ExitCode;

#[derive(serde::Serialize)]
struct SessionEntry {
    id: u64,
    term_size: Option<terra_protocol::TermSize>,
}

pub async fn run(
    args: &crate::cli::SessionsArgs,
    name: Option<&str>,
    project_dir: &Path,
) -> Result<ExitCode> {
    let bx = &resolve::resolve_pinned_box(project_dir, name)?;
    let clients = session::list_clients(bx, args.agent.agent_timeout).await?;
    if args.json {
        let entries: Vec<SessionEntry> = clients
            .into_iter()
            .map(|client| SessionEntry {
                id: client.id,
                term_size: client.reported_term_size,
            })
            .collect();
        let json =
            serde_json::to_string_pretty(&entries).context("serializing sessions to json")?;
        let mut out = std::io::stdout().lock();
        render::finish_stdout_write(writeln!(out, "{json}"))?;
        return Ok(ExitCode::SUCCESS);
    }
    if clients.is_empty() {
        eprintln!("terra: nobody is attached to {bx}");
    }
    let mut out = std::io::stdout().lock();
    for client in clients {
        render::finish_stdout_write(writeln!(out, "{}", format_client_line(&client)))?;
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
                reported_term_size: Some(terra_protocol::TermSize { rows: 24, cols: 80 })
            }),
            "7\t24x80"
        );
    }

    #[test]
    fn session_entry_serializes_to_json_with_snake_case_keys() {
        let entries = vec![
            SessionEntry {
                id: 1,
                term_size: Some(terra_protocol::TermSize { rows: 24, cols: 80 }),
            },
            SessionEntry {
                id: 2,
                term_size: None,
            },
        ];
        let json = serde_json::to_string(&entries).unwrap();
        assert!(json.contains(r#"{"id":1,"term_size":{"rows":24,"cols":80}}"#));
        assert!(json.contains(r#"{"id":2,"term_size":null}"#));
    }
}
