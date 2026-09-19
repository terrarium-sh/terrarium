//! `terra completions <SHELL>` - print shell completion script to stdout.

use crate::render;
use anyhow::Result;
use clap::CommandFactory;
use std::io::Write;
use std::process::ExitCode;

pub fn generate_completions<W: Write>(shell: clap_complete::Shell, out: &mut W) -> Result<()> {
    let mut cmd = crate::cli::Cli::command();
    let mut buf = Vec::new();
    clap_complete::generate(shell, &mut cmd, "terra", &mut buf);
    render::finish_stdout_write(out.write_all(&buf))?;
    render::finish_stdout_write(out.flush())
}

pub fn run(args: &crate::cli::CompletionsArgs) -> Result<ExitCode> {
    let mut out = std::io::stdout().lock();
    generate_completions(args.shell, &mut out)?;
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap_complete::Shell;

    #[test]
    fn generates_completion_scripts_for_all_shells() {
        for shell in [
            Shell::Bash,
            Shell::Elvish,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Zsh,
        ] {
            let mut out = Vec::new();
            generate_completions(shell, &mut out).unwrap();
            let script = String::from_utf8(out).unwrap();
            assert!(!script.is_empty());
            assert!(script.contains("terra"));
        }
    }
}
