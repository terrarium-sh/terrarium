//! `terra ls` - list this directory's boxes, or every box on this machine.

use crate::state::BoxRef;
use crate::{config, render, resolve, state};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub fn run(args: &crate::cli::LsArgs, project_dir: &Path) -> Result<ExitCode> {
    let boxes = if args.all {
        list_boxes_on_this_machine()?
    } else {
        list_boxes_of_project(project_dir)?
    };
    if args.tsv {
        let mut out = std::io::stdout().lock();
        for bx in boxes {
            render::finish_stdout_write(writeln!(out, "{}", format_tsv_line(&bx)))?;
        }
        return Ok(ExitCode::SUCCESS);
    }
    if args.json {
        let entries: Vec<BoxEntry<'_>> = boxes
            .iter()
            .map(|bx| {
                let box_state = bx.get_state();
                let (pid, process_identity) = if box_state == state::BoxState::Running {
                    bx.read_vm_process()
                        .map_or((None, None), |vm| (Some(vm.pid), vm.process_identity))
                } else {
                    (None, None)
                };
                BoxEntry {
                    name: bx.get_name(),
                    state: box_state,
                    project_dir: bx.get_project_dir(),
                    dir: bx.get_dir(),
                    pid,
                    process_identity,
                }
            })
            .collect();
        let json = serde_json::to_string_pretty(&entries).context("serializing boxes to json")?;
        let mut out = std::io::stdout().lock();
        render::finish_stdout_write(writeln!(out, "{json}"))?;
        return Ok(ExitCode::SUCCESS);
    }

    if boxes.is_empty() {
        if args.all {
            eprintln!("terra: no boxes on this machine");
        } else {
            eprintln!(
                "terra: no boxes in {} - `terra <box> setup` makes one",
                project_dir.display()
            );
        }
        return Ok(ExitCode::SUCCESS);
    }
    let mut out = std::io::stdout().lock();
    for bx in boxes {
        let box_state = bx.get_state();
        if args.all {
            render::finish_stdout_write(writeln!(
                out,
                "{box_state:<12} {} ({})",
                bx.get_project_dir().display(),
                bx.get_name()
            ))?;
        } else {
            render::finish_stdout_write(writeln!(out, "{box_state:<12} {}", bx.get_name()))?;
        }
        if !matches!(box_state, state::BoxState::NotCreated) {
            render::finish_stdout_write(writeln!(out, "  files: {}", bx.get_dir().display()))?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn format_tsv_line(bx: &BoxRef) -> String {
    format!(
        "{}\t{}\t{}\t{}",
        bx.get_state(),
        render::escape_printable(bx.get_name()),
        render::escape_printable_path(bx.get_project_dir()),
        render::escape_printable_path(bx.get_dir())
    )
}

#[derive(serde::Serialize)]
struct BoxEntry<'a> {
    name: &'a str,
    state: state::BoxState,
    project_dir: &'a Path,
    dir: &'a Path,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    /// Opaque platform-specific process start identity token (Linux ticks
    /// since boot, macOS epoch microseconds, Windows FILETIME) used to
    /// distinguish the running VM from a recycled PID.
    #[serde(skip_serializing_if = "Option::is_none")]
    process_identity: Option<u64>,
}

fn list_boxes_of_project(project_dir: &Path) -> Result<Vec<BoxRef>> {
    // Listing is what you reach for to find out what is wrong, so a broken
    // manifest must not be the thing that stops it.
    resolve::list_known_names(
        project_dir,
        config::load_manifest_or_warn(project_dir).as_ref(),
    )?
    .iter()
    .map(|n| BoxRef::resolve(project_dir, n))
    .collect()
}

/// Every box under [`state::get_box_home_path`], sorted by the directory it belongs
/// to. A slug that never recorded an origin label is not ours to list.
fn list_boxes_on_this_machine() -> Result<Vec<BoxRef>> {
    let home = state::get_box_home_path()?;
    let mut boxes: Vec<(PathBuf, String, PathBuf)> = Vec::new();
    let projects = match std::fs::read_dir(&home) {
        Ok(projects) => projects,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error).with_context(|| format!("reading {}", home.display())),
    }
    .collect::<std::io::Result<Vec<_>>>()?;
    for project in projects
        .into_iter()
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
    {
        let project = project.path();
        let Some(origin) = state::read_origin(&project) else {
            continue;
        };
        let project_boxes = match state::list_boxes_in(&project) {
            Ok(boxes) => boxes,
            Err(error) => {
                eprintln!(
                    "terra: skipping unreadable box state {}: {error:#}",
                    project.display()
                );
                continue;
            }
        };
        for (name, dir) in project_boxes {
            boxes.push((origin.clone(), name, dir));
        }
    }
    boxes.sort();
    Ok(boxes
        .into_iter()
        .map(|(origin, _, dir)| BoxRef::from_state_dir(dir, &origin))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn unreadable_project_state_does_not_hide_other_boxes() {
        use std::os::unix::fs::PermissionsExt;

        if crate::sys::is_host_root() {
            return;
        }
        let _home = crate::sys::TestHome::new();
        let projects = tempfile::tempdir().unwrap();
        let visible = BoxRef::resolve(&projects.path().join("visible"), "dev").unwrap();
        let unreadable = BoxRef::resolve(&projects.path().join("unreadable"), "dev").unwrap();
        for bx in [&visible, &unreadable] {
            std::fs::create_dir_all(bx.get_dir()).unwrap();
            bx.write_origin();
        }
        let unreadable_project = unreadable.get_dir().parent().unwrap();
        std::fs::set_permissions(unreadable_project, std::fs::Permissions::from_mode(0o100))
            .unwrap();
        let listed = list_boxes_on_this_machine();
        std::fs::set_permissions(unreadable_project, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        let listed = listed.unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].get_dir(), visible.get_dir());
    }

    /// `--tsv` is the one format scripts may rely on, so the line itself is
    /// the contract: four tab-separated fields - state, name, directory,
    /// files - in that order. The human listing is prose and free to change;
    /// this one is not.
    #[test]
    fn a_tsv_line_is_four_fields_in_the_promised_order() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(crate::state::ROOTFS_FILE), b"image").unwrap();

        let line = format_tsv_line(&bx);
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            fields,
            [
                "stopped".to_string(),
                "dev".to_string(),
                dir.path().display().to_string(),
                bx.get_dir().display().to_string(),
            ],
            "{line}"
        );
    }

    #[test]
    fn a_json_listing_is_an_array_with_promised_fields() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(crate::state::ROOTFS_FILE), b"image").unwrap();

        let entries = vec![
            BoxEntry {
                name: bx.get_name(),
                state: bx.get_state(),
                project_dir: bx.get_project_dir(),
                dir: bx.get_dir(),
                pid: None,
                process_identity: None,
            },
            BoxEntry {
                name: bx.get_name(),
                state: state::BoxState::Running,
                project_dir: bx.get_project_dir(),
                dir: bx.get_dir(),
                pid: Some(1234),
                process_identity: Some(5678),
            },
        ];
        let json = serde_json::to_string(&entries).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0]["name"], "dev");
        assert_eq!(parsed[0]["state"], "stopped");
        assert_eq!(parsed[0]["project_dir"], dir.path().to_str().unwrap());
        assert_eq!(parsed[0]["dir"], bx.get_dir().to_str().unwrap());
        assert!(parsed[0].get("pid").is_none());
        assert!(parsed[0].get("process_identity").is_none());
        assert_eq!(parsed[1]["pid"], 1234);
        assert_eq!(parsed[1]["process_identity"], 5678);
    }
}
