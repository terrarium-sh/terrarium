//! `terra ls` - list this directory's boxes, or every box on this machine.

use crate::state::BoxRef;
use crate::{config, resolve, state};
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

pub fn run(args: &crate::cli::LsArgs, project_dir: &Path) -> Result<ExitCode> {
    let boxes = if args.all {
        boxes_on_this_machine()?
    } else {
        boxes_of_project(project_dir)?
    };
    if args.tsv {
        for bx in boxes {
            println!("{}", tsv_line(&bx));
        }
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
    for bx in boxes {
        let box_state = bx.state();
        if args.all {
            println!(
                "{box_state:<12} {} ({})",
                bx.project_dir().display(),
                bx.name()
            );
        } else {
            println!("{box_state:<12} {}", bx.name());
        }
        if !matches!(box_state, state::BoxState::NotCreated) {
            println!("  files: {}", bx.dir().display());
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn tsv_line(bx: &BoxRef) -> String {
    format!(
        "{}\t{}\t{}\t{}",
        bx.state(),
        bx.name(),
        bx.project_dir().display(),
        bx.dir().display()
    )
}

fn boxes_of_project(project_dir: &Path) -> Result<Vec<BoxRef>> {
    // Listing is what you reach for to find out what is wrong, so a broken
    // manifest must not be the thing that stops it.
    resolve::list_known_names(
        project_dir,
        config::load_manifest_or_warn(project_dir).as_ref(),
    )
    .iter()
    .map(|n| BoxRef::resolve(project_dir, n))
    .collect()
}

/// Every box under [`state::box_home_path`], sorted by the directory it belongs
/// to. A slug that never recorded an origin label is not ours to list.
fn boxes_on_this_machine() -> Result<Vec<BoxRef>> {
    let home = state::box_home_path()?;
    let mut boxes: Vec<(PathBuf, String, PathBuf)> = Vec::new();
    for project in
        crate::sys::dir_entries(&home).filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
    {
        let project = project.path();
        let Some(origin) = state::read_origin(&project) else {
            continue;
        };
        for (name, dir) in state::boxes_in(&project) {
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

    /// `--tsv` is the one format scripts may rely on, so the line itself is
    /// the contract: four tab-separated fields - state, name, directory,
    /// files - in that order. The human listing is prose and free to change;
    /// this one is not.
    #[test]
    fn a_tsv_line_is_four_fields_in_the_promised_order() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.dir()).unwrap();
        std::fs::write(bx.rootfs_img(), b"image").unwrap();

        let line = tsv_line(&bx);
        let fields: Vec<&str> = line.split('\t').collect();
        assert_eq!(
            fields,
            [
                "stopped".to_string(),
                "dev".to_string(),
                dir.path().display().to_string(),
                bx.dir().display().to_string(),
            ],
            "{line}"
        );
    }
}
