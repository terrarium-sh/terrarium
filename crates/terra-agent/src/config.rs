use super::bootstrap::mount;
use super::hooks::{HOOK_TIMEOUT, wait_for_child};
use anyhow::{Context, Result, bail};
use rustix::mount::MountFlags;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use tokio_util::sync::CancellationToken;

const SUBORDINATE_ID_START: u32 = 100_000;
const SUBORDINATE_ID_COUNT: u32 = 65_536;
const DOAS_CONF: &str = "/etc/doas.conf";
const DOAS_DIR: &str = "/etc/doas.d";

pub(super) async fn configure_network(
    net: &terra_protocol::Net,
    cancellation: &CancellationToken,
) -> Result<()> {
    run_ip(&["link", "set", "lo", "up"], cancellation).await?;
    run_ip(
        &[
            "addr",
            "add",
            &format!("{}/{}", net.guest_ip, net.prefix),
            "dev",
            "eth0",
        ],
        cancellation,
    )
    .await?;
    run_ip(&["link", "set", "eth0", "up"], cancellation).await?;
    run_ip(
        &["route", "add", "default", "via", &net.gateway.to_string()],
        cancellation,
    )
    .await?;
    fs::write("/etc/resolv.conf", format!("nameserver {}\n", net.dns))
        .context("writing /etc/resolv.conf")
}

async fn run_ip(args: &[&str], cancellation: &CancellationToken) -> Result<()> {
    let mut command = Command::new("ip");
    command.args(args);
    let (mut child, pidfd) = crate::reap::spawn_owned(|| command.spawn()).context("running ip")?;
    let status = wait_for_child(&mut child, &pidfd, Some(HOOK_TIMEOUT), cancellation)
        .await
        .context("waiting for ip")?;
    if !status.success() {
        bail!("ip {args:?} failed ({status})");
    }
    Ok(())
}

pub(super) fn mount_filesystems(plan: &terra_protocol::Plan) -> Result<()> {
    for share in &plan.shares {
        mount_share(share)?;
    }
    for volume in &plan.volumes {
        prepare_mount_point(&volume.guest)?;
        mount(
            Some(&volume.dev),
            &volume.guest,
            Some("ext4"),
            MountFlags::NOSUID | MountFlags::NODEV,
        )?;
        if !plan.root
            && let Err(error) = rustix::fs::chown(
                &volume.guest,
                Some(rustix::process::Uid::from_raw(terra_protocol::WORKLOAD_ID)),
                Some(rustix::process::Gid::from_raw(terra_protocol::WORKLOAD_ID)),
            )
        {
            eprintln!("terra: warning: could not chown {}: {error}", volume.guest);
        }
    }
    Ok(())
}

fn mount_share(share: &terra_protocol::Share) -> Result<()> {
    prepare_mount_point(&share.guest)?;
    let flags = if share.readonly {
        MountFlags::RDONLY
    } else {
        MountFlags::empty()
    };
    mount(
        Some(&share.tag),
        &share.guest,
        Some("virtiofs"),
        flags | MountFlags::NOSUID | MountFlags::NODEV,
    )
}

fn prepare_mount_point(path: &str) -> Result<()> {
    crate::sync::ensure_directory(Path::new(path), false)
        .with_context(|| format!("creating mount point {path}"))
}

pub(super) fn ensure_baked(on_create: &[String]) -> Result<()> {
    if on_create.is_empty() || is_baked(&on_create.join("\n"))? {
        return Ok(());
    }
    bail!(
        "this box's on_create never finished baking - `terra setup` re-runs it (`--rebuild` for a clean slate)"
    )
}

pub(super) fn is_baked(recipe: &str) -> Result<bool> {
    match fs::read_to_string(terra_protocol::RECIPE_STAMP_PATH) {
        Ok(stamped) if stamped == recipe => Ok(true),
        Ok(stamped) if !stamped.is_empty() => {
            eprintln!(
                "terra: warning: on_create changed since this box was created, and the old one is already baked in; keeping it (`terra rm` rebuilds)"
            );
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context(format!("reading {}", terra_protocol::RECIPE_STAMP_PATH)),
    }
}

pub(super) async fn configure_user(as_root: bool, cancellation: &CancellationToken) -> Result<()> {
    if as_root {
        return Ok(());
    }
    let entry = format!("{}:", terra_protocol::WORKLOAD_USER_NAME);
    if !fs::read_to_string("/etc/passwd")
        .is_ok_and(|passwords| passwords.lines().any(|line| line.starts_with(&entry)))
    {
        let workload_id = terra_protocol::WORKLOAD_ID.to_string();
        run_quiet_command(
            "addgroup",
            &["-g", &workload_id, terra_protocol::WORKLOAD_USER_NAME],
            cancellation,
        )
        .await;
        run_quiet_command(
            "adduser",
            &[
                "-D",
                "-u",
                &workload_id,
                "-G",
                terra_protocol::WORKLOAD_USER_NAME,
                terra_protocol::WORKLOAD_USER_NAME,
            ],
            cancellation,
        )
        .await;
    }
    setup_subordinate_ids("/etc/subuid")?;
    setup_subordinate_ids("/etc/subgid")?;
    setup_rootless_container_config()?;
    let runtime_dir = format!("/run/user/{}", terra_protocol::WORKLOAD_ID);
    fs::create_dir_all(&runtime_dir).with_context(|| format!("creating {runtime_dir}"))?;
    fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700))?;
    rustix::fs::chown(
        &runtime_dir,
        Some(rustix::process::Uid::from_raw(terra_protocol::WORKLOAD_ID)),
        Some(rustix::process::Gid::from_raw(terra_protocol::WORKLOAD_ID)),
    )?;
    Ok(())
}

pub(super) fn configure_sudo(as_root: bool, commands: &[String]) -> Result<()> {
    use std::fmt::Write as _;
    if as_root {
        return Ok(());
    }
    match fs::remove_dir_all(DOAS_DIR) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context(format!("removing {DOAS_DIR}")),
    }
    fs::create_dir_all(DOAS_DIR).with_context(|| format!("creating {DOAS_DIR}"))?;
    let mut policy =
        String::from("# Generated by terra from the profile's `sudo:` - edits are overwritten.\n");
    for command in commands {
        if command.contains(['\n', '#']) {
            eprintln!("terra: warning: skipping invalid sudo `{command}`");
            continue;
        }
        let _ = writeln!(
            policy,
            "permit nopass {} cmd {command}",
            terra_protocol::WORKLOAD_ID
        );
    }
    fs::write(DOAS_CONF, policy).with_context(|| format!("writing {DOAS_CONF}"))?;
    fs::set_permissions(DOAS_CONF, fs::Permissions::from_mode(0o640))
        .with_context(|| format!("securing {DOAS_CONF}"))?;
    Ok(())
}

fn setup_rootless_container_config() -> Result<()> {
    if !Path::new("/usr/bin/podman").exists() {
        return Ok(());
    }
    let config_dir = format!("{}/.config/containers", terra_protocol::WORKLOAD_HOME);
    crate::sync::ensure_directory(Path::new(&config_dir), true)?;
    let config = format!("{config_dir}/containers.conf");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&config)
    {
        Ok(mut file) => file.write_all(b"[engine]\ncgroup_manager = \"cgroupfs\"\n")?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).with_context(|| format!("creating {config}")),
    }
    rustix::fs::chown(
        &config,
        Some(rustix::process::Uid::from_raw(terra_protocol::WORKLOAD_ID)),
        Some(rustix::process::Gid::from_raw(terra_protocol::WORKLOAD_ID)),
    )?;
    Ok(())
}

fn setup_subordinate_ids(path: &str) -> Result<()> {
    let entry = format!(
        "{}:{SUBORDINATE_ID_START}:{SUBORDINATE_ID_COUNT}",
        terra_protocol::WORKLOAD_USER_NAME
    );
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).with_context(|| format!("reading {path}")),
    };
    if contents
        .lines()
        .all(|line| !line.starts_with(&format!("{}:", terra_protocol::WORKLOAD_USER_NAME)))
    {
        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?;
        if !contents.is_empty() && !contents.ends_with('\n') {
            writeln!(file)?;
        }
        writeln!(file, "{entry}")?;
    }
    Ok(())
}

async fn run_quiet_command(command_name: &str, args: &[&str], cancellation: &CancellationToken) {
    use std::os::unix::process::CommandExt as _;
    let mut command = Command::new(command_name);
    command
        .args(args)
        .process_group(0)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let status = match crate::reap::spawn_owned(|| command.spawn()) {
        Ok((mut child, pidfd)) => {
            wait_for_child(&mut child, &pidfd, Some(HOOK_TIMEOUT), cancellation).await
        }
        Err(error) => Err(error),
    };
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => eprintln!(
            "terra: warning: `{command_name}` exited {status} - the {} user may be missing",
            terra_protocol::WORKLOAD_USER_NAME
        ),
        Err(error) => eprintln!("terra: warning: could not run `{command_name}`: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    #[test]
    fn an_empty_on_create_needs_no_bake_stamp() {
        assert!(ensure_baked(&[]).is_ok());
    }

    #[test]
    fn subordinate_ids_append_to_a_file_without_a_trailing_newline() {
        let path = crate::create_scratch_path("init", "subordinate-ids");
        fs::write(&path, "other:200000:65536").unwrap();
        setup_subordinate_ids(path.to_str().unwrap()).unwrap();
        setup_subordinate_ids(path.to_str().unwrap()).unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "other:200000:65536\nterri:100000:65536\n"
        );
        fs::remove_file(path).unwrap();
    }
    #[test]
    fn a_symlinked_mount_point_is_supported() {
        let real = crate::create_scratch_path("init", "mp-real");
        let link = crate::create_scratch_path("init", "mp-link");
        let fresh = crate::create_scratch_path("init", "mp-fresh");
        let _ = fs::remove_dir_all(&real);
        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&fresh);
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        prepare_mount_point(&link.to_string_lossy()).unwrap();
        prepare_mount_point(&link.join("src").to_string_lossy()).unwrap();
        assert!(real.join("src").is_dir());
        assert!(prepare_mount_point(&real.to_string_lossy()).is_ok());
        assert!(prepare_mount_point(&fresh.join("a/b").to_string_lossy()).is_ok());
        assert!(fresh.join("a/b").is_dir());

        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&real);
        let _ = fs::remove_dir_all(&fresh);
    }
}
