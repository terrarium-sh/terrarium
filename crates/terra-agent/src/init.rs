//! Guest init (PID 1): bring the guest up and run the plan.

use crate::term::session::{
    ClientConn, DEFAULT_COLS, DEFAULT_ROWS, MAX_COLS, MAX_ROWS, MIN_COLS, MIN_ROWS, Session, Sink,
};
use crate::term::tty::{get_winsize, set_raw, set_winsize};
use crate::vsock::{VMADDR_CID_HOST, VsockListener, connect};
use anyhow::{Context, Result, bail};
use pty_process::blocking::Command as PtyCommand;
use pty_process::blocking::Pty;
use rustix::mount::MountFlags;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use terra_shared::contract::{
    CONTROL_VSOCK_PORT, DEFAULT_STOP_GRACE_SECS, Net, Plan, PlanMode, RECIPE_STAMP_PATH,
    RESIZE2FS_GUEST_PATH, ROOT_DEVICE, STOP_SIGNAL, Share, WORKLOAD_ID, WORKLOAD_USER_NAME,
};
use terra_shared::no_symlinks;

const AGENT_FAILED: i32 = 1;
const CLEAN_MOUNT: &str = "/mnt/clean";

pub fn boot() -> bool {
    let (control, outcome) = match enter_root() {
        Ok((plan, control, owner_userns)) => {
            let outcome = execute(&plan, &control, owner_userns.as_ref());
            (Some(control), outcome)
        }
        Err(e) => (None, Err(e)),
    };
    if let Err(e) = &outcome {
        eprintln!("terra-agent: init failed: {e:#}");
    }

    let code = *outcome.as_ref().unwrap_or(&AGENT_FAILED);
    // Disk sync happens before reporting so host teardown is safe to race.
    rustix::fs::sync();
    // libkrun's exit-code ioctl requires a virtiofs root; an ext4 guest reports 0.
    if let Some(mut control) = control {
        let report = terra_shared::contract::encode_frame(&code)
            .and_then(|frame| control.write_all(&frame).and_then(|()| control.flush()));
        if let Err(e) = report {
            eprintln!("terra-agent: warning: could not report the exit status ({code}): {e}");
        }
    }
    outcome.is_err()
}

fn enter_root() -> Result<(Plan, File, Option<std::os::fd::OwnedFd>)> {
    const NEWROOT: &str = "/mnt/root";

    mount(None, "/proc", Some("proc"), MountFlags::empty()).context("mounting /proc")?;
    mount(None, "/sys", Some("sysfs"), MountFlags::empty()).context("mounting /sys")?;
    fs::create_dir_all("/dev/pts")?;
    mount(None, "/dev/pts", Some("devpts"), MountFlags::empty()).context("mounting /dev/pts")?;
    fs::create_dir_all("/dev/shm")?;
    for (target, fstype) in [("/dev/shm", "tmpfs"), ("/sys/fs/cgroup", "cgroup2")] {
        if let Err(e) = mount(None, target, Some(fstype), MountFlags::empty()) {
            eprintln!("terra: warning: could not mount {target}: {e:#}");
        }
    }
    redirect_console_ports();
    mount(None, "/mnt", Some("tmpfs"), MountFlags::empty())
        .context("mounting the staging tmpfs")?;
    fs::create_dir_all(NEWROOT)?;
    fs::create_dir_all(CLEAN_MOUNT)?;

    let mut control =
        connect(VMADDR_CID_HOST, CONTROL_VSOCK_PORT).context("dialling the host control port")?;
    let plan: Plan = terra_shared::contract::read_frame(&mut control)
        .context("reading the boot plan")?
        .ok_or_else(|| anyhow::anyhow!("control channel closed before receiving boot plan"))?;

    grow_filesystem(ROOT_DEVICE);
    for d in &plan.volumes {
        grow_filesystem(&d.dev);
    }

    let owner_userns = plan
        .share_owner
        .filter(|_| !plan.shares.is_empty())
        .map(crate::idmap::create_owner_userns)
        .transpose()?;

    mount(
        Some(ROOT_DEVICE),
        NEWROOT,
        Some("ext4"),
        MountFlags::empty(),
    )
    .with_context(|| format!("mounting the guest rootfs image ({ROOT_DEVICE})"))?;

    for d in ["proc", "sys", "dev", "terra"] {
        fs::create_dir_all(format!("{NEWROOT}/{d}"))?;
    }
    for d in ["proc", "sys", "dev"] {
        mount(
            Some(&format!("/{d}")),
            &format!("{NEWROOT}/{d}"),
            None,
            rustix::mount::MountFlags::BIND | rustix::mount::MountFlags::REC,
        )
        .with_context(|| format!("binding /{d} into the guest root"))?;
    }

    rustix::process::chroot(NEWROOT).context("chroot into the guest root")?;
    // chroot leaves cwd outside the new root.
    std::env::set_current_dir("/").context("chdir after chroot")?;
    apply_tz(plan.host_tz.as_deref());
    Ok((plan, control, owner_userns))
}

fn redirect_console_ports() {
    let Ok(ports) = fs::read_dir("/sys/class/virtio-ports") else {
        return;
    };
    for entry in ports.flatten() {
        let Ok(name) = fs::read_to_string(entry.path().join("name")) else {
            continue;
        };
        let (target, writable) = match name.trim() {
            "krun-stdin" => (0, false),
            "krun-stdout" => (1, true),
            "krun-stderr" => (2, true),
            _ => continue,
        };
        let dev = format!("/dev/{}", entry.file_name().to_string_lossy());
        let opened = if writable {
            fs::OpenOptions::new().write(true).open(&dev)
        } else {
            fs::File::open(&dev)
        };
        match opened {
            // Keep fd open so stdio does not close with it.
            Ok(f) if f.as_raw_fd() == target => {
                let _ = rustix::io::fcntl_setfd(&f, rustix::io::FdFlags::empty());
                std::mem::forget(f);
            }
            Ok(f) => {
                let _ = match target {
                    0 => rustix::stdio::dup2_stdin(&f),
                    1 => rustix::stdio::dup2_stdout(&f),
                    2 => rustix::stdio::dup2_stderr(&f),
                    _ => unreachable!("unexpected console fd target: {target}"),
                };
            }
            Err(e) => eprintln!("terra: warning: could not open {dev}: {e}"),
        }
    }
}

fn grow_filesystem(dev: &str) {
    if let Err(e) = mount(Some(dev), CLEAN_MOUNT, Some("ext4"), MountFlags::empty()) {
        eprintln!("terra: warning: {dev} would not mount ({e:#}) - skipping resize");
        return;
    }
    if let Err(e) = rustix::mount::unmount(CLEAN_MOUNT, rustix::mount::UnmountFlags::empty())
        .map_err(std::io::Error::from)
        .with_context(|| format!("umount {CLEAN_MOUNT}"))
    {
        eprintln!("terra: warning: could not unmount {CLEAN_MOUNT} ({e:#}) - skipping resize");
        let _ = rustix::mount::unmount(CLEAN_MOUNT, rustix::mount::UnmountFlags::DETACH);
        return;
    }
    match Command::new(RESIZE2FS_GUEST_PATH)
        .args(["-f", dev])
        .status()
    {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("terra: warning: resize2fs {dev} exited {s} - image may be undersized"),
        Err(e) => eprintln!("terra: warning: could not run resize2fs for {dev}: {e}"),
    }
}

fn apply_tz(bytes: Option<&[u8]>) {
    if let Some(bytes) = bytes.filter(|bytes| !bytes.is_empty()) {
        let _ = std::fs::create_dir_all("/etc");
        let tmp = "/etc/.localtime.tmp";
        if let Err(e) = std::fs::write(tmp, bytes) {
            eprintln!("terra-agent: warning: could not write /etc/localtime: {e}");
        } else {
            let _ = std::fs::rename(tmp, "/etc/localtime");
        }
    }
}

fn mount(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: rustix::mount::MountFlags,
) -> Result<()> {
    rustix::mount::mount(
        source.unwrap_or("none"),
        target,
        fstype.unwrap_or("none"),
        flags,
        c"",
    )
    .map_err(std::io::Error::from)
    .with_context(|| format!("mounting {target}"))
}

#[allow(unsafe_code)]
fn execute(
    plan: &Plan,
    control: &File,
    owner_userns: Option<&std::os::fd::OwnedFd>,
) -> Result<i32> {
    // The vsock port is bound before any hooks or network run.
    // Otherwise guest code could bind it first over vsock loopback and hijack agent services.
    let port = crate::vsock::VsockListener::bind(terra_shared::contract::AGENT_VSOCK_PORT)
        .map_err(|e| anyhow::anyhow!("binding the agent port: {e}"))?;

    restrict_ptrace();
    setup_env(plan);
    crate::reap::watch_orphans();
    setup_net(&plan.net)?;

    // HOME is the workload's in every mode, so it must exist even in a bake,
    // which has not created its user yet.
    let home = terra_shared::contract::WORKLOAD_HOME;
    crate::files::ensure_directory(Path::new(home), true)
        .with_context(|| format!("creating home {home}"))?;

    // A Create VM has no shares and is guest root.
    if plan.mode == PlanMode::Create {
        return bake_if_stale(&plan.on_create).map(|()| 0);
    }
    if !is_baked(&plan.on_create.join("\n"))? {
        bail!(
            "this box's on_create never finished baking - `terra setup` re-runs it \
             (`--rebuild` for a clean slate)"
        );
    }

    for s in &plan.shares {
        mount_share(s, owner_userns)?;
    }
    // Volumes are guest-local ext4; hand each one's root to the workload user
    // so both guest users can write.
    for d in &plan.volumes {
        prepare_mount_point(&d.guest)?;
        mount(
            Some(&d.dev),
            &d.guest,
            Some("ext4"),
            MountFlags::NOSUID | MountFlags::NODEV,
        )?;
        if !plan.root {
            // Chown after mount targets the volume's root inode, not the underlying directory.
            if let Err(e) = rustix::fs::chown(
                &d.guest,
                Some(rustix::process::Uid::from_raw(WORKLOAD_ID)),
                Some(rustix::process::Gid::from_raw(WORKLOAD_ID)),
            ) {
                eprintln!("terra: warning: could not chown {}: {e}", d.guest);
            }
        }
    }
    fs::write("/terra/README.md", &plan.sandbox_info).context("writing sandbox description")?;
    setup_user(plan.root);
    setup_sudo(plan.root, &plan.sudo)?;
    for line in &plan.on_start {
        run_hook(line, Some(HOOK_TIMEOUT))?;
    }

    let workdir = plan
        .workdir
        .clone()
        .unwrap_or_else(|| terra_shared::contract::WORKLOAD_HOME.to_owned());
    crate::files::ensure_directory(Path::new(&workdir), !plan.root)
        .with_context(|| format!("creating workdir {workdir}"))?;
    std::env::set_current_dir(&workdir).with_context(|| format!("entering workdir {workdir}"))?;

    let daemons = crate::daemon::spawn_all(&plan.daemons, plan.root);
    let stop_grace = Duration::from_secs(DEFAULT_STOP_GRACE_SECS);

    let outcome = run_workload(plan, control, port, stop_grace);
    let (code, session) = match outcome {
        Ok(pair) => pair,
        Err(e) => {
            daemons.stop(stop_grace);
            return Err(e.context("running the workload"));
        }
    };

    // Daemons stay up through pre_stop hooks in case hooks interact with them.
    for line in &plan.pre_stop {
        let _ = run_hook(line, Some(HOOK_TIMEOUT));
    }
    daemons.stop(stop_grace);
    session.broadcast_exit(code);
    Ok(code)
}

fn is_baked(recipe: &str) -> Result<bool> {
    match fs::read_to_string(RECIPE_STAMP_PATH) {
        Ok(stamped) if stamped == recipe => Ok(true),
        Ok(stamped) if !stamped.is_empty() => {
            eprintln!(
                "terra: warning: on_create changed since this box was created, and \
                 the old one is already baked in; keeping it (`terra rm` rebuilds)"
            );
            Ok(true)
        }
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e).context(format!("reading {RECIPE_STAMP_PATH}")),
    }
}

fn bake_if_stale(on_create: &[String]) -> Result<()> {
    let recipe = on_create.join("\n");
    if is_baked(&recipe)? {
        return Ok(());
    }
    if !on_create.is_empty() {
        println!("terra: baking on_create…");
    }
    for line in on_create {
        run_hook(line, Some(HOOK_TIMEOUT))?;
    }
    fs::write(RECIPE_STAMP_PATH, &recipe).with_context(|| format!("stamping {RECIPE_STAMP_PATH}"))
}

fn make_mount_error(path: &str, e: &std::io::Error) -> anyhow::Error {
    let why = if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
        "it, or a directory above it, is a symlink"
    } else {
        "it cannot be opened as a directory"
    };
    anyhow::anyhow!(
        "refusing to mount at {path}: {why} ({e}) - either the guest filesystem \
         ships one there (mount somewhere else) or something inside this box put \
         it there (`terra rm` rebuilds the filesystem)"
    )
}

fn prepare_mount_point(path: &str) -> Result<()> {
    let mount_point = Path::new(path);
    let open_directory =
        || no_symlinks::open_no_symlinks(mount_point, no_symlinks::OpenMode::ReadDirectory);
    match open_directory() {
        Ok(_) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => bail!(make_mount_error(path, &e)),
    }
    crate::files::ensure_directory(mount_point, false)
        .with_context(|| format!("creating mount point {path}"))?;
    open_directory()
        .map(|_| ())
        .map_err(|e| make_mount_error(path, &e))
}

/// Restricts ptrace to process descendants (Yama scope 1).
/// Without this, same-uid processes could inspect each other's memory.
fn restrict_ptrace() {
    const PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";
    if let Err(e) = fs::write(PATH, "1\n") {
        eprintln!("terra: warning: could not restrict ptrace ({PATH}): {e}");
    }
}

fn mount_share(s: &Share, owner_userns: Option<&std::os::fd::OwnedFd>) -> Result<()> {
    prepare_mount_point(&s.guest)?;
    let flags = if s.readonly {
        MountFlags::RDONLY
    } else {
        MountFlags::empty()
    };
    mount(
        Some(&s.tag),
        &s.guest,
        Some("virtiofs"),
        flags | MountFlags::NOSUID | MountFlags::NODEV,
    )?;
    if let Some(userns) = owner_userns {
        crate::idmap::remount_idmapped(&s.guest, userns)
            .with_context(|| format!("idmapping the share at {}", s.guest))?;
    }
    Ok(())
}

const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

#[allow(unsafe_code)]
fn setup_env(plan: &Plan) {
    let home = terra_shared::contract::WORKLOAD_HOME;
    // SAFETY: no other thread touches the environment yet.
    unsafe {
        for (k, v) in &plan.env {
            if k.is_empty() || k.contains(['=', '\0']) || v.contains('\0') {
                eprintln!("terra: warning: skipping invalid env key `{k}`");
                continue;
            }
            std::env::set_var(k, v);
        }
        std::env::set_var("PATH", DEFAULT_PATH);
        std::env::set_var("HOME", home);
        std::env::set_var("TERM", "xterm-256color");
    }
    let name = b"terrarium";
    let _ = rustix::system::sethostname(name);
}

fn setup_net(net: &Net) -> Result<()> {
    run_ip(&["link", "set", "lo", "up"])?;
    run_ip(&[
        "addr",
        "add",
        &format!("{}/{}", net.guest_ip, net.prefix),
        "dev",
        "eth0",
    ])?;
    run_ip(&["link", "set", "eth0", "up"])?;
    run_ip(&["route", "add", "default", "via", &net.gateway.to_string()])?;
    fs::write("/etc/resolv.conf", format!("nameserver {}\n", net.dns))
        .context("writing /etc/resolv.conf")
}

fn run_ip(args: &[&str]) -> Result<()> {
    let status = Command::new("ip")
        .args(args)
        .status()
        .context("running ip")?;
    if !status.success() {
        bail!("ip {args:?} failed ({status})");
    }
    Ok(())
}

const DOAS_CONF: &str = "/etc/doas.conf";

/// Drop-in directory for doas rules; persistent files here must be cleaned up on boot.
const DOAS_DIR: &str = "/etc/doas.d";

fn setup_sudo(as_root: bool, commands: &[String]) -> Result<()> {
    use std::fmt::Write as _;
    if as_root {
        return Ok(());
    }
    match fs::remove_dir_all(DOAS_DIR) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context(format!("removing {DOAS_DIR}")),
    }
    fs::create_dir_all(DOAS_DIR).with_context(|| format!("creating {DOAS_DIR}"))?;
    let mut policy =
        String::from("# Generated by terra from the profile's `sudo:` - edits are overwritten.\n");
    for cmd in commands {
        if cmd.contains(['\n', '#']) {
            eprintln!("terra: warning: skipping invalid sudo `{cmd}`");
            continue;
        }
        let _ = writeln!(policy, "permit nopass {WORKLOAD_ID} cmd {cmd}");
    }
    fs::write(DOAS_CONF, policy).with_context(|| format!("writing {DOAS_CONF}"))?;
    // doas refuses a policy file writable by others.
    fs::set_permissions(DOAS_CONF, std::fs::Permissions::from_mode(0o640))
        .with_context(|| format!("securing {DOAS_CONF}"))?;
    Ok(())
}

fn setup_user(as_root: bool) {
    if as_root {
        return;
    }
    let entry = format!("{WORKLOAD_USER_NAME}:");
    if fs::read_to_string("/etc/passwd").is_ok_and(|p| p.lines().any(|l| l.starts_with(&entry))) {
        return;
    }
    let workload_id = WORKLOAD_ID.to_string();
    run_quiet_command("addgroup", &["-g", &workload_id, WORKLOAD_USER_NAME]);
    run_quiet_command(
        "adduser",
        &[
            "-D",
            "-u",
            &workload_id,
            "-G",
            WORKLOAD_USER_NAME,
            WORKLOAD_USER_NAME,
        ],
    );
}

fn run_quiet_command(cmd: &str, args: &[&str]) {
    let mut command = Command::new(cmd);
    command
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let status = match crate::reap::spawn_owned(|| command.spawn()) {
        Ok((mut child, child_pidfd)) => wait_with_timeout(&mut child, &child_pidfd, HOOK_TIMEOUT),
        Err(error) => Err(error),
    };
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!(
            "terra: warning: `{cmd}` exited {s} - the {WORKLOAD_USER_NAME} user may be missing"
        ),
        Err(e) => eprintln!("terra: warning: could not run `{cmd}`: {e}"),
    }
}

// ---- the workload, the daemons, and the graceful stop ----------------------

/// How long the workload's last output is given to cross the PTY after the
/// process itself has gone - see the drain at the end of [`run_workload`].
/// Bounded because EOF may never come: a backgrounded grandchild can hold the
/// slave open for as long as it likes, and the box still has to stop.
const OUTPUT_DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Run the plan's processes - the daemons and the workload on its PTY - and
/// hand back the workload's status and its session once it exits. The stop
/// watcher rides a clone of the control connection, so a graceful stop reaches
/// the workload; the original stays owed the exit status at the end of the
/// boot.
fn run_workload(
    plan: &Plan,
    control: &File,
    port: VsockListener,
    stop_grace: Duration,
) -> Result<(i32, Arc<Session>)> {
    let Some((cmd, args)) = plan.workload.split_first() else {
        bail!("empty workload argv");
    };
    let (pty, mut child, child_pidfd) =
        spawn_on_pty(cmd, args, DEFAULT_ROWS, DEFAULT_COLS, plan.root, None)?;

    let master: OwnedFd = pty.into();
    let reader = master.try_clone()?;
    let input_file = std::fs::File::from(master);
    let master_fd = input_file.as_raw_fd();
    let input: Sink = Arc::new(Mutex::new(input_file));
    let session = Session::new(input);
    // Console attaches before the pump to capture output overflow from fast one-shots.
    if plan.workload_on_console {
        attach_console(&session, master_fd);
    }

    let (drained_tx, drained) = std::sync::mpsc::channel::<()>();
    let out_session = session.clone();
    std::thread::spawn(move || {
        let _drained_tx = drained_tx;
        crate::exec::pump_copy(std::fs::File::from(reader), |chunk| {
            out_session.feed_output(chunk);
            true
        });
    });

    crate::vsock::serve_agent_port(&session, port, master_fd, plan.root);

    let exited = Arc::new(AtomicBool::new(false));
    watch_graceful_stop(
        control
            .try_clone()
            .context("cloning the control connection")?,
        child_pidfd,
        exited.clone(),
        stop_grace,
    );

    let code = crate::exec::wait_for_exit_code(&mut child);
    exited.store(true, Ordering::SeqCst);
    let _ = drained.recv_timeout(OUTPUT_DRAIN_GRACE);
    Ok((code, session))
}

#[allow(unsafe_code)]
fn attach_console(session: &Arc<Session>, master_fd: RawFd) {
    let stdin = std::io::stdin();
    set_raw(std::os::fd::AsFd::as_fd(&stdin));
    let conn = ClientConn::from_console(std::io::stdout());
    let id = session.attach_client(&conn);
    if let Some((rows, cols)) = get_winsize(std::os::fd::AsFd::as_fd(&stdin))
        && let Some((r, c)) = session.set_client_size(id, rows, cols)
    {
        set_winsize(
            // SAFETY: `master_fd` is the live PTY master owned by the session's input sink,
            // which outlives this borrow.
            unsafe { std::os::fd::BorrowedFd::borrow_raw(master_fd) },
            r,
            c,
        );
    }

    let session = session.clone();
    std::thread::spawn(move || {
        crate::exec::pump_copy(std::io::stdin(), |chunk| session.send_input(chunk).is_ok());
    });
}

/// Spawns `cmd` on a PTY, dropping the slave end on return so the master EOFs on process exit.
#[allow(unsafe_code)]
pub(crate) fn spawn_on_pty(
    cmd: &str,
    args: &[String],
    rows: u16,
    cols: u16,
    as_root: bool,
    home_env: Option<&str>,
) -> Result<(Pty, std::process::Child, OwnedFd)> {
    let (pty, pts) = pty_process::blocking::open()?;
    pty.resize(pty_process::Size::new(
        rows.clamp(MIN_ROWS, MAX_ROWS),
        cols.clamp(MIN_COLS, MAX_COLS),
    ))?;
    let mut command = PtyCommand::new(cmd).args(args);
    if let Some(home_env) = home_env {
        command = command.env("HOME", home_env);
    }
    if !as_root {
        // SAFETY: a post-fork/pre-exec hook that only calls async-signal-safe
        // id-setting syscalls.
        command = unsafe { command.pre_exec(drop_privileges) };
    }
    let (child, child_pidfd) = crate::reap::spawn_owned(|| command.spawn(pts))?;
    Ok((pty, child, child_pidfd))
}

/// Drops to the workload user post-fork. Setting gid before uid preserves privilege to set uid.
pub fn drop_privileges() -> std::io::Result<()> {
    rustix::thread::set_thread_groups(&[]).map_err(std::io::Error::from)?;
    rustix::thread::set_thread_gid(rustix::process::Gid::from_raw(WORKLOAD_ID))
        .map_err(std::io::Error::from)?;
    rustix::thread::set_thread_uid(rustix::process::Uid::from_raw(WORKLOAD_ID))
        .map_err(std::io::Error::from)?;
    Ok(())
}

const STOP_POLL: Duration = Duration::from_millis(50);

fn watch_graceful_stop(
    control: File,
    workload: OwnedFd,
    exited: Arc<AtomicBool>,
    stop_grace: Duration,
) {
    std::thread::spawn(move || stop_gracefully(control, workload, exited, stop_grace));
}

/// Stops the workload on stop byte or host disconnect, escalating to SIGKILL after grace.
/// Signaling through a pidfd avoids PID recycling races with subsequent processes.
fn stop_gracefully(
    mut control: File,
    workload: OwnedFd,
    exited: Arc<AtomicBool>,
    stop_grace: Duration,
) {
    let mut byte = [0u8; 1];
    loop {
        match control.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == STOP_SIGNAL => break,
            Ok(_) => {}
            // EINTR is retried; treating errors as stops would prematurely terminate the workload.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                eprintln!("terra-agent: the control connection failed ({e}) - stopping");
                break;
            }
        }
    }
    let _ = rustix::process::pidfd_send_signal(&workload, rustix::process::Signal::TERM);
    let deadline = std::time::Instant::now() + stop_grace;
    while std::time::Instant::now() < deadline && !exited.load(Ordering::SeqCst) {
        std::thread::sleep(STOP_POLL);
    }
    if !exited.load(Ordering::SeqCst) {
        eprintln!(
            "terra-agent: workload ignored SIGTERM after {}s - killing it",
            stop_grace.as_secs()
        );
        let _ = rustix::process::pidfd_send_signal(&workload, rustix::process::Signal::KILL);
    }
    drop(workload);
    drop(exited);
}

const HOOK_TIMEOUT: Duration = Duration::from_mins(5);

fn wait_with_timeout(
    child: &mut std::process::Child,
    child_pidfd: &OwnedFd,
    timeout: Duration,
) -> std::io::Result<std::process::ExitStatus> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => break,
            Ok(None) => {}
        }
        if std::time::Instant::now() >= deadline {
            let _ = rustix::process::pidfd_send_signal(child_pidfd, rustix::process::Signal::KILL);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    crate::reap::wait_owned(child)
}

fn run_hook(sh_cmd_line: &str, timeout: Option<Duration>) -> Result<()> {
    let (mut child, child_pidfd) =
        crate::reap::spawn_owned(|| Command::new("sh").arg("-c").arg(sh_cmd_line).spawn())
            .with_context(|| format!("spawning hook `{sh_cmd_line}`"))?;
    let status = match timeout {
        Some(timeout) => wait_with_timeout(&mut child, &child_pidfd, timeout)?,
        None => crate::reap::wait_owned(&mut child)?,
    };
    if !status.success() {
        bail!("hook `{sh_cmd_line}` failed ({status})");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_scratch_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("terra-agent-init-{}-{name}", std::process::id()))
    }

    /// A mount point's parents can belong to the workload from a previous boot -
    /// the rootfs persists - and `create_dir_all` follows a symlink to a
    /// directory and reports success. Mounting through one puts a read-write host
    /// share, or a volume this then chowns to the workload user, wherever the
    /// workload pointed it: `/usr/local/bin`, say, which `$PATH` reaches first.
    ///
    /// Both spellings have to be refused. The leaf was; a symlinked *parent* was
    /// not, because an `lstat` of the whole path resolves everything above the
    /// last component on its way - so the link answered for the directory behind
    /// it and the mount landed on the far side.
    #[test]
    fn a_symlinked_mount_point_is_refused() {
        let real = create_scratch_path("mp-real");
        let link = create_scratch_path("mp-link");
        let _ = fs::remove_dir_all(&real);
        let _ = fs::remove_file(&link);
        fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let err = prepare_mount_point(&link.to_string_lossy())
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");

        let under = link.join("src");
        let err = prepare_mount_point(&under.to_string_lossy())
            .unwrap_err()
            .to_string();
        assert!(err.contains("symlink"), "{err}");
        assert!(
            !real.join("src").exists(),
            "the mount point was created through the link"
        );

        assert!(prepare_mount_point(&real.to_string_lossy()).is_ok());
        let fresh = create_scratch_path("mp-fresh");
        let _ = fs::remove_dir_all(&fresh);
        assert!(prepare_mount_point(&fresh.join("a/b").to_string_lossy()).is_ok());
        assert!(fresh.join("a/b").is_dir());

        let _ = fs::remove_file(&link);
        let _ = fs::remove_dir_all(&real);
        let _ = fs::remove_dir_all(&fresh);
    }

    /// `pre_stop` runs on the way to `exit`, and PID 1 returning is what ends the
    /// VM - so an unbounded hook is a VM that never stops. The binary a hook
    /// invokes lives in the box's own guest-writable rootfs, so a box can arrange
    /// this for itself.
    #[test]
    fn a_wedged_pre_stop_hook_is_killed() {
        let start = std::time::Instant::now();
        let _ = run_hook("sleep 600", Some(Duration::from_millis(300)));
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "sh_ok waited {:?} on a hook that never returns",
            start.elapsed()
        );
        let start = std::time::Instant::now();
        let _ = run_hook("true", Some(HOOK_TIMEOUT));
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    /// A workload willing to die, a 30s grace, and a stop byte: the stop must
    /// return as soon as it is gone, not wait the grace out - the box's
    /// shutdown is the workload's exit, not a timer.
    #[test]
    fn a_stop_ends_early_when_the_workload_takes_the_signal() {
        use std::io::Write;
        use std::os::unix::net::UnixStream;
        let (mut host, guest) = UnixStream::pair().unwrap();
        let guest = File::from(std::os::fd::OwnedFd::from(guest));
        let (mut child, pidfd) = crate::reap::spawn_owned(|| {
            Command::new("/bin/sh")
                .arg("-c")
                .arg("trap 'exit 0' TERM; while true; do sleep 1; done")
                .spawn()
        })
        .unwrap();
        let exited = Arc::new(AtomicBool::new(false));
        let reaped = exited.clone();
        let wait_workload = std::thread::spawn(move || {
            crate::reap::wait_owned(&mut child).unwrap();
            reaped.store(true, Ordering::SeqCst);
        });

        let watcher = std::thread::spawn({
            let exited = exited.clone();
            move || {
                stop_gracefully(guest, pidfd, exited, Duration::from_secs(30));
            }
        });
        host.write_all(&[STOP_SIGNAL]).unwrap();

        let start = std::time::Instant::now();
        let deadline = start + Duration::from_secs(10);
        while !watcher.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(watcher.is_finished(), "the stop waited the grace out");
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "the stop took {:?}",
            start.elapsed()
        );
        watcher.join().unwrap();
        wait_workload.join().unwrap();
        assert!(exited.load(Ordering::SeqCst));
    }
}
