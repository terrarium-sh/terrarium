//! Who holds a box: the run lock, the process that holds it, and how to ask it to stop.
use super::{BoxRef, CONTROL_SOCKET};
use anyhow::{Context, Result, anyhow, bail};
use std::fs::{File, TryLockError};
use std::time::{Duration, Instant};
use terra_protocol::PlanMode;

pub(crate) const PID_FILE: &str = "terra.pid";

pub(crate) const HOST_PID_FILE: &str = "host.pid";

pub(crate) const SUPERVISOR_PID_FILE: &str = "supervisor.pid";

const SETUP_MARK: &str = "setup";

/// POSIX record locks would let an unrelated close of the pid file unlock a running box.
const LOCK_CONTENTION_GRACE: Duration = Duration::from_millis(500);

pub struct SetupMark<'a>(&'a File);

impl SetupMark<'_> {
    pub(crate) fn clear(self) -> std::io::Result<()> {
        BoxRef::rewrite_lock_line(self.0, "")
    }
}

impl Drop for SetupMark<'_> {
    fn drop(&mut self) {
        if let Err(error) = self.0.set_len(0) {
            log::warn!("could not clear setup mark: {error}");
        }
    }
}

/// A published host process and its start identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// The process start identity when the pid was published, by which
    /// [`crate::sys::terminate_process`] tells this process from a stranger later
    /// recycled onto the pid. `None` - an old line, or the host had no
    /// identity - cannot be signalled.
    pub process_identity: Option<u64>,
}

/// Who holds a box's run lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Holder {
    Free,
    SettingUp,
    Running,
}

impl Holder {
    pub fn holds(self) -> bool {
        self != Holder::Free
    }
}

impl BoxRef {
    /// Take the box lock and undo what a run that died part-way left behind.
    pub(crate) fn lock_and_repair(&self) -> Result<File> {
        // Locked before anything on disk moves - a setup racing a finished `rm`
        // would otherwise resurrect the state directory after rm reported it gone.
        let lock = self.lock_run()?;
        self.recover_import()?;
        // Under the lock anything staged here predates this run - a setup or boot
        // that died part-way through an install.
        crate::vm::image::sweep_staging_temps(self.get_dir(), |_| false);
        Ok(lock)
    }

    /// [`Self::lock_and_repair`] a box that has a state directory; `Ok(None)`
    /// for one that does not, which nothing can hold, and which locking would
    /// create.
    pub(crate) fn lock_if_present(&self) -> Result<Option<File>> {
        if !self.get_dir().is_dir() {
            return Ok(None);
        }
        self.lock_and_repair().map(Some)
    }

    /// Take the box lock for a boot, refusing a box whose setup did not finish.
    pub fn lock_finished(&self) -> Result<File> {
        let lock = self.lock_and_repair()?;
        self.ensure_project_dir_exists()?;
        anyhow::ensure!(
            self.is_set_up(),
            "{self} is not set up for its recipe - `terra {} setup` finishes it",
            self.get_name()
        );
        Ok(lock)
    }

    /// Empty for a box nobody has taken.
    fn read_lock_line(&self) -> String {
        std::fs::read_to_string(self.dir.join(PID_FILE)).unwrap_or_default()
    }

    pub fn read_vm_process(&self) -> Option<ProcessIdentity> {
        let line = match std::fs::read_to_string(self.dir.join(HOST_PID_FILE)) {
            Ok(line) => line,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => self.read_lock_line(),
            Err(_) => return None,
        };
        let mut words = line.split_whitespace();
        let pid = words.next()?.parse().ok().filter(|pid| *pid > 0)?;
        let process_identity = Some(words.next()?.parse().ok()?);
        if words.next().is_some_and(|word| word != SETUP_MARK) || words.next().is_some() {
            return None;
        }
        Some(ProcessIdentity {
            pid,
            process_identity,
        })
    }

    pub(crate) fn clear_host_pid(&self) -> std::io::Result<()> {
        match std::fs::remove_file(self.dir.join(SUPERVISOR_PID_FILE)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        match std::fs::remove_file(self.dir.join(HOST_PID_FILE)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn read_supervisor_process(&self) -> Option<ProcessIdentity> {
        let line = std::fs::read_to_string(self.dir.join(SUPERVISOR_PID_FILE)).ok()?;
        let mut words = line.split_whitespace();
        let pid = words.next()?.parse().ok().filter(|pid| *pid > 0)?;
        let process_identity = Some(words.next()?.parse().ok()?);
        if words.next().is_some() {
            return None;
        }
        Some(ProcessIdentity {
            pid,
            process_identity,
        })
    }

    pub fn request_stop(&self) -> Result<()> {
        use std::io::Write as _;

        let mut control =
            terra_platform::local_socket::LocalStream::connect(self.dir.join(CONTROL_SOCKET))
                .with_context(|| format!("connecting to {self}'s stop service"))?;
        control
            .write_all(&[terra_protocol::STOP_SIGNAL])
            .with_context(|| format!("asking {self} to stop"))
    }

    fn is_marked_setting_up(&self) -> bool {
        self.read_lock_line()
            .split_whitespace()
            .any(|w| w == SETUP_MARK)
    }

    /// Rewrites the lock metadata without replacing the inode.
    pub(crate) fn rewrite_lock_line(mut file: &File, line: &str) -> std::io::Result<()> {
        use std::io::{Seek as _, Write as _};
        file.seek(std::io::SeekFrom::Start(0))?;
        file.set_len(0)?;
        file.write_all(line.as_bytes())?;
        file.sync_all()
    }

    pub fn publish_pid(lock: &File, pid: u32, mode: PlanMode) -> std::io::Result<()> {
        let process_identity = crate::sys::read_process_start_time(pid).ok_or_else(|| {
            std::io::Error::other(format!("reading start identity for pid {pid}"))
        })?;
        let mut line = format!("{pid} {process_identity}");
        if mode == PlanMode::Create {
            line.push(' ');
            line.push_str(SETUP_MARK);
        }
        Self::rewrite_lock_line(lock, &line)
    }

    pub fn get_holder(&self) -> Result<Holder> {
        let path = self.dir.join(PID_FILE);
        if !crate::sys::holds_run_lock(&path)
            .with_context(|| format!("probing run lock {}", path.display()))?
        {
            return Ok(Holder::Free);
        }
        if self.is_marked_setting_up() {
            return Ok(Holder::SettingUp);
        }
        Ok(Holder::Running)
    }

    pub fn mark_setting_up(lock: &File) -> std::io::Result<SetupMark<'_>> {
        Self::rewrite_lock_line(lock, SETUP_MARK)?;
        Ok(SetupMark(lock))
    }

    pub fn setup_holds_it(&self) -> anyhow::Error {
        anyhow!(
            "{self} is being set up - its setup VM holds the box and serves \
             no agent port (`{logs}` follows the setup; run this again once it is \
             done)",
            logs = self.build_logs_command()
        )
    }

    /// Take the box's exclusive lock, held for as long as the returned `File`
    /// lives. The OS drops it when the process dies, so it never goes stale.
    #[must_use = "the box is locked only while this File lives"]
    pub fn lock_run(&self) -> Result<File> {
        let path = self.dir.join(PID_FILE);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let deadline = Instant::now() + LOCK_CONTENTION_GRACE;
        let locked = loop {
            match crate::sys::try_lock_run(&path) {
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(crate::sys::POLL);
                }
                settled => break settled,
            }
        };
        match locked {
            Ok(file) => {
                file.set_len(0)
                    .with_context(|| format!("truncating lock {}", path.display()))?;
                // A holder that died without cleanup left its pids; `ls` would report them while
                // this non-VM holder (export, import, storage) owns the box.
                self.clear_host_pid()
                    .with_context(|| format!("clearing stale pids in {}", self.dir.display()))?;
                Ok(file)
            }
            Err(TryLockError::WouldBlock) => {
                if self.is_marked_setting_up() {
                    return Err(self.setup_holds_it());
                }
                bail!(
                    "{self} is locked by another terra command{} - it may be running, \
                     or a setup, export or import may hold it for minutes",
                    self.read_vm_process()
                        .map_or_else(String::new, |vm| format!(" (pid {})", vm.pid)),
                )
            }
            Err(TryLockError::Error(e)) => {
                Err(e).with_context(|| format!("locking {}", path.display()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::PID_FILE;
    use crate::state::{self, resolve_box_ref, wait_until_free};
    use crate::sys::TestHome;
    use std::fs::OpenOptions;

    #[test]
    fn graceful_stop_reaches_the_box_control_socket() {
        use std::io::Read as _;

        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().join("dev"), dir.path());
        std::fs::create_dir_all(&bx.dir).unwrap();
        let listener =
            terra_platform::local_socket::LocalListener::bind(bx.dir.join(CONTROL_SOCKET)).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0];
            stream.read_exact(&mut request).unwrap();
            request
        });

        bx.request_stop().unwrap();
        assert_eq!(server.join().unwrap(), [terra_protocol::STOP_SIGNAL]);
    }

    /// A VM killed without cleanup leaves host.pid and supervisor.pid behind. Taking the lock
    /// proves no process owns the box, so the files go, or `ls --json` would report the dead
    /// VM's pid while an export or import holds the box.
    #[test]
    fn taking_the_run_lock_clears_a_dead_holders_pids() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        std::fs::create_dir_all(b.get_dir()).unwrap();
        for file in [HOST_PID_FILE, SUPERVISOR_PID_FILE] {
            std::fs::write(b.get_dir().join(file), "4242 1\n").unwrap();
        }
        assert!(b.read_vm_process().is_some() && b.read_supervisor_process().is_some());
        let _lock = b.lock_run().unwrap();
        assert_eq!(b.read_vm_process(), None);
        assert_eq!(b.read_supervisor_process(), None);
    }

    /// A boot racing a momentary hold on the lock must not be told the box is
    /// in use: `lock_run` keeps looking until [`LOCK_CONTENTION_GRACE`] runs
    /// out, and a holder that lets go inside that is no holder. A single retry
    /// covered one of these; the probes come in numbers.
    ///
    /// Both kinds of momentary holder are here, because `lock_run` takes the
    /// lock *exclusive* and both block it: another terra partway through
    /// `lock_run` of its own, and the shared probe [`holds_lock`] takes - which
    /// is the common one, since every `terra ls` and every poll of `terra stop`
    /// takes it.
    #[test]
    fn lock_run_outlasts_a_momentary_holder() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        std::fs::create_dir_all(b.get_dir()).unwrap();
        let hold_briefly = |lock: fn(&File) -> std::result::Result<(), TryLockError>| {
            let probe = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(b.get_dir().join(PID_FILE))
                .unwrap();
            lock(&probe).unwrap();
            let released = std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(30));
                drop(probe);
            });
            let took = b.lock_run();
            released.join().unwrap();
            assert!(took.is_ok(), "a momentary holder was taken for a live box");
        };
        hold_briefly(File::try_lock);
        hold_briefly(File::try_lock_shared);
    }

    /// A contended lock names the command holding it instead of advising
    /// `terra stop`: a setup or a storage export legitimately keeps the box for
    /// minutes, and stopping it is not what the contender wants to be told.
    /// A box mid-setup answers with the setup refusal, which says what the
    /// holder actually is.
    #[test]
    fn contention_names_the_command_holding_the_box() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        std::fs::create_dir_all(b.get_dir()).unwrap();

        let lock = b.lock_run().unwrap();
        BoxRef::publish_pid(&lock, std::process::id(), PlanMode::Run).unwrap();
        let err = b.lock_run().expect_err("the box is held").to_string();
        assert!(
            err.contains(&format!(
                "locked by another terra command (pid {})",
                std::process::id()
            )),
            "{err}"
        );
        assert!(!err.contains("terra stop"), "no stop advice: {err}");

        let marked = BoxRef::mark_setting_up(&lock).unwrap();
        let err = format!("{:#}", b.lock_run().expect_err("the box is held"));
        assert!(err.contains("being set up"), "{err}");
        drop(marked);
    }

    /// Asking who holds a box must not itself look like holding it: the probe
    /// takes a *shared* lock, so a second probe in flight - `terra ls` beside
    /// the poll loop in `terra stop`, which is a pairing that happens
    /// constantly - still reads the truth. With an exclusive probe each saw the
    /// other and called a stopped box running.
    #[test]
    fn a_probe_in_flight_does_not_make_a_stopped_box_look_running() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        std::fs::create_dir_all(b.get_dir()).unwrap();
        std::fs::write(b.get_dir().join(PID_FILE), "").unwrap();

        let in_flight = OpenOptions::new()
            .read(true)
            .open(b.get_dir().join(PID_FILE))
            .unwrap();
        in_flight.try_lock_shared().unwrap();
        assert_eq!(
            b.get_holder().unwrap(),
            Holder::Free,
            "another probe was mistaken for a live holder"
        );
        drop(in_flight);

        // …and a box that really is held still reads as running, which is the
        // half a probe that always answered "no" would also satisfy.
        let held = b.lock_run().unwrap();
        assert_eq!(b.get_holder().unwrap(), Holder::Running);
        drop(held);
        wait_until_free(&b);
        assert_eq!(b.get_holder().unwrap(), Holder::Free);
    }

    /// The lock, the pid and the setup mark are one file: taking the lock empties
    /// whatever the last run left, so a dead pid can never be read as a live one
    /// and a mark a killed setup left behind can never make the next boot read as
    /// a setup. What is signalled must also *be* a pid (signalling `0` reaches
    /// the process group).
    ///
    /// [`BoxRef::holder`] is the whole of the answer, so it is read here rather
    /// than the mark: a mark nobody is holding the lock over is nobody's, which
    /// is what a setup killed between writing it and taking the lock leaves.
    #[test]
    fn the_lock_is_the_pid_file_and_taking_it_empties_what_the_last_run_left() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        std::fs::create_dir_all(b.get_dir()).unwrap();

        assert_eq!(b.read_vm_process(), None, "no pid file at all");
        for bad in ["", "  ", "0", "-1", "nonsense", SETUP_MARK] {
            std::fs::write(b.get_dir().join(PID_FILE), bad).unwrap();
            assert_eq!(b.read_vm_process(), None, "{bad:?} is not a pid");
            assert_eq!(
                b.get_holder().unwrap(),
                Holder::Free,
                "{bad:?} under no lock"
            );
        }

        let lock = b.lock_run().unwrap();
        assert_eq!(
            b.read_vm_process(),
            None,
            "the last run's pid outlived its lock"
        );
        assert_eq!(
            b.get_holder().unwrap(),
            Holder::Running,
            "a killed setup's mark outlived its lock"
        );

        BoxRef::publish_pid(&lock, std::process::id(), PlanMode::Run).unwrap();
        let published = b.read_vm_process().unwrap();
        assert_eq!(published.pid, std::process::id());
        assert_eq!(
            published.process_identity,
            crate::sys::read_process_start_time(std::process::id()),
            "the start identity is read from the host and round-trips"
        );
        BoxRef::publish_pid(&lock, std::process::id(), PlanMode::Create).unwrap();
        let marked = b.read_vm_process().unwrap();
        assert_eq!(
            marked.pid,
            std::process::id(),
            "a marked line still names its pid"
        );
        assert_eq!(
            marked.process_identity, published.process_identity,
            "the mark rides behind the start identity"
        );

        for line in ["4242", "4242 setup", "4242 7 other"] {
            BoxRef::rewrite_lock_line(&lock, line).unwrap();
            assert_eq!(
                b.read_vm_process(),
                None,
                "a lock line without a start identity, or with trailing words, names no process: {line}"
            );
        }

        // Still the same inode being locked, not a fresh file beside it.
        assert!(b.get_dir().join(PID_FILE).exists());
        assert!(b.lock_run().is_err(), "a second run got the same box");

        // A setup that has not spawned its child yet: marked, with no pid to
        // signal - which is what `terra stop` waits out rather than mistaking
        // for a stopped box. The guard puts the file back however it ended.
        let marked = BoxRef::mark_setting_up(&lock).unwrap();
        assert_eq!(
            b.get_holder().unwrap(),
            Holder::SettingUp,
            "the mark alone is a mark"
        );
        assert_eq!(
            b.read_vm_process(),
            None,
            "a setup marks the box before it has a pid"
        );
        BoxRef::publish_pid(&lock, std::process::id(), PlanMode::Create).unwrap();
        assert_eq!(b.get_holder().unwrap(), Holder::SettingUp);
        assert_eq!(
            b.read_vm_process().map(|vm| vm.pid),
            Some(std::process::id()),
            "and publishes both once it has one"
        );
        drop(marked);
        assert_eq!(b.get_holder().unwrap(), Holder::Running);
        assert_eq!(
            b.read_vm_process(),
            None,
            "the setup child's pid outlived the setup"
        );

        BoxRef::publish_pid(&lock, std::process::id(), PlanMode::Run).unwrap();
        assert_eq!(
            b.read_vm_process().map(|vm| vm.pid),
            Some(std::process::id())
        );

        drop(lock);
        wait_until_free(&b);
        assert_eq!(b.get_holder().unwrap(), Holder::Free);
    }

    #[test]
    fn publication_requires_a_live_identity_and_a_writable_lock() {
        let dir = tempfile::tempdir().unwrap();
        let b = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
        let lock = b.lock_run().unwrap();
        BoxRef::publish_pid(&lock, std::process::id(), PlanMode::Run).unwrap();
        let original = std::fs::read(b.get_dir().join(PID_FILE)).unwrap();
        assert!(BoxRef::publish_pid(&lock, u32::MAX, PlanMode::Run).is_err());
        assert_eq!(std::fs::read(b.get_dir().join(PID_FILE)).unwrap(), original);
        let readonly = File::open(b.get_dir().join(PID_FILE)).unwrap();
        assert!(BoxRef::publish_pid(&readonly, std::process::id(), PlanMode::Run).is_err());
        assert!(BoxRef::mark_setting_up(&readonly).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn taking_a_run_lock_rejects_symlink_redirection() {
        let directory = tempfile::tempdir().unwrap();
        let box_dir = directory.path().join("box");
        std::fs::create_dir(&box_dir).unwrap();
        let bx = BoxRef::from_state_dir(box_dir, directory.path());
        let redirected = directory.path().join("outside");
        std::fs::write(&redirected, b"original").unwrap();
        crate::sys::symlink_file(&redirected, bx.get_dir().join(PID_FILE)).unwrap();

        assert!(bx.lock_run().is_err());
        assert_eq!(std::fs::read(&redirected).unwrap(), b"original");
        std::fs::remove_file(&redirected).unwrap();
        assert!(bx.lock_run().is_err());
        assert!(!redirected.exists());
    }

    #[test]
    fn protected_host_pid_takes_precedence_and_invalid_records_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(dir.path().to_owned(), dir.path());
        let lock = bx.lock_run().unwrap();
        BoxRef::rewrite_lock_line(&lock, "42 7").unwrap();
        let host_pid = bx.get_dir().join(HOST_PID_FILE);

        std::fs::write(&host_pid, "123 456").unwrap();
        assert_eq!(
            bx.read_vm_process(),
            Some(ProcessIdentity {
                pid: 123,
                process_identity: Some(456),
            })
        );
        for invalid in ["", "123", "123 invalid", "123 456 stranger"] {
            std::fs::write(&host_pid, invalid).unwrap();
            assert_eq!(bx.read_vm_process(), None, "{invalid:?}");
        }
        std::fs::remove_file(&host_pid).unwrap();
        std::fs::create_dir(&host_pid).unwrap();
        assert_eq!(bx.read_vm_process(), None);
        assert!(bx.clear_host_pid().is_err());
        std::fs::remove_dir(&host_pid).unwrap();

        bx.clear_host_pid().unwrap();
        assert_eq!(
            bx.read_vm_process(),
            Some(ProcessIdentity {
                pid: 42,
                process_identity: Some(7),
            })
        );
    }

    #[test]
    fn supervisor_identity_is_separate_validated_and_cleared_before_boot() {
        let directory = tempfile::tempdir().unwrap();
        let bx = BoxRef::from_state_dir(directory.path().into(), directory.path());
        let lock = bx.lock_run().unwrap();
        BoxRef::rewrite_lock_line(&lock, "42 7").unwrap();
        let supervisor_pid = bx.get_dir().join(SUPERVISOR_PID_FILE);
        std::fs::write(&supervisor_pid, "123 456").unwrap();
        assert_eq!(
            bx.read_supervisor_process(),
            Some(ProcessIdentity {
                pid: 123,
                process_identity: Some(456),
            })
        );
        assert_eq!(bx.read_vm_process().map(|process| process.pid), Some(42));
        for invalid in ["", "123", "123 invalid", "0 456", "123 456 setup"] {
            std::fs::write(&supervisor_pid, invalid).unwrap();
            assert_eq!(bx.read_supervisor_process(), None, "{invalid:?}");
        }
        bx.clear_host_pid().unwrap();
        assert!(!supervisor_pid.exists());
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_lock_is_not_a_free_box() {
        let dir = tempfile::tempdir().unwrap();
        let invalid_parent = dir.path().join("file");
        std::fs::write(&invalid_parent, b"not a directory").unwrap();
        let b = BoxRef::from_state_dir(invalid_parent, dir.path());
        assert!(b.get_holder().is_err());
        assert!(b.get_state().is_err());
    }

    /// The pid file is rewritten in place, never renamed over: the run lock
    /// is held on its inode, and a replacement file would hand the next
    /// opener a fresh, unlocked inode while the box stayed locked on the old
    /// one.
    #[test]
    fn publishing_a_pid_preserves_the_held_lock() {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        std::fs::create_dir_all(b.get_dir()).unwrap();
        let held = b.lock_run().unwrap();

        BoxRef::publish_pid(&held, std::process::id(), PlanMode::Run).unwrap();
        #[cfg(unix)]
        let identity = |p: &std::path::Path| {
            let meta = std::fs::metadata(p).unwrap();
            (meta.dev(), meta.ino())
        };
        #[cfg(unix)]
        let before = identity(&b.get_dir().join(PID_FILE));

        // Longer, then shorter than what it replaced - no tail may survive.
        BoxRef::publish_pid(&held, std::process::id(), PlanMode::Create).unwrap();
        BoxRef::publish_pid(&held, std::process::id(), PlanMode::Run).unwrap();
        #[cfg(unix)]
        assert_eq!(
            identity(&b.get_dir().join(PID_FILE)),
            before,
            "the lock file was replaced"
        );
        assert_eq!(
            std::fs::read_to_string(b.get_dir().join(PID_FILE)).unwrap(),
            format!(
                "{} {}",
                std::process::id(),
                crate::sys::read_process_start_time(std::process::id()).unwrap()
            )
        );
        assert!(
            b.get_holder().unwrap().holds(),
            "the lock outlived the rewrites"
        );
        drop(held);
    }

    /// What [`BoxRef::setup_holds_it`] says, pinned at the definition that
    /// owns it: it is the one refusal for a box mid-`terra setup`, and
    /// `session` and `cmd::start` both hand it straight to their callers -
    /// which used to assert its wording themselves, so rewording it here broke
    /// two tests that are about neither the wording nor this message.
    #[test]
    fn the_refusal_for_a_box_being_set_up_names_the_setup_and_the_way_to_watch_it() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());

        let refusal = b.setup_holds_it().to_string();
        assert!(refusal.contains("being set up"), "{refusal}");
        assert!(refusal.contains(b.get_name()), "which box: {refusal}");
        assert!(
            refusal.contains(&b.build_logs_command()),
            "the way to watch it: {refusal}"
        );
    }

    /// A box boots only once setup finished for its pinned recipe. Missing,
    /// empty, and mismatched stamps all need a setup VM to succeed.
    #[test]
    fn a_box_whose_setup_did_not_finish_is_not_locked_for_a_boot() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let bx = BoxRef::resolve(dir.path(), "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "{}").unwrap();
        let rootfs = bx.get_dir().join(state::ROOTFS_FILE);
        let stamp = bx.get_dir().join(state::SETUP_STAMP);
        let refusal = || {
            bx.lock_finished()
                .expect_err("an unfinished setup must not boot")
                .to_string()
        };

        assert!(refusal().contains("terra dev setup"));
        std::fs::write(&stamp, b"").unwrap();
        assert!(
            refusal().contains("terra dev setup"),
            "stamp without a root image"
        );
        std::fs::remove_file(&stamp).unwrap();
        std::fs::write(&rootfs, b"").unwrap();
        assert!(
            refusal().contains("terra dev setup"),
            "root image without a stamp"
        );
        std::fs::write(&stamp, b"").unwrap();
        assert!(refusal().contains("terra dev setup"), "empty stamp");
        bx.write_setup_stamp().unwrap();
        bx.lock_finished().unwrap();
    }

    /// A set-up box whose project directory is gone is listed as `gone`, so
    /// booting it is refused the way a box for a typo'd directory is.
    #[test]
    fn a_set_up_box_whose_project_directory_is_gone_is_not_locked_for_a_boot() {
        let dir = tempfile::tempdir().unwrap();
        let _home = crate::sys::TestHome::new();
        let project = dir.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let bx = BoxRef::resolve(&project, "dev").unwrap();
        std::fs::create_dir_all(bx.get_dir()).unwrap();
        std::fs::write(bx.get_dir().join(state::ROOTFS_FILE), b"").unwrap();
        std::fs::write(bx.get_dir().join(state::RECIPE_FILE), "{}").unwrap();
        bx.write_setup_stamp().unwrap();
        std::fs::remove_dir(&project).unwrap();

        let refusal = bx
            .lock_finished()
            .expect_err("a box without its project directory must not boot")
            .to_string();

        assert!(
            refusal.contains(&project.display().to_string()),
            "{refusal}"
        );
    }

    /// Locking a box creates its state directory, so a box nobody set up is
    /// reported as unheld instead of being locked into existence.
    #[test]
    fn a_box_with_no_state_is_not_locked_into_existence() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        assert!(b.lock_if_present().unwrap().is_none());
        assert!(!b.get_dir().exists(), "asking created the box");

        std::fs::create_dir_all(b.get_dir()).unwrap();
        let held = b
            .lock_if_present()
            .unwrap()
            .expect("a box with state is locked");
        assert!(b.lock_run().is_err(), "the lock was not held");
        drop(held);
    }
}
