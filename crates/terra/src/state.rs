//! Terra's state on disk: `~/.terra`, the per-box paths under it, and the run
//! lock.

use anyhow::{Context, Result, anyhow, bail};
use sha2::{Digest as _, Sha256};
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const BOX_HOME: &str = "box";
const CACHE_HOME: &str = "cache";

const ROOTFS_FILE: &str = "rootfs.img";
pub(crate) const PID_FILE: &str = "terra.pid";

const VOLUME_PREFIX: &str = "vol-";
const VOLUME_SUFFIX: &str = ".img";

/// The one user-authored file in a box's state dir.
pub const RECIPE_FILE: &str = "recipe.yaml";

const BAKE_MARK: &str = "bake";

/// How long [`BoxRef::lock_run`] outwaits a momentary holder before calling the
/// box taken. Not a lockless test: asking whether a lock is held without taking
/// one needs POSIX record locks, which a process drops on *any* close of the
/// file - one stray read of the pid file would unlock a running box.
const LOCK_CONTENTION_GRACE: Duration = Duration::from_millis(500);

pub const ORIGIN_FILE: &str = ".path";

/// One resolved box: its project directory, name, and state directory
/// (`~/.terra/box/<slug>/<name>`).
#[derive(Clone, Debug)]
pub struct BoxRef {
    project_dir: PathBuf,
    name: String,
    dir: PathBuf,
}

impl BoxRef {
    pub fn resolve(project_dir: &Path, name: &str) -> Result<Self> {
        let dir = project_state_dir(project_dir)?.join(name);
        Ok(Self {
            project_dir: project_dir.to_path_buf(),
            name: name.to_owned(),
            dir,
        })
    }

    pub fn from_state_dir(dir: PathBuf, project_dir: &Path) -> Self {
        let name = dir
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
        Self {
            project_dir: project_dir.to_path_buf(),
            name,
            dir,
        }
    }

    pub fn project_dir(&self) -> &Path {
        &self.project_dir
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    #[must_use]
    pub fn control_sock(&self) -> PathBuf {
        self.dir.join("c")
    }

    #[must_use]
    pub fn agent_sock(&self) -> PathBuf {
        self.dir.join("a")
    }

    /// Refuse the box before anything is built - the alternative is
    /// `ENAMETOOLONG` buried in a half-done boot.
    pub fn ensure_sockets_fit(&self) -> Result<()> {
        let sock = self.control_sock();
        let len = sock.as_os_str().len();
        if len > crate::sys::MAX_SOCK_PATH {
            bail!(
                "this box's path is too long: its control socket would be {len} bytes and a \
                 unix socket path cannot exceed {max} ({sock})\n\
                 (a shorter box name helps, `--project` moves the box, or move the project)",
                max = crate::sys::MAX_SOCK_PATH,
                sock = sock.display(),
            );
        }
        Ok(())
    }

    #[must_use]
    pub fn rootfs_img(&self) -> PathBuf {
        self.dir.join(ROOTFS_FILE)
    }

    #[must_use]
    pub fn volume_img(&self, name: &str) -> PathBuf {
        self.dir
            .join(format!("{VOLUME_PREFIX}{name}{VOLUME_SUFFIX}"))
    }

    /// Every volume image the box has, whatever its recipe names.
    #[must_use]
    pub fn volume_images(&self) -> Vec<PathBuf> {
        crate::sys::dir_entries(&self.dir)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(VOLUME_PREFIX) && n.ends_with(VOLUME_SUFFIX))
            })
            .collect()
    }

    #[must_use]
    pub fn unused_volume_images(&self, configured: &[String]) -> Vec<PathBuf> {
        let keep: Vec<PathBuf> = configured.iter().map(|n| self.volume_img(n)).collect();
        self.volume_images()
            .into_iter()
            .filter(|path| !keep.contains(path))
            .collect()
    }

    /// The image `name` addresses in this box, or `None` for a name that is
    /// not one terra puts there.
    pub fn image_named(&self, name: &str) -> Option<PathBuf> {
        if name == ROOTFS_FILE {
            return Some(self.rootfs_img());
        }
        let volume = name
            .strip_prefix(VOLUME_PREFIX)?
            .strip_suffix(VOLUME_SUFFIX)?;
        let plain =
            !volume.is_empty() && !matches!(volume, "." | "..") && !volume.contains(['/', '\\']);
        plain.then(|| self.volume_img(volume))
    }

    pub fn recipe(&self) -> PathBuf {
        self.dir.join(RECIPE_FILE)
    }

    pub fn pid_file(&self) -> PathBuf {
        self.dir.join(PID_FILE)
    }

    /// Empty for a box nobody has taken.
    fn lock_line(&self) -> String {
        std::fs::read_to_string(self.pid_file()).unwrap_or_default()
    }

    /// The box's diagnostic log (see [`crate::logs`]).
    pub fn log(&self) -> PathBuf {
        self.dir.join("terra.log")
    }

    /// Every writer that does not go through the logger, fresh per run.
    pub fn diagnostics_log(&self) -> PathBuf {
        self.dir.join("diagnostics.log")
    }

    pub fn logs_command(&self) -> String {
        format!(
            "terra {} logs --project {}",
            self.name,
            crate::render::shell_word(&self.project_dir.to_string_lossy())
        )
    }

    pub fn vm_process(&self) -> Option<VmProcess> {
        let line = self.lock_line();
        let mut words = line.split_whitespace();
        let pid = words.next()?.parse().ok().filter(|pid| *pid > 0)?;
        let started_at = words.next().and_then(|w| w.parse().ok());
        Some(VmProcess { pid, started_at })
    }

    fn marked_baking(&self) -> bool {
        self.lock_line().split_whitespace().any(|w| w == BAKE_MARK)
    }

    /// One contiguous write, so the worst a concurrent reader sees is a torn
    /// tail (see the inode test for why this never renames over the file).
    fn rewrite_lock_line(&self, line: &str) -> std::io::Result<()> {
        use std::io::{Seek as _, Write as _};
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.pid_file())?;
        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(line.as_bytes())?;
        file.set_len(u64::try_from(line.len()).unwrap_or_default())
    }

    /// A failed write is worth a warning: `terra stop` finds this VM by the pid
    /// published here.
    pub fn publish_pid(&self, pid: u32, baking: bool) {
        use std::fmt::Write as _;
        let mut line = pid.to_string();
        if let Some(started_at) = crate::sys::process_start_time(pid) {
            let _ = write!(line, " {started_at}");
        }
        if baking {
            line.push(' ');
            line.push_str(BAKE_MARK);
        }
        if let Err(e) = self.rewrite_lock_line(&line) {
            log::warn!("terra: warning: could not publish pid {pid} for {self}: {e}");
        }
    }

    /// A host that cannot lock at all reads as [`Holder::Free`], and leaves the
    /// real complaint to `lock_run`.
    pub fn holder(&self) -> Holder {
        if !holds_lock(&self.pid_file()) {
            return Holder::Free;
        }
        if self.marked_baking() {
            return Holder::SettingUp;
        }
        Holder::Running
    }

    #[must_use = "the bake mark is cleared when this drops"]
    pub fn mark_baking<'a>(&self, lock: &'a File) -> BakeMark<'a> {
        if let Err(e) = self.rewrite_lock_line(BAKE_MARK) {
            log::warn!("terra: warning: could not mark {self} as baking: {e}");
        }
        BakeMark(lock)
    }

    pub fn setup_holds_it(&self) -> anyhow::Error {
        anyhow!(
            "{self} is being set up - its `on_create` bake holds the box and serves \
             no agent port (`{logs}` follows the bake; run this again once it is \
             done)",
            logs = self.logs_command()
        )
    }

    pub fn state(&self) -> BoxState {
        match self.holder() {
            Holder::Running => BoxState::Running,
            Holder::SettingUp => BoxState::SettingUp,
            // "Stopped" would invite booting a box whose project directory is gone.
            Holder::Free if !self.project_dir.is_dir() => BoxState::Gone,
            Holder::Free if self.rootfs_img().exists() => BoxState::Stopped,
            Holder::Free => BoxState::NotCreated,
        }
    }

    /// Take the box's exclusive lock, held for as long as the returned `File`
    /// lives. The OS drops it when the process dies, so it never goes stale.
    #[must_use = "the box is locked only while this File lives"]
    pub fn lock_run(&self) -> Result<File> {
        let path = self.pid_file();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("opening lock {}", path.display()))?;
        let deadline = Instant::now() + LOCK_CONTENTION_GRACE;
        let locked = loop {
            match file.try_lock() {
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(crate::sys::POLL);
                }
                settled => break settled,
            }
        };
        match locked {
            Ok(()) => {
                let _ = file.set_len(0);
                Ok(file)
            }
            Err(TryLockError::WouldBlock) => {
                if self.marked_baking() {
                    return Err(self.setup_holds_it());
                }
                bail!(
                    "{} is locked by another terra command{} - a bake, export or \
                     import holds the box for minutes",
                    self.dir.display(),
                    self.vm_process()
                        .map_or_else(String::new, |vm| format!(" (pid {})", vm.pid)),
                )
            }
            Err(TryLockError::Error(e)) => {
                Err(e).with_context(|| format!("locking {}", path.display()))
            }
        }
    }

    /// Best-effort, UTF-8 paths only: the worst failure is a box that boots
    /// but is missing from `terra ls`.
    pub fn write_origin(&self) {
        if let Some(project) = self.dir.parent()
            && let Some(text) = self.project_dir.to_str()
        {
            let _ = std::fs::write(project.join(ORIGIN_FILE), text);
        }
    }
}

/// The mark of one bake, taken away when this drops - the error paths included.
pub struct BakeMark<'a>(&'a File);

impl Drop for BakeMark<'_> {
    fn drop(&mut self) {
        let _ = self.0.set_len(0);
    }
}

/// The VM process a box's pid file names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmProcess {
    pub pid: u32,
    /// The process's `/proc` starttime when the pid was published, by which
    /// [`crate::sys::signal_pid`] tells this VM from a stranger later
    /// recycled onto the pid. `None` - an old line, or `/proc` had nothing -
    /// signals unverified.
    pub started_at: Option<u64>,
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

/// A box's name and its directory - either alone is ambiguous.
impl std::fmt::Display for BoxRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.project_dir.display())
    }
}

pub(crate) fn terra_home_path() -> Result<PathBuf> {
    Ok(crate::sys::home_dir()?.join(".terra"))
}

pub const SETTINGS_FILE: &str = "config.yaml";

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Settings {
    storage: StorageSettings,
}

#[derive(Debug, Default, Clone, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
struct StorageSettings {
    boxes: Option<PathBuf>,
    cache: Option<PathBuf>,
}

thread_local! {
    /// [`SETTINGS_FILE`] as this thread first read it - a cache per thread
    /// rather than per process, because the file lives under the home
    /// directory and every test runs on a home of its own
    /// ([`crate::sys::TestHome`]).
    static SETTINGS: std::cell::RefCell<Option<Settings>> =
        const { std::cell::RefCell::new(None) };
}

/// What [`SETTINGS_FILE`] overrides, or nothing where there is no such file.
fn settings() -> Result<Settings> {
    if let Some(settled) = SETTINGS.with_borrow(Clone::clone) {
        return Ok(settled);
    }
    let read = read_settings()?;
    SETTINGS.with_borrow_mut(|cached| *cached = Some(read.clone()));
    Ok(read)
}

/// Read [`SETTINGS_FILE`] again: for a test that writes one where a path has
/// already been resolved, and for [`crate::sys::TestHome`], which moves the
/// file the name means.
#[cfg(test)]
pub(crate) fn forget_settings() {
    SETTINGS.with_borrow_mut(|cached| *cached = None);
}

fn read_settings() -> Result<Settings> {
    let path = terra_home_path()?.join(SETTINGS_FILE);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Settings::default()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    yaml_serde::from_str(&text).with_context(|| format!("failed to parse {}", path.display()))
}

fn settings_dir(dir: &Path, field: &str) -> Result<PathBuf> {
    let path = crate::config::expand_tilde(dir)?;
    anyhow::ensure!(
        path.is_absolute(),
        "{field} in {SETTINGS_FILE} must be an absolute path or start with '~/': '{}'",
        dir.display()
    );
    Ok(path)
}

pub fn box_home_path() -> Result<PathBuf> {
    match settings()?.storage.boxes {
        Some(dir) => settings_dir(&dir, "storage.boxes"),
        None => Ok(terra_home_path()?.join(BOX_HOME)),
    }
}

/// Where the kernel and boot volume are unpacked.
pub fn cache_path() -> Result<PathBuf> {
    match settings()?.storage.cache {
        Some(dir) => settings_dir(&dir, "storage.cache"),
        None => Ok(terra_home_path()?.join(CACHE_HOME)),
    }
}

fn ensure_owner_only_dir(dir: PathBuf, holds: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    crate::sys::owner_only(&dir, true).with_context(|| {
        format!(
            "securing {} - it holds {holds}, so terra will not read one out of a \
             directory it cannot make owner-only",
            dir.display()
        )
    })?;
    Ok(dir)
}

pub fn ensure_terra_home() -> Result<PathBuf> {
    ensure_owner_only_dir(
        terra_home_path()?,
        "this machine's recipes (what a sandbox may mount and reach) and where the \
         boxes and the kernel are kept",
    )
}

pub fn ensure_box_home() -> Result<PathBuf> {
    ensure_terra_home()?;
    ensure_owner_only_dir(
        box_home_path()?,
        "every box's recipe, disk images and sockets",
    )
}

pub fn ensure_cache_dir() -> Result<PathBuf> {
    ensure_terra_home()?;
    ensure_owner_only_dir(
        cache_path()?,
        "the guest kernel and the PID-1 agent every box boots",
    )
}

/// `<box_dir>/<slug>` - every box of `project_dir`.
///
/// Built from [`box_home_path`] because [`crate::policy::mount`] protects only
/// what that function returns - a second spelling would escape the check.
pub fn project_state_dir(project_dir: &Path) -> Result<PathBuf> {
    Ok(box_home_path()?.join(slug(project_dir)))
}

/// The boxes under one `~/.terra/box/<slug>/`, as `(name, state directory)`.
/// Unordered, empty for a slug that is not there.
pub fn boxes_in(project_state_dir: &Path) -> impl Iterator<Item = (String, PathBuf)> {
    crate::sys::dir_entries(project_state_dir)
        .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
        .filter_map(|e| Some((e.file_name().into_string().ok()?, e.path())))
}

pub fn existing_names(project_dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = project_state_dir(project_dir)
        .iter()
        .flat_map(|p| boxes_in(p))
        .map(|(name, _)| name)
        .collect();
    names.sort();
    names
}

/// Crockford's base32 alphabet, lowercased.
const SLUG_ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

const SLUG_BYTES: usize = 10;
const _: () = assert!(
    SLUG_BYTES.is_multiple_of(5) && SLUG_BYTES <= 32,
    "SLUG_BYTES must be a multiple of 5 (so base32 needs no padding) and fit a sha256 digest"
);

/// The algorithm must never change - it *is* every box's address, and changing
/// it would orphan them all. Truncated to 80 bits, accidental collisions are
/// very unlikely (2^40 birthday) and landing on a *chosen* path would take
/// ~2^80 work, which is what sha256 buys over a fast non-cryptographic hash.
fn slug(project_dir: &Path) -> String {
    let real = std::fs::canonicalize(project_dir).unwrap_or_else(|_| project_dir.to_path_buf());
    let digest = Sha256::digest(real.to_string_lossy().as_bytes());

    let mut out = String::with_capacity(2 + SLUG_BYTES * 8 / 5);
    out.push_str("t-");
    // `acc` holds at most 12 bits (four left over, plus the byte just read),
    // so a u16 cannot overflow.
    let (mut acc, mut bits) = (0u16, 0u32);
    for byte in &digest[..SLUG_BYTES] {
        acc = (acc << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(SLUG_ALPHABET[usize::from((acc >> bits) & 0x1f)] as char);
        }
    }
    out
}

pub fn read_origin(project: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(project.join(ORIGIN_FILE)).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| PathBuf::from(text))
}

/// Whether a box has a guest filesystem, and whether a terra is holding it.
pub enum BoxState {
    Running,
    SettingUp,
    Stopped,
    NotCreated,
    /// State remains, but the project directory is gone.
    Gone,
}

impl std::fmt::Display for BoxState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `pad`, not `write_str`: only `pad` honors the width the listing
        // asks for.
        f.pad(match self {
            BoxState::Running => "running",
            BoxState::SettingUp => "setting-up",
            BoxState::Stopped => "stopped",
            BoxState::NotCreated => "not-created",
            BoxState::Gone => "gone",
        })
    }
}

fn holds_lock(path: &Path) -> bool {
    let Ok(file) = OpenOptions::new().read(true).open(path) else {
        return false; // no lock file -> never started
    };
    match file.try_lock_shared() {
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(TryLockError::WouldBlock) => true,
        Err(TryLockError::Error(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::TestHome;

    /// Every test here holds a [`TestHome`] before it resolves anything:
    /// resolution settles a box's directory under the home there and then, so
    /// one taken afterwards would be a box in the developer's real `~/.terra`.
    fn bx(project_dir: &Path) -> BoxRef {
        BoxRef::resolve(project_dir, "dev").unwrap()
    }

    /// Substituting the cwd let whatever directory terra ran from supply the
    /// kernel it boots.
    #[test]
    fn terra_home_is_absolute_never_the_cwd() {
        let _home = TestHome::new();
        let home = ensure_terra_home().unwrap();
        assert!(home.is_absolute(), "{}", home.display());
        assert!(home.ends_with(".terra"), "{}", home.display());
    }

    /// A loose `~/.terra` let another host account choose what a box mounts
    /// and runs. Both halves are checked here - a directory terra creates, and
    /// one it finds already open, which is the case that matters since terra
    /// creating it is not the risky one.
    #[cfg(unix)]
    #[test]
    fn terra_home_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode_of = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

        let _home = TestHome::new();
        let home = ensure_terra_home().unwrap();
        assert_eq!(mode_of(&home), 0o700, "{} is loose", home.display());

        // …and one that was already open is tightened rather than accepted.
        // This is the half that used to be checked on a directory of its own,
        // because loosening the *real* `~/.terra` to prove it would have
        // loosened a directory shared with every other test in the run.
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o775)).unwrap();
        ensure_terra_home().unwrap();
        assert_eq!(
            mode_of(&home),
            0o700,
            "a directory that was already open was left as it was"
        );
    }

    /// The base32 encoding is written here, so pin it against a digest taken
    /// from somewhere else rather than against itself. `/tmp` is canonical on
    /// every host this runs on, so `slug` hashes exactly that string:
    ///
    /// ```text
    /// $ printf /tmp | sha256sum | cut -c1-20
    /// e9671acd244849c57167
    /// ```
    ///
    /// which is the 10 bytes the slug encodes, five bits at a time.
    #[test]
    fn the_slug_is_base32_of_the_first_digest_bytes() {
        let s = slug(Path::new("/tmp"));
        assert_eq!(s, "t-x5khnk94914wawb7");

        let body = s.strip_prefix("t-").expect("every slug is prefixed");
        assert_eq!(body.len(), SLUG_BYTES * 8 / 5, "no padding, exact fit");
        assert!(
            body.bytes().all(|c| SLUG_ALPHABET.contains(&c)),
            "a slug is one case and has no look-alike letters: {s}"
        );
    }

    #[test]
    fn box_state_lives_in_the_home_layout() {
        let home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let project_dir = dir.path().join("fresh");
        std::fs::create_dir(&project_dir).unwrap();
        let b = bx(&project_dir);
        assert!(
            b.dir()
                .starts_with(home.path().join(".terra").join(BOX_HOME))
        );
        assert_eq!(b.dir().file_name().unwrap(), "dev");
        let project = b.dir().parent().unwrap();
        let slug = project.file_name().unwrap().to_str().unwrap();
        assert!(slug.starts_with("t-"), "{}", b.dir().display());
        assert_eq!(
            slug.len(),
            18,
            "the slug is `t-` and 16 base32 characters: {slug}"
        );

        // The prefix is a constant, so the hash is the only thing telling two
        // projects apart - a slug that stopped varying would put every project
        // on the machine in one directory.
        let other = dir.path().join("second");
        std::fs::create_dir(&other).unwrap();
        assert_ne!(
            bx(&other).dir().parent().unwrap(),
            project,
            "two project directories must not share a slug"
        );
        assert_eq!(bx(&project_dir).dir(), project.join("dev"));
        // Resolution created nothing: listing commands resolve boxes they never build.
        assert!(!b.dir().exists());
    }

    /// Every state is one word. `terra ls --tsv` is read by scripts that split
    /// on whitespace, where a state spelled `not created` shifts every field
    /// after it - and the human listing shares this spelling, so neither can
    /// drift from what the other promises.
    #[test]
    fn every_box_state_is_a_single_word() {
        for state in [
            BoxState::Running,
            BoxState::SettingUp,
            BoxState::Stopped,
            BoxState::NotCreated,
            BoxState::Gone,
        ] {
            let word = state.to_string();
            assert!(!word.is_empty());
            assert!(
                !word.chars().any(char::is_whitespace),
                "{word:?} is not a single word"
            );
        }
    }

    /// `config.yaml` is what moves the two directories that grow onto another
    /// disk. Every box hangs off [`box_home_path`], so a box resolved after the
    /// file is written really lands there - and each directory is secured in
    /// its own right, because an external disk is commonly mounted for everyone.
    ///
    /// The file is read once ([`settings`]), which a test writing one after a
    /// path has already been resolved says out loud.
    #[cfg(unix)]
    #[test]
    fn config_yaml_moves_the_boxes_and_the_cache_off_the_home_directory() {
        use std::os::unix::fs::PermissionsExt;
        let home = TestHome::new();
        let elsewhere = tempfile::tempdir().unwrap();
        let project = tempfile::tempdir().unwrap();

        // No file at all is the default layout, under `~/.terra`.
        assert_eq!(box_home_path().unwrap(), home.path().join(".terra/box"));
        assert_eq!(cache_path().unwrap(), home.path().join(".terra/cache"));

        let terra = ensure_terra_home().unwrap();
        std::fs::write(
            terra.join(SETTINGS_FILE),
            format!(
                "storage:\n  boxes: {home}/boxes\n  cache: {home}/cache\n",
                home = elsewhere.path().display()
            ),
        )
        .unwrap();
        forget_settings();
        assert_eq!(box_home_path().unwrap(), elsewhere.path().join("boxes"));
        assert_eq!(cache_path().unwrap(), elsewhere.path().join("cache"));
        assert!(
            bx(project.path())
                .dir()
                .starts_with(elsewhere.path().join("boxes")),
            "the box did not follow storage.boxes"
        );

        for made in [ensure_box_home().unwrap(), ensure_cache_dir().unwrap()] {
            let mode = std::fs::metadata(&made).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{} is loose", made.display());
        }
    }

    /// The file decides where every box on the machine is, so anything it says
    /// that terra cannot act on is refused rather than quietly answered with the
    /// default layout - which would read as a machine with no boxes at all.
    #[test]
    fn a_config_yaml_terra_cannot_act_on_is_refused_rather_than_ignored() {
        let _home = TestHome::new();
        let terra = ensure_terra_home().unwrap();
        let settings = terra.join(SETTINGS_FILE);

        for (yaml, wanted) in [
            ("storage:\n  boxes: ../boxes\n", "absolute path"),
            ("storage:\n  cache: cache\n", "absolute path"),
            ("storage:\n  boxes: ~alice/boxes\n", "absolute path"),
            ("storage:\n  boxs: /tmp/b\n", "failed to parse"),
            ("storage:\n  boxes: [/tmp/b]\n", "failed to parse"),
            // The flat spelling this setting never shipped with.
            ("boxes: /tmp/b\n", "failed to parse"),
        ] {
            std::fs::write(&settings, yaml).unwrap();
            forget_settings();
            let err = format!(
                "{:#}",
                box_home_path()
                    .and_then(|_| cache_path())
                    .expect_err("a setting terra cannot act on must not fall back")
            );
            assert!(err.contains(wanted), "{yaml:?}: {err}");
        }

        // One directory named leaves the other where it was, and `~` expands.
        std::fs::write(&settings, "storage:\n  cache: ~/somewhere-else\n").unwrap();
        forget_settings();
        assert_eq!(box_home_path().unwrap(), terra.join(BOX_HOME));
        assert_eq!(
            cache_path().unwrap(),
            crate::sys::home_dir().unwrap().join("somewhere-else")
        );
        // An empty file is a file that overrides nothing.
        std::fs::write(&settings, "").unwrap();
        forget_settings();
        assert_eq!(cache_path().unwrap(), terra.join(CACHE_HOME));
    }

    /// [`SETTINGS_FILE`] is read once and kept, so that one command cannot
    /// resolve two of its own paths under two different box homes - the file
    /// is commonly queried several times over ([`crate::policy::mount`] alone
    /// reads three of the directories it names). Proven by taking the file
    /// away from a resolution that has already happened: a second read would
    /// answer with the default layout instead of what was settled.
    #[test]
    fn the_settings_file_is_read_once_rather_than_once_per_path() {
        let _home = TestHome::new();
        let elsewhere = tempfile::tempdir().unwrap();
        let terra = ensure_terra_home().unwrap();
        let settings = terra.join(SETTINGS_FILE);
        std::fs::write(
            &settings,
            format!("storage:\n  boxes: {}/boxes\n", elsewhere.path().display()),
        )
        .unwrap();

        let settled = box_home_path().unwrap();
        assert_eq!(settled, elsewhere.path().join("boxes"));

        std::fs::remove_file(&settings).unwrap();
        assert_eq!(
            box_home_path().unwrap(),
            settled,
            "the file was read a second time"
        );
    }

    /// The names in a storage artifact were written on another machine, so an
    /// image is addressed by matching what this box would have called one of
    /// its own - a name that could leave the box's directory answers `None`
    /// rather than a path outside it.
    #[test]
    fn only_a_name_this_box_would_have_given_an_image_addresses_one() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = bx(dir.path());

        assert_eq!(b.image_named(ROOTFS_FILE), Some(b.rootfs_img()));
        assert_eq!(b.image_named("vol-data.img"), Some(b.volume_img("data")));
        for outside in [
            "../../.ssh/authorized_keys",
            "/etc/passwd",
            "vol-../../evil.img",
            "vol-..img",
            "vol-.img",
            "vol-/evil.img",
            RECIPE_FILE,
            PID_FILE,
            "",
        ] {
            assert_eq!(b.image_named(outside), None, "{outside} addressed a file");
        }
        // …and whatever it does answer is inside the box, by construction.
        for name in [ROOTFS_FILE, "vol-data.img", "vol-x.y.img"] {
            let path = b.image_named(name).unwrap();
            assert_eq!(path.parent(), Some(b.dir()), "{name} escaped the state dir");
        }
    }

    #[test]
    fn existing_names_lists_what_is_on_disk() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        assert!(existing_names(dir.path()).is_empty());
    }

    #[test]
    fn a_symlinked_project_directory_is_the_same_box() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("project");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert_eq!(bx(&real).dir(), bx(&link).dir());
        }
        #[cfg(not(unix))]
        let _ = link;
    }

    #[test]
    fn all_box_state_lives_under_the_state_dir() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = bx(dir.path());
        for p in [
            b.rootfs_img(),
            b.volume_img("data"),
            b.control_sock(),
            b.recipe(),
            b.agent_sock(),
            b.pid_file(),
            b.log(),
            b.diagnostics_log(),
        ] {
            assert!(
                p.starts_with(b.dir()),
                "{} escapes the state dir",
                p.display()
            );
        }
        assert_eq!(b.rootfs_img(), b.dir().join("rootfs.img"));
        assert_eq!(b.volume_img("data"), b.dir().join("vol-data.img"));
    }

    /// Socket paths spend from `sun_path`'s 107 bytes; the slug is a fixed 18,
    /// so neither the project's depth nor the length of its directory name
    /// lengthens a socket path. The long-named case is the one that used to
    /// cost - the directory name was part of the slug.
    #[test]
    fn socket_paths_are_bounded_and_same_length() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let shallow = dir.path().join("box");
        std::fs::create_dir_all(&shallow).unwrap();
        assert!(bx(&shallow).ensure_sockets_fit().is_ok());

        let deep = shallow.join(
            "src/company/team/service/packages/frontend/apps/admin-console/experiments/checkout-rewrite",
        );
        std::fs::create_dir_all(&deep).unwrap();
        let b = bx(&deep);
        assert!(b.ensure_sockets_fit().is_ok());
        assert!(
            b.control_sock().as_os_str().len() < 108,
            "a socket path must fit sun_path: {}",
            b.control_sock().display()
        );

        // The case the old slug paid for: the directory's *name* was part of
        // it, so this box's sockets were ~30 bytes longer than the shallow
        // one's for no reason but its label.
        let long_name = dir.path().join("a-project-directory-with-a-very-long-name");
        std::fs::create_dir_all(&long_name).unwrap();
        assert_eq!(
            bx(&long_name).control_sock().as_os_str().len(),
            bx(&shallow).control_sock().as_os_str().len(),
            "a project's directory name must not lengthen its socket paths"
        );

        // Checking one socket covers both only while their names are the
        // same length - pin that rather than trust it.
        let lengths: Vec<usize> = [b.control_sock(), b.agent_sock()]
            .iter()
            .map(|p| p.as_os_str().len())
            .collect();
        assert!(
            lengths.iter().all(|n| *n == lengths[0]),
            "socket names must stay the same length: {lengths:?}"
        );
    }

    /// A renamed or dropped volume leaves its image behind, and this walk is
    /// what finds them: only `vol-*.img` answers - everything else in the
    /// state directory is the box itself - and never an image the recipe
    /// still names. What to *do* with one is the caller's question
    /// (`setup::tests` pins that a boot keeps them and only `--rebuild`
    /// sweeps).
    #[test]
    fn unused_volume_images_lists_only_what_the_recipe_dropped() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = bx(dir.path());
        assert!(
            b.unused_volume_images(&[]).is_empty(),
            "a box with no state dir has nothing to list"
        );
        std::fs::create_dir_all(b.dir()).unwrap();
        for name in ["data", "cache", "old"] {
            std::fs::write(b.volume_img(name), b"image").unwrap();
        }
        std::fs::write(b.rootfs_img(), b"rootfs").unwrap();
        std::fs::write(b.recipe(), "hw:\n  cpus: 1\n").unwrap();
        std::fs::write(b.log(), b"output").unwrap();

        let mut unused = b.unused_volume_images(&["data".to_string()]);
        unused.sort();
        assert_eq!(unused, vec![b.volume_img("cache"), b.volume_img("old")]);

        // With no volumes configured every image is unused - and still nothing
        // but a volume image is listed.
        let mut all = b.unused_volume_images(&[]);
        all.sort();
        assert_eq!(
            all,
            vec![
                b.volume_img("cache"),
                b.volume_img("data"),
                b.volume_img("old")
            ]
        );
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
        let b = bx(dir.path());
        std::fs::create_dir_all(b.dir()).unwrap();
        let hold_briefly = |lock: fn(&File) -> std::result::Result<(), TryLockError>| {
            let probe = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .truncate(false)
                .open(b.pid_file())
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
    /// `terra stop`: a bake or a storage export legitimately keeps the box for
    /// minutes, and stopping it is not what the contender wants to be told.
    /// A box mid-bake answers with the setup refusal, which says what the
    /// holder actually is.
    #[test]
    fn contention_names_the_command_holding_the_box() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = bx(dir.path());
        std::fs::create_dir_all(b.dir()).unwrap();

        let lock = b.lock_run().unwrap();
        b.publish_pid(4242, false);
        let err = b.lock_run().expect_err("the box is held").to_string();
        assert!(
            err.contains("locked by another terra command (pid 4242)"),
            "{err}"
        );
        assert!(!err.contains("terra stop"), "no stop advice: {err}");

        let marked = b.mark_baking(&lock);
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
        let b = bx(dir.path());
        std::fs::create_dir_all(b.dir()).unwrap();
        std::fs::write(b.pid_file(), "").unwrap();

        let in_flight = OpenOptions::new().read(true).open(b.pid_file()).unwrap();
        in_flight.try_lock_shared().unwrap();
        assert_eq!(
            b.holder(),
            Holder::Free,
            "another probe was mistaken for a live holder"
        );
        drop(in_flight);

        // …and a box that really is held still reads as running, which is the
        // half a probe that always answered "no" would also satisfy.
        let held = b.lock_run().unwrap();
        assert_eq!(b.holder(), Holder::Running);
        drop(held);
        assert_eq!(b.holder(), Holder::Free);
    }

    /// The lock, the pid and the bake mark are one file: taking the lock empties
    /// whatever the last run left, so a dead pid can never be read as a live one
    /// and a mark a killed bake left behind can never make the next boot read as
    /// a bake. What is signalled must also *be* a pid (signalling `0` reaches
    /// the process group).
    ///
    /// [`BoxRef::holder`] is the whole of the answer, so it is read here rather
    /// than the mark: a mark nobody is holding the lock over is nobody's, which
    /// is what a bake killed between writing it and taking the lock leaves.
    #[test]
    fn the_lock_is_the_pid_file_and_taking_it_empties_what_the_last_run_left() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = bx(dir.path());
        std::fs::create_dir_all(b.dir()).unwrap();

        assert_eq!(b.vm_process(), None, "no pid file at all");
        for bad in ["", "  ", "0", "-1", "nonsense", BAKE_MARK] {
            std::fs::write(b.pid_file(), bad).unwrap();
            assert_eq!(b.vm_process(), None, "{bad:?} is not a pid");
            assert_eq!(b.holder(), Holder::Free, "{bad:?} under no lock");
        }

        b.publish_pid(4242, false);
        let published = b.vm_process().unwrap();
        assert_eq!(published.pid, 4242);
        assert_eq!(
            published.started_at,
            crate::sys::process_start_time(4242),
            "the starttime is read off /proc and round-trips"
        );
        b.publish_pid(4242, true);
        let marked = b.vm_process().unwrap();
        assert_eq!(marked.pid, 4242, "a marked line still names its pid");
        assert_eq!(
            marked.started_at, published.started_at,
            "the mark rides behind the starttime"
        );

        // A line from before starttimes were recorded still reads.
        std::fs::write(b.pid_file(), "4242").unwrap();
        let legacy = b.vm_process().unwrap();
        assert_eq!(legacy.pid, 4242);
        assert_eq!(legacy.started_at, None, "the old format has no starttime");
        std::fs::write(b.pid_file(), "4242 bake").unwrap();
        assert_eq!(
            b.vm_process().unwrap().started_at,
            None,
            "a bare word where the starttime belongs reads as absent"
        );

        let lock = b.lock_run().unwrap();
        assert_eq!(b.vm_process(), None, "the last run's pid outlived its lock");
        assert_eq!(
            b.holder(),
            Holder::Running,
            "a killed bake's mark outlived its lock"
        );
        // Still the same inode being locked, not a fresh file beside it.
        assert!(b.pid_file().exists());
        assert!(b.lock_run().is_err(), "a second run got the same box");

        // A bake that has not spawned its child yet: marked, with no pid to
        // signal - which is what `terra stop` waits out rather than mistaking
        // for a stopped box. The guard puts the file back however it ended.
        let marked = b.mark_baking(&lock);
        assert_eq!(b.holder(), Holder::SettingUp, "the mark alone is a mark");
        assert_eq!(
            b.vm_process(),
            None,
            "a bake marks the box before it has a pid"
        );
        b.publish_pid(4242, true);
        assert_eq!(b.holder(), Holder::SettingUp);
        assert_eq!(
            b.vm_process().map(|vm| vm.pid),
            Some(4242),
            "and publishes both once it has one"
        );
        drop(marked);
        assert_eq!(b.holder(), Holder::Running);
        assert_eq!(
            b.vm_process(),
            None,
            "the bake child's pid outlived the bake"
        );

        b.publish_pid(std::process::id(), false);
        assert_eq!(b.vm_process().map(|vm| vm.pid), Some(std::process::id()));

        drop(lock);
        assert_eq!(b.holder(), Holder::Free);
    }

    /// The pid file is rewritten in place, never renamed over: the run lock
    /// is held on its inode, and a replacement file would hand the next
    /// opener a fresh, unlocked inode while the box stayed locked on the old
    /// one.
    #[cfg(unix)]
    #[test]
    fn publishing_a_pid_keeps_the_lock_file_s_inode() {
        use std::os::unix::fs::MetadataExt;
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = bx(dir.path());
        std::fs::create_dir_all(b.dir()).unwrap();
        let held = b.lock_run().unwrap();

        b.publish_pid(4242, false);
        let identity = |p: &Path| {
            let meta = std::fs::metadata(p).unwrap();
            (meta.dev(), meta.ino())
        };
        let before = identity(&b.pid_file());

        // Longer, then shorter than what it replaced - no tail may survive.
        b.publish_pid(u32::MAX - 1, true);
        b.publish_pid(4242, false);
        assert_eq!(
            identity(&b.pid_file()),
            before,
            "the lock file was replaced"
        );
        // 4242 names nothing in /proc, so the published line is bare.
        assert_eq!(std::fs::read_to_string(b.pid_file()).unwrap(), "4242");
        assert!(b.holder().holds(), "the lock outlived the rewrites");
        drop(held);
    }

    /// What [`BoxRef::setup_holds_it`] says, pinned at the definition that
    /// owns it: it is the one refusal for a box mid-`terra setup`, and
    /// `session` and `cmd::start` both hand it straight to their callers -
    /// which used to assert its wording themselves, so rewording it here broke
    /// two tests that are about neither the wording nor this message.
    #[test]
    fn the_refusal_for_a_box_being_set_up_names_the_bake_and_the_way_to_watch_it() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = bx(dir.path());

        let refusal = b.setup_holds_it().to_string();
        assert!(refusal.contains("being set up"), "{refusal}");
        assert!(refusal.contains(b.name()), "which box: {refusal}");
        assert!(
            refusal.contains(&b.logs_command()),
            "the way to watch it: {refusal}"
        );
    }

    /// Every state a caller can meet is one of [`Holder`]'s, and only a box
    /// nobody holds falls through to what is on disk. `terra ls` reported a box
    /// mid-`terra setup` as plain `running`, which reads as a box there is
    /// something to talk to in.
    #[test]
    fn a_box_being_set_up_is_its_own_state_not_running() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = bx(dir.path());
        std::fs::create_dir_all(b.dir()).unwrap();

        assert!(matches!(b.state(), BoxState::NotCreated));
        std::fs::write(b.rootfs_img(), b"image").unwrap();
        assert!(matches!(b.state(), BoxState::Stopped));

        let lock = b.lock_run().unwrap();
        assert!(matches!(b.state(), BoxState::Running));
        let marked = b.mark_baking(&lock);
        assert!(matches!(b.state(), BoxState::SettingUp));
        assert_eq!(b.state().to_string(), "setting-up");
        drop(marked);
        drop(lock);

        // A working tree that is gone outranks the filesystem still being there.
        drop(dir);
        assert!(matches!(b.state(), BoxState::Gone));
    }
}
