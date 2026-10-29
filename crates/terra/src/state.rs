//! Terra's state on disk: `~/.terra`, and each box's directory under it.

use anyhow::{Context, Result, bail};
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

mod images;
mod import;
mod lock;
mod pin;
mod setup_state;

pub(crate) use images::ROOTFS_FILE;
pub(crate) use import::StagedImportFile;
pub(crate) use lock::{HOST_PID_FILE, PID_FILE, SUPERVISOR_PID_FILE};
pub use lock::{Holder, ProcessIdentity};
pub use pin::{PINNED_PATHS_FILE, RECIPE_FILE};
pub(crate) use pin::{PinnedPaths, list_pinned_recipes_across_boxes, write_pin};
pub(crate) use setup_state::SETUP_STAMP;
pub use setup_state::{BoxSetupState, BoxState};

const BOX_HOME: &str = "box";

pub(crate) const CONTROL_SOCKET: &str = "c";
pub(crate) const AGENT_SOCKET: &str = "a";
/// The one box directory the VM worker may write, beside its volumes.
pub(crate) const RUNTIME_LOG_DIR: &str = "runtime-logs";
pub(crate) const LOG_FILE: &str = "runtime-logs/terra.log";
pub(crate) const DIAGNOSTICS_LOG: &str = "runtime-logs/diagnostics.log";

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
    pub(crate) fn prepare_state_dir(&self) -> Result<()> {
        self.ensure_project_dir_exists()?;
        // Box state inherits the box directory's protection, which
        // [`ensure_box_home`] enforces.
        ensure_box_home()?;
        std::fs::create_dir_all(self.get_dir())
            .with_context(|| format!("creating box state {}", self.get_dir().display()))?;
        crate::sys::set_owner_only(self.get_dir(), true)
            .with_context(|| format!("securing box state {}", self.get_dir().display()))?;
        self.write_origin()?;
        Ok(())
    }

    /// Refused rather than created: a typo'd `--project` would silently mint a
    /// directory and a box for it.
    fn ensure_project_dir_exists(&self) -> Result<()> {
        anyhow::ensure!(
            self.get_project_dir().is_dir(),
            "{} is not a directory, so it can have no box (--project names the \
             directory a box belongs to - check the spelling, or create it first)",
            self.get_project_dir().display()
        );
        Ok(())
    }

    pub fn resolve(project_dir: &Path, name: &str) -> Result<Self> {
        let name = crate::name::normalize_box_name(name);
        let dir = get_project_state_dir(project_dir)?.join(&name);
        Ok(Self {
            project_dir: project_dir.to_path_buf(),
            name,
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

    pub fn get_project_dir(&self) -> &Path {
        &self.project_dir
    }

    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn get_dir(&self) -> &Path {
        &self.dir
    }

    /// Refuse the box before anything is built - the alternative is
    /// `ENAMETOOLONG` buried in a half-done boot.
    pub fn ensure_sockets_fit(&self) -> Result<()> {
        let sock = self.dir.join(CONTROL_SOCKET);
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

    pub fn build_logs_command(&self) -> String {
        format!(
            "terra {} logs --project {}",
            self.name,
            crate::render::quote_shell_word(&self.project_dir.to_string_lossy())
        )
    }

    pub fn write_origin(&self) -> Result<()> {
        use std::io::Write as _;
        let project = self
            .dir
            .parent()
            .context("box state has no project directory")?;
        // On Unix, resolved like the slug, so every spelling of one project records the same
        // origin; Windows keeps the typed path rather than canonicalize's verbatim `\\?\` form.
        #[cfg(unix)]
        let bytes = {
            use std::os::unix::ffi::OsStringExt as _;
            crate::sys::canonicalize_existing_prefix(&self.project_dir)
                .into_os_string()
                .into_vec()
        };
        #[cfg(windows)]
        let bytes = {
            use std::os::windows::ffi::OsStrExt as _;
            [0xff, 0xfe]
                .into_iter()
                .chain(
                    self.project_dir
                        .as_os_str()
                        .encode_wide()
                        .flat_map(u16::to_le_bytes),
                )
                .collect::<Vec<_>>()
        };
        crate::vm::image::staged_write(&project.join(ORIGIN_FILE), |file| {
            Ok(file.write_all(&bytes)?)
        })
        .context("recording project origin")
    }
}

/// A box's name and its directory - either alone is ambiguous.
impl std::fmt::Display for BoxRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({})", self.name, self.project_dir.display())
    }
}

pub(crate) fn get_terra_home_path() -> Result<PathBuf> {
    Ok(crate::sys::resolve_home_dir()?.join(".terra"))
}

pub fn get_box_home_path() -> Result<PathBuf> {
    get_terra_home_path().map(|home| home.join(BOX_HOME))
}

fn ensure_owner_only_dir(dir: PathBuf, holds: &str) -> Result<PathBuf> {
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    crate::sys::set_owner_only(&dir, true).with_context(|| {
        format!(
            "securing {} - it holds {holds}, so terra will not read one out of a \
             directory it cannot make owner-only",
            dir.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        anyhow::ensure!(
            std::fs::metadata(&dir)?.permissions().mode() & 0o777 == 0o700,
            "securing {} - it holds {holds}, so terra will not read one out of a directory that is not owner-only",
            dir.display()
        );
    }
    Ok(dir)
}

pub fn ensure_terra_home() -> Result<PathBuf> {
    ensure_owner_only_dir(
        get_terra_home_path()?,
        "this machine's recipes (what a sandbox may mount and reach) and where the \
         boxes are kept",
    )
}

pub fn ensure_box_home() -> Result<PathBuf> {
    let terra_home = ensure_terra_home()?;
    ensure_owner_only_dir(
        terra_home.join(BOX_HOME),
        "every box's recipe, disk images and sockets",
    )
}

/// `<box_dir>/<slug>` - every box of `project_dir`.
///
/// Built from [`get_box_home_path`] because [`crate::policy::mount`] protects only
/// what that function returns - a second spelling would escape the check.
pub fn get_project_state_dir(project_dir: &Path) -> Result<PathBuf> {
    Ok(get_box_home_path()?.join(compute_slug(project_dir)))
}

/// The boxes under one `~/.terra/box/<slug>/`, as `(name, state directory)`.
/// Unordered; a missing slug is empty.
pub fn list_boxes_in(project_state_dir: &Path) -> Result<Vec<(String, PathBuf)>> {
    let entries = match std::fs::read_dir(project_state_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", project_state_dir.display()));
        }
    }
    .collect::<std::io::Result<Vec<_>>>()
    .with_context(|| format!("reading {}", project_state_dir.display()))?;
    let mut boxes = Vec::new();
    for entry in entries {
        if !entry.file_type()?.is_dir() {
            continue;
        }
        if let Some((name, path)) = {
            entry
                .file_name()
                .into_string()
                .ok()
                .filter(|name| !name.starts_with('.'))
                // An older terra's `Dev/` is a directory no box name resolves to.
                .filter(|name| *name == crate::name::normalize_box_name(name))
                .map(|name| (name, entry.path()))
        } {
            boxes.push((name, path));
        }
    }
    Ok(boxes)
}

pub fn list_existing_names(project_dir: &Path) -> Result<Vec<String>> {
    let project = get_project_state_dir(project_dir)?;
    let mut names: Vec<String> = list_boxes_in(&project)?
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    names.sort();
    Ok(names)
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
fn compute_slug(project_dir: &Path) -> String {
    let real = crate::sys::canonicalize_existing_prefix(project_dir);
    let digest = Sha256::digest(real.as_os_str().as_encoded_bytes());

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
    let bytes = std::fs::read(project.join(ORIGIN_FILE)).ok()?;
    if bytes.is_empty() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt as _;
        Some(std::ffi::OsString::from_vec(bytes).into())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStringExt as _;
        let wide = bytes.strip_prefix(&[0xff, 0xfe])?;
        if wide.is_empty() || !wide.len().is_multiple_of(2) {
            return None;
        }
        let wide = wide
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .collect::<Vec<_>>();
        Some(std::ffi::OsString::from_wide(&wide).into())
    }
}

#[cfg(test)]
fn wait_until_free(b: &BoxRef) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while b.get_holder().unwrap() != Holder::Free && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(test)]
/// Every test here holds a [`TestHome`] before it resolves anything:
/// resolution settles a box's directory under the home there and then, so
/// one taken afterwards would be a box in the developer's real `~/.terra`.
fn resolve_box_ref(project_dir: &Path) -> BoxRef {
    BoxRef::resolve(project_dir, "dev").unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::TestHome;

    #[test]
    fn project_origins_preserve_native_paths_and_reject_failed_writes() {
        let dir = tempfile::tempdir().unwrap();
        let box_dir = dir.path().join("box");
        // Unix origins are recorded resolved, and macOS's temp directory sits behind a symlink.
        #[cfg(unix)]
        let project = dir.path().canonicalize().unwrap().join("project ");
        #[cfg(windows)]
        let project = dir.path().join("project ");
        let mut paths = vec![PathBuf::from(" project \t"), project];
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;
            paths.push(std::ffi::OsString::from_vec(b"/project-\xff ".to_vec()).into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt as _;
            paths.push(
                std::ffi::OsString::from_wide(&[
                    u16::from(b'C'),
                    u16::from(b':'),
                    u16::from(b'\\'),
                    0xd800,
                ])
                .into(),
            );
        }
        for path in paths {
            let bx = BoxRef::from_state_dir(box_dir.clone(), &path);
            bx.write_origin().unwrap();
            assert_eq!(read_origin(dir.path()), Some(path));
        }
        #[cfg(unix)]
        {
            std::fs::write(
                dir.path().join(ORIGIN_FILE),
                b"/project with trailing space ",
            )
            .unwrap();
            assert_eq!(
                read_origin(dir.path()),
                Some(PathBuf::from("/project with trailing space "))
            );
        }
        #[cfg(windows)]
        {
            std::fs::write(dir.path().join(ORIGIN_FILE), b"invalid UTF-16 origin").unwrap();
            assert_eq!(read_origin(dir.path()), None);
        }
        #[cfg(unix)]
        {
            let real = tempfile::tempdir().unwrap();
            let link = dir.path().join("project-link");
            std::os::unix::fs::symlink(real.path(), &link).unwrap();
            BoxRef::from_state_dir(box_dir.clone(), &link)
                .write_origin()
                .unwrap();
            assert_eq!(
                read_origin(dir.path()),
                Some(real.path().canonicalize().unwrap())
            );
        }
        std::fs::remove_file(dir.path().join(ORIGIN_FILE)).unwrap();
        std::fs::create_dir(dir.path().join(ORIGIN_FILE)).unwrap();
        let bx = BoxRef::from_state_dir(box_dir, dir.path());
        assert!(bx.write_origin().is_err());
        assert!(dir.path().join(ORIGIN_FILE).is_dir());
    }

    #[test]
    fn missing_project_under_a_symlink_keeps_the_same_slug() {
        let directory = tempfile::tempdir().unwrap();
        let real = directory.path().join("real");
        let link = directory.path().join("link");
        std::fs::create_dir(&real).unwrap();
        crate::sys::symlink_dir(&real, &link).unwrap();
        assert_eq!(
            compute_slug(&real.join("missing")),
            compute_slug(&link.join("missing"))
        );
        let before_creation = compute_slug(&real.join("missing"));
        std::fs::create_dir(real.join("missing")).unwrap();
        assert_eq!(before_creation, compute_slug(&link.join("missing")));
    }

    /// Substituting the cwd let whatever directory terra ran from supply the
    /// recipes it trusts.
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
    /// from somewhere else rather than against itself. On Unix `/` is its own
    /// canonical form, so `slug` hashes exactly that string:
    ///
    /// ```text
    /// $ printf / | sha256sum | cut -c1-20
    /// 8a5edab28263244321
    /// ```
    ///
    /// which is the 10 bytes the slug encodes, five bits at a time.
    #[test]
    fn the_slug_is_base32_of_the_first_digest_bytes() {
        let s = compute_slug(Path::new("/"));
        // Windows resolves `/` to a drive root, whose spelling is not fixed.
        #[cfg(unix)]
        assert_eq!(s, "t-h9fdncm2ccj468cy");

        let body = s.strip_prefix("t-").expect("every slug is prefixed");
        assert_eq!(body.len(), SLUG_BYTES * 8 / 5, "no padding, exact fit");
        assert!(
            body.bytes().all(|c| SLUG_ALPHABET.contains(&c)),
            "a slug is one case and has no look-alike letters: {s}"
        );
    }

    #[test]
    fn distinct_non_utf8_project_paths_have_distinct_slugs() {
        use std::ffi::OsString;
        #[cfg(unix)]
        let names = {
            use std::os::unix::ffi::OsStringExt as _;
            [
                OsString::from_vec(vec![0x80]),
                OsString::from_vec(vec![0x81]),
            ]
        };
        #[cfg(windows)]
        let names = {
            use std::os::windows::ffi::OsStringExt as _;
            [
                OsString::from_wide(&[0xd800]),
                OsString::from_wide(&[0xd801]),
            ]
        };
        let root = tempfile::tempdir().unwrap();
        let [first, second] = names.map(|name| root.path().join(name));
        assert!(first.to_str().is_none());
        assert!(second.to_str().is_none());
        assert_ne!(compute_slug(&first), compute_slug(&second));
    }

    #[test]
    fn box_state_lives_in_the_home_layout() {
        let home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let project_dir = dir.path().join("fresh");
        std::fs::create_dir(&project_dir).unwrap();
        let b = resolve_box_ref(&project_dir);
        assert!(
            b.get_dir()
                .starts_with(home.get_path().join(".terra").join(BOX_HOME))
        );
        assert_eq!(b.get_dir().file_name().unwrap(), "dev");
        let project = b.get_dir().parent().unwrap();
        let slug = project.file_name().unwrap().to_str().unwrap();
        assert!(slug.starts_with("t-"), "{}", b.get_dir().display());
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
            resolve_box_ref(&other).get_dir().parent().unwrap(),
            project,
            "two project directories must not share a slug"
        );
        assert_eq!(resolve_box_ref(&project_dir).get_dir(), project.join("dev"));
        // Resolution created nothing: listing commands resolve boxes they never build.
        assert!(!b.get_dir().exists());
    }

    #[test]
    fn box_path_lives_under_terra_home() {
        let home = TestHome::new();
        let terra_home = home.get_path().join(".terra");
        assert_eq!(get_box_home_path().unwrap(), terra_home.join("box"));
    }

    /// Box names are normalized to lowercase, so a directory an older terra
    /// made as `Dev/` is no box any name reaches - listing it would offer a
    /// box that every command then reports missing.
    #[test]
    fn a_directory_no_box_name_reaches_is_not_listed() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let project = get_project_state_dir(dir.path()).unwrap();
        std::fs::create_dir_all(project.join("Dev")).unwrap();
        std::fs::create_dir_all(project.join("ci")).unwrap();
        assert_eq!(list_existing_names(dir.path()).unwrap(), ["ci"]);
    }

    #[test]
    fn list_existing_names_from_disk() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            list_existing_names(dir.path()).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn list_existing_names_refuses_an_unreadable_state_directory() {
        let _home = TestHome::new();
        let project = tempfile::tempdir().unwrap();
        let state_dir = get_project_state_dir(project.path()).unwrap();
        std::fs::create_dir_all(state_dir.parent().unwrap()).unwrap();
        std::fs::write(&state_dir, "not a directory").unwrap();
        assert!(list_existing_names(project.path()).is_err());
    }

    #[test]
    fn a_symlinked_project_directory_is_the_same_box() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("project");
        std::fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        crate::sys::symlink_dir(&real, &link).unwrap();
        assert_eq!(
            resolve_box_ref(&real).get_dir(),
            resolve_box_ref(&link).get_dir()
        );
    }

    /// The VM worker's only writable box directory holds both logs it writes.
    #[test]
    fn vm_written_logs_live_in_the_runtime_log_dir() {
        for log in [LOG_FILE, DIAGNOSTICS_LOG] {
            assert_eq!(Path::new(log).parent(), Some(Path::new(RUNTIME_LOG_DIR)));
        }
    }

    #[test]
    fn all_box_state_lives_under_the_state_dir() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let b = resolve_box_ref(dir.path());
        for p in [
            b.get_dir().join(ROOTFS_FILE),
            b.get_volume_image_path("data"),
            b.get_dir().join(CONTROL_SOCKET),
            b.get_dir().join(RECIPE_FILE),
            b.get_dir().join(AGENT_SOCKET),
            b.get_dir().join(PID_FILE),
            b.get_dir().join(LOG_FILE),
            b.get_dir().join(DIAGNOSTICS_LOG),
        ] {
            assert!(
                p.starts_with(b.get_dir()),
                "{} escapes the state dir",
                p.display()
            );
        }
        assert_eq!(
            b.get_volume_image_path("data"),
            b.get_dir().join("vol-data.img")
        );
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
        assert!(resolve_box_ref(&shallow).ensure_sockets_fit().is_ok());

        let deep = shallow.join(
            "src/company/team/service/packages/frontend/apps/admin-console/experiments/checkout-rewrite",
        );
        std::fs::create_dir_all(&deep).unwrap();
        let b = resolve_box_ref(&deep);
        assert!(b.ensure_sockets_fit().is_ok());
        assert!(
            b.get_dir().join(CONTROL_SOCKET).as_os_str().len() < 108,
            "a socket path must fit sun_path: {}",
            b.get_dir().join(CONTROL_SOCKET).display()
        );

        // The case the old slug paid for: the directory's *name* was part of
        // it, so this box's sockets were ~30 bytes longer than the shallow
        // one's for no reason but its label.
        let long_name = dir.path().join("a-project-directory-with-a-very-long-name");
        std::fs::create_dir_all(&long_name).unwrap();
        assert_eq!(
            resolve_box_ref(&long_name)
                .get_dir()
                .join(CONTROL_SOCKET)
                .as_os_str()
                .len(),
            resolve_box_ref(&shallow)
                .get_dir()
                .join(CONTROL_SOCKET)
                .as_os_str()
                .len(),
            "a project's directory name must not lengthen its socket paths"
        );

        // Checking one socket covers both only while their names are the
        // same length - pin that rather than trust it.
        let lengths: Vec<usize> = [
            b.get_dir().join(CONTROL_SOCKET),
            b.get_dir().join(AGENT_SOCKET),
        ]
        .iter()
        .map(|p| p.as_os_str().len())
        .collect();
        assert!(
            lengths.iter().all(|n| *n == lengths[0]),
            "socket names must stay the same length: {lengths:?}"
        );
    }

    /// Two spellings of one name are one box - one lock, one pin, one root -
    /// as a case-insensitive filesystem would make them anyway.
    #[test]
    fn box_names_are_case_insensitive() {
        let _home = TestHome::new();
        let dir = tempfile::tempdir().unwrap();
        let upper = BoxRef::resolve(dir.path(), "Dev").unwrap();
        let lower = BoxRef::resolve(dir.path(), "dev").unwrap();
        assert_eq!(upper.get_dir(), lower.get_dir());
        assert_eq!(upper.get_name(), "dev");
    }
}
