use anyhow::{Context, Result, bail, ensure};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read, Write};
use std::path::Path;
use sysinfo::{MemoryRefreshKind, System};

const MAX_RUNNING_BOXES: usize = 32;
const NATIVE_HEADROOM_BYTES: u64 = 384 << 20;
pub(super) fn admit(ram_bytes: u64, component_memory_bytes: usize) -> Result<File> {
    let reservation_bytes = ram_bytes
        .checked_add(
            u64::try_from(component_memory_bytes)
                .context("component memory reservation overflow")?,
        )
        .and_then(|bytes| bytes.checked_add(NATIVE_HEADROOM_BYTES))
        .context("box memory reservation overflow")?;
    let mut system = System::new();
    system.refresh_memory_specifics(MemoryRefreshKind::nothing().with_ram());
    ensure!(
        system.total_memory() > 0,
        "host memory accounting is unavailable; cannot admit a box"
    );
    let (total, available) = system.cgroup_limits().map_or(
        (system.total_memory(), system.available_memory()),
        |limits| {
            (
                limits.total_memory.min(system.total_memory()),
                limits.free_memory.min(system.available_memory()),
            )
        },
    );
    ensure!(
        reservation_bytes <= available,
        "insufficient available host memory: box needs {} MiB including component memory and native headroom; stop another box or reduce guest RAM",
        reservation_bytes >> 20
    );
    let directory = crate::state::get_terra_home_path()?.join("admission");
    let reservation = reserve(&directory, reservation_bytes, total / 4 * 3)?;
    #[cfg(unix)]
    {
        let current = rustix::process::getrlimit(rustix::process::Resource::Nofile);
        rustix::process::setrlimit(
            rustix::process::Resource::Nofile,
            rustix::process::Rlimit {
                current: Some(
                    current
                        .current
                        .unwrap_or(u64::MAX)
                        .min(terra_limits::MAX_VM_OPEN_FILES as u64),
                ),
                maximum: current.maximum,
            },
        )
        .context("limiting VM file descriptors")?;
        rustix::process::setrlimit(
            rustix::process::Resource::Core,
            rustix::process::Rlimit {
                current: Some(0),
                maximum: rustix::process::getrlimit(rustix::process::Resource::Core).maximum,
            },
        )
        .context("disabling VM core dumps")?;
    }
    log::info!(
        "box admission: {} MiB reserved including component memory and {} MiB native headroom",
        reservation_bytes >> 20,
        NATIVE_HEADROOM_BYTES >> 20
    );
    Ok(reservation)
}

fn open_record(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

fn reserve(directory: &Path, bytes: u64, capacity: u64) -> Result<File> {
    std::fs::create_dir_all(directory).context("creating box admission directory")?;
    crate::sys::set_owner_only(directory, true)?;
    let admission = open_record(&directory.join("lock"))?;
    admission.lock().context("locking box admission")?;
    let mut reserved = 0_u64;
    let mut free = None;
    for index in 0..MAX_RUNNING_BOXES {
        let slot = open_record(&directory.join(index.to_string()))?;
        let record_path = directory.join(format!("{index}.bytes"));
        match slot.try_lock() {
            Ok(()) => {
                if free.is_none() {
                    free = Some((slot, record_path));
                }
            }
            Err(TryLockError::WouldBlock) => {
                let mut record = [0; 8];
                File::open(record_path)?
                    .read_exact(&mut record)
                    .context("reading active box reservation")?;
                reserved = reserved
                    .checked_add(u64::from_le_bytes(record))
                    .context("box reservation total overflow")?;
            }
            Err(TryLockError::Error(error)) => return Err(error.into()),
        }
    }
    if reserved
        .checked_add(bytes)
        .is_none_or(|total| total > capacity)
    {
        bail!("box admission exceeds host memory budget; stop another box or reduce guest RAM");
    }
    let (slot, record_path) = free.with_context(|| {
        format!("all {MAX_RUNNING_BOXES} box admission slots are occupied; stop another box")
    })?;
    let mut record = open_record(&record_path)?;
    record.write_all(&bytes.to_le_bytes())?;
    record.set_len(8)?;
    Ok(slot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn admission_slots_are_bounded_even_for_zero_byte_reservations() {
        let directory = tempfile::tempdir().unwrap();
        let reservations = (0..MAX_RUNNING_BOXES)
            .map(|_| reserve(directory.path(), 0, 100).unwrap())
            .collect::<Vec<_>>();
        assert!(reserve(directory.path(), 0, 100).is_err());
        drop(reservations);
        assert!(reserve(directory.path(), 100, 100).is_ok());
    }

    #[test]
    fn resource_process() {
        let Ok(directory) = std::env::var("TERRA_TEST_ADMISSION") else {
            return;
        };
        let _reservation = reserve(Path::new(&directory), 50, 100).unwrap();
        if std::env::var_os("TERRA_TEST_CRASH").is_some() {
            #[cfg(unix)]
            rustix::process::setrlimit(
                rustix::process::Resource::Core,
                rustix::process::Rlimit {
                    current: Some(0),
                    maximum: Some(0),
                },
            )
            .unwrap();
            std::process::abort();
        }
        std::fs::write(Path::new(&directory).join("ready"), []).unwrap();
        let mut request = [0];
        std::io::stdin().read_exact(&mut request).unwrap();
        assert_eq!(request, [42]);
        std::fs::write(Path::new(&directory).join("responsive"), []).unwrap();
    }

    #[test]
    fn crashed_process_releases_admission_and_peer_remains_responsive() {
        use std::process::{Command, Stdio};
        let directory = tempfile::tempdir().unwrap();
        let child_command = || {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--exact",
                    "vm::resources::tests::resource_process",
                    "--nocapture",
                ])
                .env("TERRA_TEST_ADMISSION", directory.path())
                .env_remove("TERRA_TEST_CRASH")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            command
        };
        let mut peer = child_command().spawn().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !directory.path().join("ready").exists() {
            assert!(std::time::Instant::now() < deadline, "peer did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut crashed = child_command()
            .env("TERRA_TEST_CRASH", "1")
            .spawn()
            .unwrap();
        let status = loop {
            if let Some(status) = crashed.try_wait().unwrap() {
                break status;
            }
            if std::time::Instant::now() >= deadline {
                crashed.kill().unwrap();
                crashed.wait().unwrap();
                peer.kill().unwrap();
                peer.wait().unwrap();
                panic!("crashing process failed to exit");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert!(!status.success());
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            assert_eq!(status.signal(), Some(libc::SIGABRT));
        }
        let replacement = reserve(directory.path(), 50, 100).unwrap();
        assert!(reserve(directory.path(), 1, 100).is_err());
        peer.stdin.take().unwrap().write_all(&[42]).unwrap();
        assert!(peer.wait().unwrap().success());
        assert!(directory.path().join("responsive").exists());
        drop(replacement);
        assert!(reserve(directory.path(), 100, 100).is_ok());
    }

    #[test]
    fn reservations_bound_peers_and_release_on_close() {
        let directory = tempfile::tempdir().unwrap();
        let first = reserve(directory.path(), 60, 100).unwrap();
        assert!(reserve(directory.path(), 41, 100).is_err());
        let second = reserve(directory.path(), 40, 100).unwrap();
        assert!(reserve(directory.path(), 1, 100).is_err());
        drop(first);
        let replacement = reserve(directory.path(), 60, 100).unwrap();
        drop((second, replacement));
        assert!(reserve(directory.path(), 100, 100).is_ok());
    }
}
