use anyhow::{Context as _, Result, ensure};
use std::io::Read as _;
use std::path::{Path, PathBuf};

const MAX_BPF_BYTES: u64 = 4096 * 8;

pub(super) fn find_override_policy() -> Result<Option<PathBuf>> {
    let path = crate::state::get_terra_home_path()?.join("config/seccomp.bpf");
    match std::fs::symlink_metadata(&path) {
        Ok(_) => Ok(Some(path)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("checking seccomp policy {}", path.display()))
        }
    }
}

pub(crate) struct ResolvedPolicy {
    pub(crate) bpf: Vec<u8>,
}

pub(crate) fn resolve(policy: Option<&Path>, allow_fallback: bool) -> Result<ResolvedPolicy> {
    if let Some(path) = policy {
        return read_policy(path)
            .with_context(|| format!("invalid seccomp policy {}", path.display()));
    }
    ensure!(
        allow_fallback,
        "a seccomp policy is required (vm.bwrap.allow_fallback: false); set vm.bwrap.policy or provide ~/.terra/config/seccomp.bpf"
    );
    Ok(ResolvedPolicy {
        bpf: super::fallback_policy::BPF.to_vec(),
    })
}

fn read_policy(path: &Path) -> Result<ResolvedPolicy> {
    let file = crate::sys::open_regular_file(path)
        .with_context(|| format!("opening {}", path.display()))?;
    let mut bpf = Vec::new();
    file.take(MAX_BPF_BYTES + 1).read_to_end(&mut bpf)?;
    ensure!(
        !bpf.is_empty() && bpf.len() as u64 <= MAX_BPF_BYTES && bpf.len().is_multiple_of(8),
        "expected raw classic BPF: 1–4096 instructions of 8 bytes each"
    );
    Ok(ResolvedPolicy { bpf })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_policy_is_authoritative_and_never_falls_back_on_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.bpf");
        let bpf = super::super::fallback_policy::BPF;
        std::fs::write(&path, bpf).unwrap();
        for allow_fallback in [false, true] {
            assert_eq!(resolve(Some(&path), allow_fallback).unwrap().bpf, bpf);
        }
        for invalid in [
            Vec::new(),
            vec![0; 7],
            vec![0; usize::try_from(MAX_BPF_BYTES).unwrap() + 8],
        ] {
            std::fs::write(&path, invalid).unwrap();
            assert!(resolve(Some(&path), true).is_err());
        }
        std::fs::remove_file(&path).unwrap();
        assert!(resolve(Some(&path), true).is_err());
        assert!(resolve(None, false).is_err());
        assert_eq!(resolve(None, true).unwrap().bpf, bpf);
    }

    #[test]
    fn nonregular_policy_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        assert!(resolve(Some(directory.path()), true).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fifo_policy_is_rejected_without_blocking() {
        use std::sync::mpsc;
        use std::time::Duration;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.bpf");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap();

        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = send.send(resolve(Some(&path), true));
        });
        assert!(
            receive
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .is_err()
        );
    }
}
