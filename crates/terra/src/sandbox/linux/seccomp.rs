use anyhow::{Context as _, Result, ensure};
use seccompiler::{BpfProgram, BpfProgramRef, sock_filter};
use std::io::Read as _;
use std::path::Path;

const MAX_BPF_BYTES: usize = 4096 * 8;

pub(crate) fn resolve_policy(policy: Option<&Path>, allow_fallback: bool) -> Result<Vec<u8>> {
    if let Some(path) = policy {
        return read_policy(path);
    }
    ensure!(
        allow_fallback,
        "a seccomp policy is required (vm.bwrap.allow_fallback: false); set vm.bwrap.policy or provide ~/.terra/config/seccomp.bpf"
    );
    Ok(super::DEFAULT_POLICY.to_vec())
}

pub(crate) fn read_policy(path: &Path) -> Result<Vec<u8>> {
    let file = crate::sys::open_regular_file(path)
        .with_context(|| format!("opening seccomp policy {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((MAX_BPF_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    validate_bpf(&bytes).with_context(|| format!("invalid seccomp policy {}", path.display()))?;
    Ok(bytes)
}

pub(crate) fn install_policy(bytes: &[u8]) -> Result<()> {
    seccompiler::apply_filter_all_threads(&decode_bpf(bytes)?)
        .context("installing workload seccomp policy")
}

pub(super) fn validate_bpf(bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_BPF_BYTES && bytes.len().is_multiple_of(8),
        "expected raw classic BPF: 1–4096 instructions of 8 bytes each"
    );
    Ok(())
}

pub(crate) fn encode_bpf(program: BpfProgramRef<'_>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(program.len() * 8);
    for instruction in program {
        bytes.extend_from_slice(&instruction.code.to_le_bytes());
        bytes.extend_from_slice(&[instruction.jt, instruction.jf]);
        bytes.extend_from_slice(&instruction.k.to_le_bytes());
    }
    bytes
}

pub(crate) fn decode_bpf(bytes: &[u8]) -> Result<BpfProgram> {
    validate_bpf(bytes)?;
    Ok(bytes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|bytes| sock_filter {
            code: u16::from_le_bytes([bytes[0], bytes[1]]),
            jt: bytes[2],
            jf: bytes[3],
            k: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_policy_is_authoritative_and_never_falls_back_on_error() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.bpf");
        let bpf = super::super::DEFAULT_POLICY;
        std::fs::write(&path, bpf).unwrap();
        for allow_fallback in [false, true] {
            assert_eq!(resolve_policy(Some(&path), allow_fallback).unwrap(), bpf);
        }
        for invalid in [Vec::new(), vec![0; 7], vec![0; 4096 * 8 + 8]] {
            std::fs::write(&path, invalid).unwrap();
            assert!(resolve_policy(Some(&path), true).is_err());
        }
        std::fs::remove_file(&path).unwrap();
        assert!(resolve_policy(Some(&path), true).is_err());
        assert!(resolve_policy(None, false).is_err());
        assert_eq!(resolve_policy(None, true).unwrap(), bpf);
    }

    #[test]
    fn raw_bpf_round_trips_without_native_padding_or_endianness() -> Result<()> {
        let bytes = [0x15, 0, 2, 3, 0x78, 0x56, 0x34, 0x12];
        let program = decode_bpf(&bytes)?;
        assert_eq!(program[0].code, 0x15);
        assert_eq!((program[0].jt, program[0].jf), (2, 3));
        assert_eq!(program[0].k, 0x1234_5678);
        assert_eq!(encode_bpf(&program), bytes);
        for invalid in [Vec::new(), vec![0; 7], vec![0; 4096 * 8 + 8]] {
            assert!(decode_bpf(&invalid).is_err());
        }
        Ok(())
    }

    #[test]
    fn policy_files_reject_directories_and_fifos_without_blocking() {
        use std::sync::mpsc;
        use std::time::Duration;

        let directory = tempfile::tempdir().unwrap();
        assert!(read_policy(directory.path()).is_err());
        let path = directory.path().join("policy.bpf");
        rustix::fs::mkfifoat(
            rustix::fs::CWD,
            &path,
            rustix::fs::Mode::from_raw_mode(0o600),
        )
        .unwrap();
        let (send, receive) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = send.send(read_policy(&path));
        });
        assert!(
            receive
                .recv_timeout(Duration::from_secs(1))
                .unwrap()
                .is_err()
        );
    }
}
