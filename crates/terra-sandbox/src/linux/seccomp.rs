use anyhow::{Context as _, Result, ensure};
use seccompiler::{BpfProgram, BpfProgramRef, sock_filter};
use std::io::Read as _;
use std::path::Path;

const MAX_BPF_BYTES: usize = 4096 * 8;
pub const BUNDLE_FORMAT_VERSION: u32 = 1;

pub fn resolve_policy(policy: Option<&Path>, allow_fallback: bool) -> Result<crate::PolicyBundle> {
    if let Some(path) = policy {
        return read_bundle(path);
    }
    ensure!(
        allow_fallback,
        "a seccomp bundle is required (vm.bwrap.allow_fallback: false); set vm.bwrap.policy to a generated bundle directory or provide ~/.terra/config/seccomp"
    );
    Ok(crate::PolicyBundle {
        supervisor: super::fallback_policy::SUPERVISOR.to_vec(),
        vm: super::fallback_policy::VM.to_vec(),
        network: super::fallback_policy::NETWORK.to_vec(),
    })
}

fn read_bundle(path: &Path) -> Result<crate::PolicyBundle> {
    ensure!(
        path.is_dir(),
        "seccomp policy {} is not a bundle directory; run `terra self-test --generate-policy` and set vm.bwrap.policy to the generated bundle directory",
        path.display()
    );
    let file = terra_platform::filesystem::open_regular_file(&path.join("manifest.json"))?;
    let mut bytes = Vec::new();
    file.take(256 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 256 * 1024,
        "seccomp manifest exceeds 256 KiB"
    );
    let manifest: serde_json::Value = serde_json::from_slice(&bytes)?;
    ensure!(
        manifest["format_version"] == BUNDLE_FORMAT_VERSION
            && manifest["target"] == env!("TERRA_BUILD_TARGET"),
        "invalid or incompatible seccomp bundle manifest"
    );
    let mut policies = Vec::new();
    for role in crate::Role::ALL {
        let bytes = read_policy(&path.join(format!("{}.seccomp.bpf", role.name())))?;
        ensure!(
            manifest["roles"][role.name()]["bpf_sha256"] == hash_bytes(&bytes),
            "seccomp {} policy hash does not match the manifest",
            role.name()
        );
        policies.push(bytes);
    }
    let [supervisor, vm, network]: [Vec<u8>; 3] = policies
        .try_into()
        .map_err(|_| anyhow::anyhow!("missing seccomp role"))?;
    Ok(crate::PolicyBundle {
        supervisor,
        vm,
        network,
    })
}

pub fn read_policy(path: &Path) -> Result<Vec<u8>> {
    let file = terra_platform::filesystem::open_regular_file(path)
        .with_context(|| format!("opening seccomp policy {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take((MAX_BPF_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    validate_bpf(&bytes).with_context(|| format!("invalid seccomp policy {}", path.display()))?;
    Ok(bytes)
}

pub fn install_policy(bytes: &[u8]) -> Result<()> {
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

#[must_use]
pub fn encode_bpf(program: BpfProgramRef<'_>) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(program.len() * 8);
    for instruction in program {
        bytes.extend_from_slice(&instruction.code.to_le_bytes());
        bytes.extend_from_slice(&[instruction.jt, instruction.jf]);
        bytes.extend_from_slice(&instruction.k.to_le_bytes());
    }
    bytes
}

pub fn decode_bpf(bytes: &[u8]) -> Result<BpfProgram> {
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

#[must_use]
pub fn hash_bytes(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    use std::fmt::Write as _;
    let mut encoded = String::with_capacity(64);
    for byte in sha2::Sha256::digest(bytes) {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_bundle_or_invalid_policy_never_falls_back() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.bpf");
        let bpf = super::super::DEFAULT_POLICY;
        std::fs::write(&path, bpf).unwrap();
        for allow_fallback in [false, true] {
            assert!(resolve_policy(Some(&path), allow_fallback).is_err());
        }
        for invalid in [Vec::new(), vec![0; 7], vec![0; 4096 * 8 + 8]] {
            std::fs::write(&path, invalid).unwrap();
            assert!(resolve_policy(Some(&path), true).is_err());
        }
        std::fs::remove_file(&path).unwrap();
        assert!(resolve_policy(Some(&path), true).is_err());
        assert!(resolve_policy(None, false).is_err());
        assert_eq!(resolve_policy(None, true).unwrap().supervisor, bpf);
    }

    #[test]
    fn role_bundle_requires_every_policy_and_its_manifest_hash() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let builtins = resolve_policy(None, true)?;
        let mut roles = serde_json::Map::new();
        for role in crate::Role::ALL {
            let bytes = builtins.get(role);
            std::fs::write(
                directory
                    .path()
                    .join(format!("{}.seccomp.bpf", role.name())),
                bytes,
            )?;
            roles.insert(
                role.name().into(),
                serde_json::json!({
                    "bpf_sha256": hash_bytes(bytes)
                }),
            );
        }
        let manifest = serde_json::json!({
            "format_version": BUNDLE_FORMAT_VERSION,
            "target": env!("TERRA_BUILD_TARGET"),
            "roles": roles,
        });
        let manifest_path = directory.path().join("manifest.json");
        std::fs::write(&manifest_path, serde_json::to_vec(&manifest)?)?;
        let loaded = resolve_policy(Some(directory.path()), false)?;
        for role in crate::Role::ALL {
            assert_eq!(loaded.get(role), builtins.get(role));
            let path = directory
                .path()
                .join(format!("{}.seccomp.bpf", role.name()));
            std::fs::remove_file(&path)?;
            assert!(resolve_policy(Some(directory.path()), true).is_err());
            std::fs::write(&path, builtins.get(role))?;
            let mut changed = builtins.get(role).to_vec();
            changed[0] ^= 1;
            std::fs::write(&path, changed)?;
            assert!(resolve_policy(Some(directory.path()), true).is_err());
            std::fs::write(path, builtins.get(role))?;
        }
        for (field, value) in [
            ("format_version", serde_json::json!(2)),
            ("target", serde_json::json!("invalid-target")),
        ] {
            let mut incompatible = manifest.clone();
            incompatible[field] = value;
            std::fs::write(&manifest_path, serde_json::to_vec(&incompatible)?)?;
            assert!(resolve_policy(Some(directory.path()), true).is_err());
        }
        Ok(())
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
