use anyhow::{Context as _, Result, ensure};
use seccompiler::{BpfProgram, sock_filter};

const MAX_BPF_BYTES: usize = 4096 * 8;

/// The role's built-in filter: dangerous interfaces and argument rules, on every build.
pub(super) const fn role_filter(role: crate::Role) -> &'static [u8] {
    use super::builtin_policy::{NETWORK_ROLE_FILTER, SUPERVISOR_ROLE_FILTER, VM_ROLE_FILTER};
    match role {
        crate::Role::Supervisor => SUPERVISOR_ROLE_FILTER,
        crate::Role::Vm => VM_ROLE_FILTER,
        crate::Role::Network => NETWORK_ROLE_FILTER,
    }
}

/// The role's syscall allowlist, or `None` for a target without a checked-in policy.
fn role_allowlist(role: crate::Role) -> Option<&'static [u8]> {
    use super::builtin_policy::{NETWORK_ALLOWLIST, SUPERVISOR_ALLOWLIST, VM_ALLOWLIST};
    let allowlist = match role {
        crate::Role::Supervisor => SUPERVISOR_ALLOWLIST,
        crate::Role::Vm => VM_ALLOWLIST,
        crate::Role::Network => NETWORK_ALLOWLIST,
    };
    (!allowlist.is_empty()).then_some(allowlist)
}

/// Confines every thread of the calling role process to the rest of its built-in policy.
/// Bubblewrap already installed a worker's role filter, so a worker adds only its allowlist; the
/// supervisor, which no launcher confines, installs both.
pub fn restrict_role(role: crate::Role) -> Result<()> {
    let role_filter = (role == crate::Role::Supervisor).then(|| role_filter(role));
    let filters: Vec<_> = role_filter
        .into_iter()
        .chain(role_allowlist(role))
        .collect();
    install_filters(&filters)
}

pub(super) fn install_filters(filters: &[&[u8]]) -> Result<()> {
    for filter in filters {
        seccompiler::apply_filter_all_threads(&decode_bpf(filter)?)
            .context("installing seccomp filter")?;
    }
    Ok(())
}

pub(super) fn validate_bpf(bytes: &[u8]) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_BPF_BYTES && bytes.len().is_multiple_of(8),
        "expected raw classic BPF: 1–4096 instructions of 8 bytes each"
    );
    Ok(())
}

pub(super) fn decode_bpf(bytes: &[u8]) -> Result<BpfProgram> {
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
    fn raw_bpf_decodes_without_native_padding_or_endianness() -> Result<()> {
        let bytes = [0x15, 0, 2, 3, 0x78, 0x56, 0x34, 0x12];
        let program = decode_bpf(&bytes)?;
        assert_eq!(program[0].code, 0x15);
        assert_eq!((program[0].jt, program[0].jf), (2, 3));
        assert_eq!(program[0].k, 0x1234_5678);
        for invalid in [Vec::new(), vec![0; 7], vec![0; 4096 * 8 + 8]] {
            assert!(decode_bpf(&invalid).is_err());
        }
        Ok(())
    }

    /// A target with a checked-in policy carries an allowlist for every role; a glibc build has
    /// none.
    #[test]
    fn musl_targets_carry_an_allowlist_for_every_role() {
        for role in crate::Role::ALL {
            assert_eq!(role_allowlist(role).is_some(), cfg!(target_env = "musl"));
        }
    }
}
