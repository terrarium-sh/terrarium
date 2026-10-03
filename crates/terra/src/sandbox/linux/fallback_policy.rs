pub(super) const BPF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/default-seccomp.bpf"));

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::*;
    #[cfg(target_arch = "x86_64")]
    use std::os::unix::process::ExitStatusExt as _;

    #[test]
    fn embedded_filter_matches_native_denylist() {
        #[cfg(target_arch = "x86_64")]
        let audit_arch = 0xc000_003e;
        #[cfg(target_arch = "aarch64")]
        let audit_arch = 0xc000_00b7;
        let load_word = u16::try_from(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS).unwrap();
        let equal = u16::try_from(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K).unwrap();
        let return_value = u16::try_from(libc::BPF_RET | libc::BPF_K).unwrap();
        let mut expected = vec![
            (load_word, 0, 0, 4),
            (equal, 1, 0, audit_arch),
            (return_value, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
            (load_word, 0, 0, 0),
        ];
        #[cfg(target_arch = "x86_64")]
        expected.extend([
            (
                u16::try_from(libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K).unwrap(),
                0,
                1,
                0x4000_0000,
            ),
            (return_value, 0, 0, libc::SECCOMP_RET_KILL_PROCESS),
        ]);
        for syscall in [
            linux_raw_sys::general::__NR_ptrace,
            linux_raw_sys::general::__NR_bpf,
            linux_raw_sys::general::__NR_perf_event_open,
            linux_raw_sys::general::__NR_kexec_load,
            linux_raw_sys::general::__NR_kexec_file_load,
            linux_raw_sys::general::__NR_init_module,
            linux_raw_sys::general::__NR_finit_module,
            linux_raw_sys::general::__NR_delete_module,
            linux_raw_sys::general::__NR_reboot,
            linux_raw_sys::general::__NR_add_key,
            linux_raw_sys::general::__NR_request_key,
            linux_raw_sys::general::__NR_keyctl,
        ] {
            expected.push((equal, 0, 1, syscall));
            expected.push((
                return_value,
                0,
                0,
                libc::SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap(),
            ));
        }
        expected.push((return_value, 0, 0, libc::SECCOMP_RET_ALLOW));
        assert!(BPF.len().is_multiple_of(8));
        let actual: Vec<_> = decode_instructions()
            .iter()
            .map(|filter| (filter.code, filter.jt, filter.jf, filter.k))
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn filter_allows_getpid_and_denies_ptrace_in_child() {
        const CHILD: &str = "TERRA_FALLBACK_SECCOMP_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "sandbox::linux::fallback_policy::tests::filter_allows_getpid_and_denies_ptrace_in_child",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            #[cfg(target_arch = "x86_64")]
            {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "sandbox::linux::fallback_policy::tests::filter_allows_getpid_and_denies_ptrace_in_child",
                    ])
                    .env(CHILD, "x32")
                    .output()
                    .unwrap();
                assert_eq!(output.status.signal(), Some(libc::SIGSYS));
            }
            return;
        }

        install_and_probe();
    }

    #[allow(unsafe_code)]
    fn install_and_probe() {
        let filters = decode_instructions();
        let program = libc::sock_fprog {
            len: filters.len().try_into().unwrap(),
            filter: filters.as_ptr().cast_mut(),
        };

        // SAFETY: The program points to live filters for the duration of prctl, and syscall arguments match their Linux ABI.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &raw const program
                ),
                0
            );
            assert!(libc::syscall(libc::SYS_getpid) > 0);
            #[cfg(target_arch = "x86_64")]
            if std::env::var("TERRA_FALLBACK_SECCOMP_TEST_CHILD").unwrap() == "x32" {
                libc::syscall(libc::SYS_getpid | 0x4000_0000);
                panic!("x32 syscall was not killed");
            }
            assert_eq!(
                libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0),
                -1
            );
        }
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
    }

    fn decode_instructions() -> Vec<libc::sock_filter> {
        BPF.as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| libc::sock_filter {
                code: u16::from_ne_bytes([chunk[0], chunk[1]]),
                jt: chunk[2],
                jf: chunk[3],
                k: u32::from_ne_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]),
            })
            .collect()
    }
}
