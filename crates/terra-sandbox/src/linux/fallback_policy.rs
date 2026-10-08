pub(super) const SUPERVISOR: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/supervisor-seccomp.bpf"));
pub(super) const VM: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/vm-seccomp.bpf"));
pub(super) const NETWORK: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/network-seccomp.bpf"));
#[cfg(test)]
const BPF: &[u8] = SUPERVISOR;

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::*;
    #[cfg(target_arch = "x86_64")]
    use std::os::unix::process::ExitStatusExt as _;

    const TIOCSTI: u32 = 0x5412;
    const TIOCLINUX: u32 = 0x541c;

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
        expected.extend([
            (equal, 0, 4, u32::try_from(libc::SYS_ioctl).unwrap()),
            (load_word, 0, 0, 24),
            (equal, 1, 0, TIOCSTI),
            (equal, 0, 1, TIOCLINUX),
            (
                return_value,
                0,
                0,
                libc::SECCOMP_RET_ERRNO | u32::try_from(libc::EPERM).unwrap(),
            ),
            (load_word, 0, 0, 0),
        ]);
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
                    "linux::fallback_policy::tests::filter_allows_getpid_and_denies_ptrace_in_child",
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
                        "linux::fallback_policy::tests::filter_allows_getpid_and_denies_ptrace_in_child",
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

    #[test]
    fn worker_filters_separate_native_network_and_virtualization_authority() {
        const CHILD: &str = "TERRA_ROLE_FALLBACK_TEST_CHILD";
        let Ok(role) = std::env::var(CHILD) else {
            for role in ["vm", "network"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "linux::fallback_policy::tests::worker_filters_separate_native_network_and_virtualization_authority",
                    ])
                    .env(CHILD, role)
                    .output()
                    .unwrap();
                assert!(
                    output.status.success(),
                    "{role}: {}\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            return;
        };
        let filter = match role.as_str() {
            "vm" => VM,
            "network" => NETWORK,
            role => panic!("invalid fallback role: {role}"),
        };
        super::super::seccomp::install_policy(filter).unwrap();
        std::os::unix::net::UnixStream::pair().unwrap();
        probe_preserved_worker_lifetime();
        probe_denied_terminal_injection();
        let network = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0));
        if role == "vm" {
            assert_eq!(network.unwrap_err().raw_os_error(), Some(libc::EPERM));
            probe_denied_vm_outgoing_sockets();
        } else {
            network.unwrap();
            probe_denied_kvm_ioctls();
            probe_broker_socket_families();
        }
    }

    #[allow(unsafe_code)]
    fn probe_broker_socket_families() {
        for (family, kind) in [
            (libc::AF_UNIX, libc::SOCK_STREAM),
            (libc::AF_NETLINK, libc::SOCK_RAW),
        ] {
            // SAFETY: socket takes no pointers, and the filter must refuse it.
            assert_eq!(unsafe { libc::socket(family, kind, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        }
        // SAFETY: socket takes no pointers; the descriptor is closed immediately.
        unsafe {
            let ipv6 = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0);
            assert!(ipv6 >= 0, "{}", std::io::Error::last_os_error());
            libc::close(ipv6);
        }
    }

    #[allow(unsafe_code)]
    fn probe_preserved_worker_lifetime() {
        // SAFETY: these process-local operations take no pointers and the filter must deny all changes.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_PDEATHSIG, 0, 0, 0, 0), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
            assert_eq!(libc::setsid(), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
            assert_eq!(libc::setpgid(0, 0), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
            assert_eq!(libc::syscall(libc::SYS_io_uring_setup, 0, 0), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        }
    }

    #[allow(unsafe_code)]
    fn probe_denied_vm_outgoing_sockets() {
        for syscall in [libc::SYS_connect, libc::SYS_sendmsg, libc::SYS_sendmmsg] {
            // SAFETY: an invalid descriptor and null pointers have no external effects even if a filter regresses.
            assert_eq!(unsafe { libc::syscall(syscall, -1, 0, 0, 0, 0, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        }
        for (address, length) in [(1_u64, 0_u64), (1 << 32, 0), (0, 1), (0, 1 << 32)] {
            // SAFETY: the invalid descriptor prevents sendto from dereferencing the deliberately invalid address.
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_sendto, -1, 0, 0, 0, address, length) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        }
        // SAFETY: the invalid descriptor and null address make this allowed call fail without external effects.
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_sendto, -1, 0, 0, 0, 0_u64, 0_u64) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[allow(unsafe_code)]
    fn probe_denied_kvm_ioctls() {
        for request in [0xae00_u32, 0xae01, 0x4008_ae46, 0xc008_ae05] {
            // SAFETY: the invalid descriptor prevents ioctl from dereferencing the unused argument.
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_ioctl, -1, u64::from(request), 0) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        }
        // SAFETY: the invalid descriptor prevents ioctl from dereferencing the unused argument.
        assert_eq!(unsafe { libc::ioctl(-1, libc::FIONBIO, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EBADF)
        );
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
        probe_denied_terminal_injection();
    }

    /// Without the denial, a confined process holding `/dev/tty` could push
    /// input into the host shell; both requests fail before the descriptor is checked.
    #[allow(unsafe_code)]
    fn probe_denied_terminal_injection() {
        for request in [TIOCSTI, TIOCLINUX] {
            // SAFETY: the invalid descriptor prevents ioctl from dereferencing the unused argument.
            assert_eq!(
                unsafe { libc::syscall(libc::SYS_ioctl, -1, u64::from(request), 0) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EPERM)
            );
        }
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
