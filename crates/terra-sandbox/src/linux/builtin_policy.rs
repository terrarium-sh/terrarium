pub(super) const SUPERVISOR_ROLE_FILTER: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/supervisor-role-filter.bpf"));
pub(super) const VM_ROLE_FILTER: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/vm-role-filter.bpf"));
pub(super) const NETWORK_ROLE_FILTER: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/network-role-filter.bpf"));
/// Empty for a target without a checked-in policy, such as a glibc development build.
pub(super) const SUPERVISOR_ALLOWLIST: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/supervisor-allowlist.bpf"));
pub(super) const VM_ALLOWLIST: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/vm-allowlist.bpf"));
pub(super) const NETWORK_ALLOWLIST: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/network-allowlist.bpf"));

#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod tests {
    use super::*;
    #[cfg(target_arch = "x86_64")]
    use std::os::unix::process::ExitStatusExt as _;

    const TIOCSTI: u32 = 0x5412;
    const TIOCLINUX: u32 = 0x541c;

    #[test]
    fn supervisor_role_filter_matches_native_rules() {
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
        let actual: Vec<_> = super::super::seccomp::decode_bpf(SUPERVISOR_ROLE_FILTER)
            .unwrap()
            .iter()
            .map(|filter| (filter.code, filter.jt, filter.jf, filter.k))
            .collect();
        assert_eq!(actual, expected);
    }

    #[test]
    fn filter_allows_getpid_and_denies_ptrace_in_child() {
        const CHILD: &str = "TERRA_BUILTIN_SECCOMP_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "linux::builtin_policy::tests::filter_allows_getpid_and_denies_ptrace_in_child",
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
                        "linux::builtin_policy::tests::filter_allows_getpid_and_denies_ptrace_in_child",
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

    /// A compiled allowlist kills the process on any unlisted syscall or `ioctl` request; listed
    /// calls reach the kernel and fail on their own merits.
    #[allow(unsafe_code)]
    #[test]
    fn compiled_allowlist_kills_unlisted_syscalls_and_ioctl_requests() {
        use std::os::unix::process::ExitStatusExt as _;
        const CHILD: &str = "TERRA_ALLOWLIST_TEST_CHILD";
        let Ok(mode) = std::env::var(CHILD) else {
            for (mode, signal) in [
                ("listed", None),
                ("unlisted", Some(libc::SIGSYS)),
                ("request", Some(libc::SIGSYS)),
            ] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "linux::builtin_policy::tests::compiled_allowlist_kills_unlisted_syscalls_and_ioctl_requests",
                    ])
                    .env(CHILD, mode)
                    .output()
                    .unwrap();
                assert_eq!(output.status.signal(), signal, "{mode}: {output:?}");
                if signal.is_none() {
                    assert!(output.status.success(), "{mode}: {output:?}");
                }
            }
            return;
        };
        let policy = terra_build::seccomp_policy::RolePolicy {
            syscalls: ["exit", "exit_group", "futex", "getpid", "ioctl"]
                .map(str::to_owned)
                .into(),
            ioctls: [u32::try_from(libc::FIONBIO).unwrap()].into(),
        };
        let architecture =
            terra_build::seccomp::Architecture::from_target(std::env::consts::ARCH, "little")
                .unwrap();
        let allowlist = terra_build::seccomp::compile_allowlist(architecture, &policy).unwrap();
        super::super::seccomp::install_filters(&[&allowlist]).unwrap();
        // SAFETY: getpid takes no pointers; the invalid descriptor keeps each ioctl from
        // dereferencing its argument, and _exit ends the process before any unlisted call.
        unsafe {
            assert!(libc::syscall(libc::SYS_getpid) > 0);
            match mode.as_str() {
                "listed" => {
                    assert_eq!(libc::ioctl(-1, libc::FIONBIO, 0), -1);
                    if *libc::__errno_location() != libc::EBADF {
                        libc::_exit(2);
                    }
                }
                "unlisted" => {
                    libc::syscall(libc::SYS_getppid);
                }
                "request" => {
                    libc::ioctl(-1, libc::TIOCGWINSZ, 0);
                }
                mode => panic!("invalid allowlist test mode: {mode}"),
            }
            libc::_exit(0);
        }
    }

    #[test]
    fn worker_filters_separate_native_network_and_virtualization_authority() {
        const CHILD: &str = "TERRA_ROLE_BUILTIN_TEST_CHILD";
        let Ok(role) = std::env::var(CHILD) else {
            for role in ["vm", "network"] {
                let output = std::process::Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "linux::builtin_policy::tests::worker_filters_separate_native_network_and_virtualization_authority",
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
            "vm" => VM_ROLE_FILTER,
            "network" => NETWORK_ROLE_FILTER,
            role => panic!("invalid built-in role: {role}"),
        };
        super::super::seccomp::install_filters(&[filter]).unwrap();
        std::os::unix::net::UnixStream::pair().unwrap();
        probe_preserved_worker_lifetime();
        probe_denied_terminal_injection();
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0));
        assert_eq!(listener.unwrap_err().raw_os_error(), Some(libc::EPERM));
        if role == "vm" {
            probe_denied_vm_listeners_and_outgoing_sockets();
        } else {
            std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
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
        for (family, kind) in [
            (libc::AF_UNIX, libc::SOCK_DGRAM),
            (libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC),
            (libc::AF_INET, libc::SOCK_STREAM),
        ] {
            let mut pair = [-1; 2];
            // SAFETY: `pair` is a live two-descriptor buffer, and the filter must refuse the call.
            assert_eq!(
                unsafe { libc::socketpair(family, kind, 0, pair.as_mut_ptr()) },
                -1
            );
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
    fn probe_denied_vm_listeners_and_outgoing_sockets() {
        for syscall in [
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_connect,
            libc::SYS_sendmsg,
            libc::SYS_sendmmsg,
        ] {
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
        super::super::seccomp::install_filters(&[SUPERVISOR_ROLE_FILTER]).unwrap();
        // SAFETY: these syscalls take no pointers.
        unsafe {
            assert!(libc::syscall(libc::SYS_getpid) > 0);
            #[cfg(target_arch = "x86_64")]
            if std::env::var("TERRA_BUILTIN_SECCOMP_TEST_CHILD").unwrap() == "x32" {
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
}
