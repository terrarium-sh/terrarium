//! Portable release acceptance through the host's native hypervisor.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

struct BoxFixture {
    terra: PathBuf,
    project: PathBuf,
    home: PathBuf,
    directory: tempfile::TempDir,
}

impl BoxFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let project = directory.path().join("project");
        let home = directory.path().join("home");
        std::fs::create_dir(&project).unwrap();
        std::fs::create_dir(&home).unwrap();
        std::fs::create_dir(home.join(".terra")).unwrap();
        std::fs::write(home.join(".terra/config.yaml"), "vm:\n  init: direct\n").unwrap();
        Self {
            terra: std::env::var_os("TERRA_BIN")
                .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_terra")), PathBuf::from),
            project,
            home,
            directory,
        }
    }

    fn run(&self, arguments: &[&str]) -> (ExitStatus, String) {
        let output = tempfile::NamedTempFile::new_in(self.directory.path()).unwrap();
        let mut child = Command::new(&self.terra)
            .arg("--project")
            .arg(&self.project)
            .args(arguments)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(output.as_file().try_clone().unwrap())
            .stderr(output.as_file().try_clone().unwrap())
            .spawn()
            .expect("starting terra");
        let deadline = Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return (status, std::fs::read_to_string(output.path()).unwrap());
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let diagnostics = self.diagnostics();
                let cleanup = self.force_remove();
                panic!(
                    "terra {arguments:?} timed out:\n{}\nguest diagnostics:\n{diagnostics}\ncleanup:\n{cleanup}",
                    std::fs::read_to_string(output.path()).unwrap(),
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn diagnostics(&self) -> String {
        std::fs::read_dir(self.home.join(".terra/box"))
            .into_iter()
            .flatten()
            .flatten()
            .map(|project| project.path().join("native/diagnostics.log"))
            .filter_map(|path| std::fs::read_to_string(path).ok())
            .collect()
    }

    fn force_remove(&self) -> String {
        let output = Command::new(&self.terra)
            .args(["native", "rm", "--force", "-t", "0"])
            .arg("--project")
            .arg(&self.project)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .output();
        match output {
            Ok(output) => format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => format!("could not remove timed-out VM: {error}"),
        }
    }

    fn successful(&self, arguments: &[&str]) -> String {
        let (status, output) = self.run(arguments);
        if !status.success() {
            let (_, mut diagnostics) = self.run(&["native", "logs"]);
            diagnostics.push_str(&self.diagnostics());
            panic!("terra {arguments:?}: {status}\n{output}\n{diagnostics}");
        }
        output
    }
}

impl Drop for BoxFixture {
    fn drop(&mut self) {
        let _ = self.run(&["stop", "-t", "5"]);
    }
}

#[test]
#[ignore = "requires a release binary and usable KVM, Hypervisor.framework, or WHP"]
fn bake_hook_output_uses_the_console_and_agent_diagnostics_use_the_log() {
    let fixture = BoxFixture::new();
    let recipe = fixture.directory.path().join("native.yaml");
    let config = serde_json::json!({
        "hw": {"cpus": 1, "mem_mib": 256},
        "hooks": {"on_create": ["echo BAKE_STDOUT; echo BAKE_STDERR >&2"]}
    });
    std::fs::write(&recipe, yaml_serde::to_string(&config).unwrap()).unwrap();
    let output = fixture.successful(&[recipe.to_str().unwrap(), "setup"]);
    assert!(output.contains("BAKE_STDOUT"), "{output}");
    assert!(output.contains("BAKE_STDERR"), "{output}");
    let diagnostics = fixture.diagnostics();
    assert!(
        diagnostics.contains("agent received boot plan"),
        "{diagnostics}"
    );
    assert!(!diagnostics.contains("BAKE_STDOUT"), "{diagnostics}");
    assert!(!diagnostics.contains("BAKE_STDERR"), "{diagnostics}");
    assert!(!output.contains("agent received boot plan"), "{output}");
}

#[test]
#[ignore = "requires a release binary and usable KVM, Hypervisor.framework, or WHP"]
fn native_boot_executes_shell() {
    for cpus in [1, 2] {
        let fixture = BoxFixture::new();
        let recipe = fixture.directory.path().join("native.yaml");
        let config = serde_json::json!({
            "hw": {"cpus": cpus, "mem_mib": 256},
            "workload": {"entrypoint": "/bin/sleep", "args": ["300"]}
        });
        std::fs::write(&recipe, yaml_serde::to_string(&config).unwrap()).unwrap();
        fixture.successful(&[recipe.to_str().unwrap(), "setup"]);
        fixture.successful(&["native", "-d"]);
        let output = fixture.successful(&[
            "native",
            "exec",
            "--",
            "/bin/sh",
            "-ec",
            &format!(
                r#"test "$(nproc)" = {cpus}
                test "$(cat /sys/kernel/terra_socket_abi)" = {socket_abi}
                vsocks=0
                for device in /sys/bus/virtio/devices/*/device; do
                    if test "$(cat "$device")" = 0x0013; then vsocks=$((vsocks + 1)); fi
                done
                test "$vsocks" = 1
                test ! -e /sys/class/net/eth0
                test ! -e /dev/terra-agent-control
                test ! -e /dev/terra-network-control
                sleep 1
                echo BOOT_SHELL_OK"#,
                socket_abi = terra_protocol::socket::VERSION,
            ),
        ]);
        assert!(
            output.contains("BOOT_SHELL_OK"),
            "{cpus}-CPU guest did not produce the shell marker:\n{output}\nguest diagnostics:\n{}",
            fixture.diagnostics()
        );
        fixture.successful(&["native", "stop"]);
    }
}

#[test]
#[ignore = "requires a release binary and usable KVM, Hypervisor.framework, or WHP"]
fn native_boot_shares_host_changes_between_running_boxes() {
    let writer = BoxFixture::new();
    let reader = BoxFixture::new();
    let shared = writer.directory.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::write(shared.join("value"), "initial").unwrap();
    for (fixture, readonly) in [(&writer, false), (&reader, true)] {
        let recipe = fixture.directory.path().join("native.yaml");
        let config = serde_json::json!({
            "hw": {"cpus": 2, "mem_mib": 256},
            "mounts": [{"host": shared, "guest": "/shared", "readonly": readonly}],
            "workload": {"entrypoint": "/bin/sleep", "args": ["300"]}
        });
        std::fs::write(&recipe, yaml_serde::to_string(&config).unwrap()).unwrap();
        fixture.successful(&[recipe.to_str().unwrap(), "setup"]);
        fixture.successful(&["native", "-d"]);
    }
    reader.successful(&[
        "native",
        "exec",
        "--",
        "sh",
        "-ec",
        "test \"$(cat /shared/value)\" = initial; test ! -e /shared/new",
    ]);
    for generation in 0..8 {
        let value = format!("host-{generation}");
        std::fs::write(shared.join("replacement"), &value).unwrap();
        std::fs::rename(shared.join("replacement"), shared.join("value")).unwrap();
        std::fs::write(shared.join("new"), &value).unwrap();
        reader.successful(&[
            "native",
            "exec",
            "--",
            "sh",
            "-ec",
            &format!(
                "test \"$(cat /shared/value)\" = {value}; test \"$(cat /shared/new)\" = {value}"
            ),
        ]);
        writer.successful(&[
            "native",
            "exec",
            "--",
            "sh",
            "-ec",
            "printf guest > /shared/value; rm /shared/new; sync",
        ]);
        reader.successful(&[
            "native", "exec", "--", "sh", "-ec",
            "test \"$(cat /shared/value)\" = guest; test ! -e /shared/new; if echo forbidden > /shared/value; then exit 1; fi",
        ]);
        assert_eq!(
            std::fs::read_to_string(shared.join("value")).unwrap(),
            "guest"
        );
        assert!(!shared.join("new").exists());
    }
    writer.successful(&["native", "stop"]);
    reader.successful(&["native", "exec", "--", "cat", "/shared/value"]);
    reader.successful(&["native", "stop"]);
}

#[test]
#[ignore = "requires a release binary and usable KVM, Hypervisor.framework, or WHP"]
fn native_boot_runs_rootless_podman_on_a_private_disk() {
    run_rootless_podman_on_a_private_disk(None);
}

#[test]
#[ignore = "requires a release binary and usable KVM, Hypervisor.framework, or WHP"]
fn native_boot_runs_rootless_podman_with_slirp4netns_on_a_private_disk() {
    run_rootless_podman_on_a_private_disk(Some("slirp4netns"));
}

fn run_rootless_podman_on_a_private_disk(network: Option<&str>) {
    let fixture = BoxFixture::new();
    let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
    allowed.set_nonblocking(true).unwrap();
    let allowed_port = allowed.local_addr().unwrap().port();
    let denied = TcpListener::bind("127.0.0.1:0").unwrap();
    denied.set_nonblocking(true).unwrap();
    let denied_port = denied.local_addr().unwrap().port();
    let readonly = fixture.directory.path().join("readonly");
    std::fs::create_dir(&readonly).unwrap();
    std::fs::write(readonly.join("seed"), "HOST_SEED").unwrap();
    let large_body = vec![b'L'; 128 * 1024];
    std::fs::write(readonly.join("large"), &large_body).unwrap();
    let recipe = fixture.directory.path().join("native.yaml");
    let packages = if network.is_some() {
        " slirp4netns"
    } else {
        ""
    };
    let network_option = network.map_or(String::new(), |network| format!("--network={network} "));
    let helper_logging = if std::env::var_os("TERRA_SLIRP_DEBUG").is_some() {
        r#"case "${1:-}" in
--help|--version|-h|-v) exec /usr/bin/slirp4netns.real "$@" ;;
esac
export SLIRP_DEBUG=call,misc G_MESSAGES_DEBUG=all
exec >>/tmp/terra-slirp-helper.log 2>&1
"#
    } else {
        ""
    };
    let helper_wrapper = if network.is_some() {
        format!(
            r#"mv /usr/bin/slirp4netns /usr/bin/slirp4netns.real
cat > /usr/bin/slirp4netns <<'SLIRP_WRAPPER'
#!/bin/sh
{helper_logging}exec /usr/bin/slirp4netns.real "$@" 2>>/tmp/terra-slirp-helper.log
SLIRP_WRAPPER
chmod 755 /usr/bin/slirp4netns
"#
        )
    } else {
        String::new()
    };
    let on_create = format!(
        r"set -e
apk add --no-cache podman fuse-overlayfs{packages}
{helper_wrapper}d=/home/terri/rootfs
mkdir -p $d/bin $d/lib $d/etc $d/dev $d/proc $d/sys $d/tmp
chmod 1777 $d/tmp
cp -a /bin/busybox $d/bin
cp -aL /lib/* $d/lib
ln -s busybox $d/bin/sh
ln -s busybox $d/bin/sleep
ln -s busybox $d/bin/wget
tar -C $d -cf /home/terri/rootfs.tar .
rm -rf $d
chown 1000:1000 /home/terri/rootfs.tar"
    );
    let script = format!(
        r#"network_diagnostics() {{
status=$?
if test "$status" -eq 0; then return; fi
echo GUEST_RESOLVER
cat /etc/resolv.conf
if podman container exists rootless; then
echo CONTAINER_RESOLVER
podman exec rootless /bin/busybox cat /etc/resolv.conf || :
echo CONTAINER_NETWORK
podman inspect --format '{{{{.NetworkSettings}}}}' rootless || :
echo PODMAN_NETWORK_MODE
podman inspect --format '{{{{.HostConfig.NetworkMode}}}}' rootless || :
echo CONTAINER_NETNS
podman exec rootless /bin/busybox readlink /proc/self/ns/net || :
container_pid="$(podman inspect --format '{{{{.State.Pid}}}}' rootless)"
readlink /proc/"$container_pid"/ns/net || :
echo HELPER_PROCESSES
for process in /proc/[0-9]*; do
process_name="$(cat "$process/comm" 2>/dev/null)" || continue
case "$process_name" in slirp4netns*|conmon)
echo "$process $process_name"
/bin/busybox tr '\0' ' ' < "$process/cmdline" || :
echo
readlink "$process/ns/net" || :
ls -l "$process/fd" || :
if test -f "$process/fd/2"; then cat "$process/fd/2" 2>/dev/null || :; fi
;; esac
done
echo SLIRP_HELPER_STDERR
cat /tmp/terra-slirp-helper.log 2>/dev/null || :
echo CONTAINER_ADDRESSES
podman exec rootless /bin/busybox ip address || :
echo CONTAINER_ROUTES
podman exec rootless /bin/busybox ip route || :
echo GUEST_LOOKUP
/bin/busybox timeout 8 /bin/busybox nslookup gate.test || :
echo CONTAINER_LOOKUP
podman exec rootless /bin/busybox timeout 8 /bin/busybox nslookup gate.test 10.0.2.3 || :
fi
return "$status"
}}
trap network_diagnostics EXIT
test "$(id -u)" = 1000
test "$(stat -c %u /dev/net/tun)" = 0
test "$(stat -c %a /dev/net/tun)" = 666
test "$(stat -c '%u:%a' "$XDG_RUNTIME_DIR")" = 1000:700
test "$(stat -f -c %T /run)" = tmpfs
test ! -e "$XDG_RUNTIME_DIR/previous-boot"
touch "$XDG_RUNTIME_DIR/previous-boot"
test "$(podman info --format '{{{{.Host.CgroupManager}}}}')" = cgroupfs
if podman container exists rootless; then
test "$(podman inspect --format '{{{{.State.Status}}}}' rootless)" = exited
podman rm rootless
echo PODMAN_STORAGE_REUSED
else
podman import "$HOME/rootfs.tar" local
fi
podman run {network_option}-d --name rootless --volume /readonly:/readonly:ro local sleep 60
container_id="$(podman ps -aq --filter name=rootless)"
test -n "$container_id"
test -d /podman/containers/storage
test "$(podman exec rootless wget -q -T 10 -O - http://gate.test:{allowed_port}/)" = HOST_NETWORK
podman exec rootless wget -q -T 10 -O /tmp/large http://gate.test:{allowed_port}/
podman exec rootless /bin/busybox cmp /readonly/large /tmp/large
if podman exec rootless wget -q -T 10 -O /dev/null http://blocked.test:{denied_port}/; then exit 1; fi
if podman exec rootless wget -q -T 10 -O /dev/null http://169.254.169.254/; then exit 1; fi
test "$(podman exec rootless /bin/busybox cat /readonly/seed)" = HOST_SEED
if podman exec rootless sh -c 'echo nope > /readonly/new-file'; then exit 1; fi
podman stop rootless
test "$container_id" = "$(podman ps -aq --filter name=rootless --filter status=exited)"
if doas id -u; then exit 1; fi
echo ROOTLESS_PODMAN_OK"#
    );
    let config = serde_json::json!({
        "network": {
            "mode": "unrestricted-public",
            "allow": [format!("gate.test:{allowed_port}")],
            "hosts": [
                {"name": "gate.test", "addr": "HOST_LOOPBACK"},
                {"name": "blocked.test", "addr": "HOST_LOOPBACK"}
            ]
        },
        "env": {"XDG_DATA_HOME": "/podman"},
        "hooks": {"on_create": [on_create]},
        "volumes": [{"name": "podman", "guest": "/podman", "size_mib": 256}],
        "mounts": [{"host": readonly, "guest": "/readonly", "readonly": true}],
        "workload": {"entrypoint": "/bin/sh", "args": ["-exc", script]}
    });
    std::fs::write(&recipe, yaml_serde::to_string(&config).unwrap()).unwrap();
    fixture.successful(&[recipe.to_str().unwrap(), "setup"]);
    for boot in 0..2 {
        let server = allowed.try_clone().unwrap();
        let response_body = large_body.clone();
        let response = std::thread::spawn(move || {
            serve_request(&server, b"HOST_NETWORK");
            serve_request(&server, &response_body);
        });
        let output = fixture.successful(&["native", "--foreground"]);
        response.join().unwrap();
        assert!(output.contains("ROOTLESS_PODMAN_OK"), "{output}");
        assert_eq!(
            output.contains("PODMAN_STORAGE_REUSED"),
            boot == 1,
            "{output}"
        );
    }
    assert!(
        matches!(denied.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock),
        "guest reached an ungranted host-loopback service"
    );
    let logs = fixture.successful(&["native", "logs"]);
    assert!(
        logs.contains("egress: blocked") && logs.contains("169.254.169.254"),
        "metadata denial absent from logs:\n{logs}"
    );
}

fn serve_request(listener: &TcpListener, body: &[u8]) {
    let deadline = Instant::now() + Duration::from_mins(1);
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut request = [0; 4096];
                assert!(stream.read(&mut request).unwrap() > 0);
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(body).unwrap();
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "guest did not connect to host");
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("accepting guest connection: {error}"),
        }
    }
}

#[test]
#[ignore = "requires a release binary, a file-events probe or Zig, and usable KVM, Hypervisor.framework, or WHP"]
fn native_boot_forwards_shared_file_events() {
    let writer = BoxFixture::new();
    let reader = BoxFixture::new();
    let shared = writer.directory.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    let probe = shared.join("probe");
    prepare_file_events_probe(&probe);
    for (fixture, readonly) in [(&writer, false), (&reader, true)] {
        let recipe = fixture.directory.path().join("native.yaml");
        let config = serde_json::json!({
            "mounts": [{"host": shared, "guest": "/shared", "readonly": readonly}],
            "workload": {"entrypoint": "/bin/sleep", "args": ["300"]}
        });
        std::fs::write(&recipe, yaml_serde::to_string(&config).unwrap()).unwrap();
        fixture.successful(&[recipe.to_str().unwrap(), "setup"]);
        fixture.successful(&["native", "-d"]);
    }
    std::fs::create_dir(shared.join("nested")).unwrap();
    for (index, (name, expected)) in [
        ("value", "host"),
        ("value", "atomic"),
        ("value", "guest"),
        ("created", "new"),
        ("created", "absent"),
        ("nested/value", "nested"),
        ("value", "resumed"),
    ]
    .into_iter()
    .enumerate()
    {
        if index == 0 {
            std::fs::write(shared.join(name), "initial").unwrap();
        }
        let (parent, basename) = name.rsplit_once('/').unwrap_or(("", name));
        reader.successful(&["native", "exec", "--", "rm", "-f", "/tmp/event-ready"]);
        std::thread::scope(|scope| {
            let probe = scope.spawn(|| {
                reader.successful(&[
                    "native",
                    "exec",
                    "--",
                    "/shared/probe",
                    &format!("/shared/{parent}"),
                    basename,
                    "/tmp/event-ready",
                    expected,
                ])
            });
            reader.successful(&["native", "exec", "--", "sh", "-ec", "for i in $(seq 1 100); do test ! -e /tmp/event-ready || exit 0; sleep .1; done; exit 1"]);
            match index {
                0 | 3 | 5 => std::fs::write(shared.join(name), expected).unwrap(),
                1 => {
                    std::fs::write(shared.join("replacement"), expected).unwrap();
                    std::fs::rename(shared.join("replacement"), shared.join(name)).unwrap();
                }
                2 => {
                    assert_guest_write_notifies_host(&writer, &shared);
                }
                4 => std::fs::remove_file(shared.join(name)).unwrap(),
                6 => {
                    for value in 0..10_000 {
                        std::fs::write(shared.join("flood"), value.to_string()).unwrap();
                    }
                    let deadline = Instant::now() + Duration::from_secs(10);
                    while !probe.is_finished() && Instant::now() < deadline {
                        std::fs::write(shared.join(name), expected).unwrap();
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
                _ => unreachable!(),
            }
            let output = probe.join().unwrap();
            assert!(output.contains("FILE_EVENTS_OK"), "{output}");
        });
    }
    assert_eq!(
        std::fs::read_to_string(shared.join("value")).unwrap(),
        "resumed"
    );
    writer.successful(&["native", "stop"]);
    reader.successful(&["native", "stop"]);
}

fn prepare_file_events_probe(probe: &std::path::Path) {
    if let Some(prebuilt) = std::env::var_os("TERRA_FILE_EVENTS_PROBE") {
        std::fs::copy(prebuilt, probe).unwrap();
    } else {
        let status = Command::new("zig")
            .args([
                "cc",
                "-target",
                &format!("{}-linux-musl", std::env::consts::ARCH),
                "-static",
                "-O2",
                "-o",
            ])
            .arg(probe)
            .arg(
                std::env::var_os("TERRA_TEST_ASSETS")
                    .map_or_else(
                        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/assets"),
                        PathBuf::from,
                    )
                    .join("file_events_probe.c"),
            )
            .status()
            .unwrap();
        assert!(status.success());
    }
}

fn assert_guest_write_notifies_host(writer: &BoxFixture, shared: &std::path::Path) {
    use notify::Watcher as _;
    let (sender, receiver) = std::sync::mpsc::channel();
    let mut watcher = notify::recommended_watcher(sender).unwrap();
    watcher
        .watch(shared, notify::RecursiveMode::Recursive)
        .unwrap();
    writer.successful(&[
        "native",
        "exec",
        "--",
        "sh",
        "-ec",
        "printf guest > /shared/value",
    ]);
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let event = receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .unwrap()
            .unwrap();
        if !matches!(event.kind, notify::EventKind::Access(_))
            && event.paths.iter().any(|path| path.ends_with("value"))
        {
            break;
        }
    }
}

#[test]
#[ignore = "requires a release binary, package downloads, and usable KVM, Hypervisor.framework, or WHP"]
fn native_boot_reloads_node_server_from_host_events() {
    let fixture = BoxFixture::new();
    let shared = fixture.directory.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    let script = |value| {
        format!(
            "require('node:http').createServer((req,res)=>res.end('{value}')).listen(3000,'127.0.0.1');\n"
        )
    };
    std::fs::write(shared.join("server.js"), script("initial")).unwrap();
    let recipe = fixture.directory.path().join("native.yaml");
    let config = serde_json::json!({
        "network": {"mode": "unrestricted-public"},
        "hooks": {"on_create": ["apk add --no-cache nodejs"]},
        "mounts": [{"host": shared, "guest": "/shared", "readonly": true}],
        "workload": {"entrypoint": "/usr/bin/node", "args": ["--watch", "/shared/server.js"]}
    });
    std::fs::write(&recipe, yaml_serde::to_string(&config).unwrap()).unwrap();
    fixture.successful(&[recipe.to_str().unwrap(), "setup"]);
    fixture.successful(&["native", "-d"]);
    for value in ["initial", "edited", "replaced"] {
        if value == "edited" {
            std::fs::write(shared.join("server.js"), script(value)).unwrap();
        } else if value == "replaced" {
            std::fs::write(shared.join("replacement.js"), script(value)).unwrap();
            std::fs::rename(shared.join("replacement.js"), shared.join("server.js")).unwrap();
        }
        fixture.successful(&["native", "exec", "--", "sh", "-ec", &format!("for i in $(seq 1 150); do if test \"$(wget -q -T 1 -O - http://127.0.0.1:3000/ || true)\" = {value}; then exit 0; fi; sleep .1; done; exit 1")]);
    }
    fixture.successful(&["native", "stop"]);
}

#[cfg(windows)]
#[derive(serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct WindowsProcessRow {
    process_id: u32,
    parent_process_id: u32,
    name: String,
    command_line: Option<String>,
}

#[cfg(windows)]
fn windows_process_descendants(supervisor_pid: u32) -> Vec<WindowsProcessRow> {
    use std::os::windows::process::CommandExt as _;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    let script = format!(
        "$children = @(Get-CimInstance Win32_Process -Filter 'ParentProcessId = {supervisor_pid}' -ErrorAction Stop | Select-Object ProcessId,ParentProcessId,Name,CommandLine); $all = @($children); foreach ($child in $children) {{ $all += @(Get-CimInstance Win32_Process -Filter \"ParentProcessId = $($child.ProcessId)\" -ErrorAction Stop | Select-Object ProcessId,ParentProcessId,Name,CommandLine) }}; ConvertTo-Json -InputObject $all -Compress"
    );
    let output = Command::new("powershell")
        .creation_flags(CREATE_NO_WINDOW)
        .args(["-NoProfile", "-NonInteractive", "-Command", &script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "querying Windows worker processes: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[cfg(windows)]
struct WindowsProcessWatch {
    pid: u32,
    handle: std::os::windows::io::OwnedHandle,
}

#[cfg(windows)]
#[allow(unsafe_code)]
impl WindowsProcessWatch {
    fn open(pid: u32) -> Self {
        use std::os::windows::io::FromRawHandle as _;
        use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
        };

        // SAFETY: pid comes from this test's supervisor ancestry; the returned handle is owned.
        let handle = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZE,
                0,
                pid,
            )
        };
        assert!(
            !handle.is_null(),
            "opening process {pid}: {}",
            std::io::Error::last_os_error()
        );
        Self {
            pid,
            // SAFETY: OpenProcess returned a unique owned handle.
            handle: unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(handle) },
        }
    }

    fn is_running(&self) -> bool {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::WaitForSingleObject;

        // SAFETY: the process handle is live and zero waits only query status.
        let status = unsafe { WaitForSingleObject(self.handle.as_raw_handle(), 0) };
        assert!(
            status == WAIT_OBJECT_0 || status == WAIT_TIMEOUT,
            "querying process {}: {}",
            self.pid,
            std::io::Error::last_os_error()
        );
        status == WAIT_TIMEOUT
    }

    fn terminate(&self) {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::System::Threading::TerminateProcess;

        // SAFETY: the retained handle pins this exact process rather than a reused PID.
        assert_ne!(
            unsafe { TerminateProcess(self.handle.as_raw_handle(), 1) },
            0,
            "terminating process {}: {}",
            self.pid,
            std::io::Error::last_os_error()
        );
    }

    fn wait_exited(&self, deadline: Instant) {
        while self.is_running() {
            assert!(
                Instant::now() < deadline,
                "process {} survived teardown",
                self.pid
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(windows)]
struct WindowsNativeBoxGuard<'a> {
    fixture: &'a BoxFixture,
    processes: Vec<WindowsProcessWatch>,
}

#[cfg(windows)]
impl<'a> WindowsNativeBoxGuard<'a> {
    fn new(fixture: &'a BoxFixture, supervisor_pid: u32, rows: &[WindowsProcessRow]) -> Self {
        let mut processes = vec![WindowsProcessWatch::open(supervisor_pid)];
        processes.extend(
            rows.iter()
                .map(|row| WindowsProcessWatch::open(row.process_id)),
        );
        Self { fixture, processes }
    }

    fn process(&self, pid: u32) -> &WindowsProcessWatch {
        self.processes
            .iter()
            .find(|process| process.pid == pid)
            .unwrap()
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
impl Drop for WindowsNativeBoxGuard<'_> {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle as _;
        use windows_sys::Win32::Foundation::WAIT_TIMEOUT;
        use windows_sys::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};

        for process in &self.processes {
            // SAFETY: retained handles pin only the exact processes spawned by this fixture.
            if unsafe { WaitForSingleObject(process.handle.as_raw_handle(), 0) } == WAIT_TIMEOUT {
                let _ = unsafe { TerminateProcess(process.handle.as_raw_handle(), 1) };
            }
        }
        for process in &self.processes {
            // SAFETY: each retained handle remains live until this guard drops.
            let _ = unsafe { WaitForSingleObject(process.handle.as_raw_handle(), 5_000) };
        }
        let _ = self.fixture.force_remove();
    }
}

#[cfg(windows)]
fn windows_box_state(fixture: &BoxFixture) -> PathBuf {
    let boxes = std::fs::read_dir(fixture.home.join(".terra/box"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect::<Vec<_>>();
    assert_eq!(
        boxes.len(),
        1,
        "fixture must own exactly one box: {boxes:?}"
    );
    boxes[0].join("native")
}

#[cfg(windows)]
fn windows_box_pid(path: &std::path::Path) -> u32 {
    std::fs::read_to_string(path)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[cfg(windows)]
fn windows_ports_available(tcp_port: u16, udp_port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", tcp_port)).is_ok()
        && std::net::UdpSocket::bind(("127.0.0.1", udp_port)).is_ok()
}

/// Abrupt Windows worker and supervisor deaths release published sockets.
#[cfg(windows)]
#[test]
#[ignore = "requires bundled guest artifacts, native WHP, AppContainer, and PowerShell CIM"]
fn windows_broker_and_supervisor_death_release_published_ports() {
    for kill_supervisor in [false, true] {
        let fixture = BoxFixture::new();
        std::fs::write(
            fixture.home.join(".terra/config.yaml"),
            "vm:\n  init: bwrap\n",
        )
        .unwrap();
        let tcp_reservation = TcpListener::bind("127.0.0.1:0").unwrap();
        let udp_reservation = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let tcp_port = tcp_reservation.local_addr().unwrap().port();
        let udp_port = udp_reservation.local_addr().unwrap().port();
        let recipe = fixture.directory.path().join("native.yaml");
        let config = serde_json::json!({
            "network": {"ports": [format!("{tcp_port}:8080/tcp"), format!("{udp_port}:8081/udp")]},
            "workload": {"entrypoint": "/bin/sleep", "args": ["300"]}
        });
        std::fs::write(&recipe, yaml_serde::to_string(&config).unwrap()).unwrap();
        fixture.successful(&[recipe.to_str().unwrap(), "setup"]);
        drop((tcp_reservation, udp_reservation));
        fixture.successful(&["native", "-d"]);
        assert!(
            TcpListener::bind(("127.0.0.1", tcp_port)).is_err(),
            "published TCP port is not held by the box"
        );
        assert!(
            std::net::UdpSocket::bind(("127.0.0.1", udp_port)).is_err(),
            "published UDP port is not held by the box"
        );

        let state = windows_box_state(&fixture);
        let supervisor_pid = windows_box_pid(&state.join("supervisor.pid"));
        let vm_pid = windows_box_pid(&state.join("host.pid"));
        let rows = windows_process_descendants(supervisor_pid);
        assert!(rows.iter().any(|row| row.process_id == vm_pid));
        let broker_wrappers = rows
            .iter()
            .filter(|row| {
                row.parent_process_id == supervisor_pid
                    && row.command_line.as_deref().is_some_and(|line| {
                        line.contains(" __sandbox_launcher") && line.contains(" __network")
                    })
            })
            .collect::<Vec<_>>();
        assert_eq!(
            broker_wrappers.len(),
            1,
            "box must own exactly one broker wrapper"
        );
        let broker_wrapper_pid = broker_wrappers[0].process_id;
        let worker_name = fixture.terra.file_name().unwrap().to_str().unwrap();
        let brokers = rows
            .iter()
            .filter(|row| {
                row.parent_process_id == broker_wrapper_pid
                    && row.name.eq_ignore_ascii_case(worker_name)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            brokers.len(),
            1,
            "broker wrapper must own exactly one worker"
        );
        let broker_pid = brokers[0].process_id;
        let guard = WindowsNativeBoxGuard::new(&fixture, supervisor_pid, &rows);
        assert!(guard.process(vm_pid).is_running());
        assert!(guard.process(broker_pid).is_running());
        let deadline = Instant::now() + Duration::from_secs(15);
        if kill_supervisor {
            guard.process(supervisor_pid).terminate();
            for process in &guard.processes {
                process.wait_exited(deadline);
            }
        } else {
            guard.process(broker_pid).terminate();
            guard.process(broker_pid).wait_exited(deadline);
            guard.process(broker_wrapper_pid).wait_exited(deadline);
            assert!(guard.process(supervisor_pid).is_running());
            assert!(guard.process(vm_pid).is_running());
        }
        while !windows_ports_available(tcp_port, udp_port) {
            assert!(
                Instant::now() < deadline,
                "published ports survived process death"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        if !kill_supervisor {
            fixture.successful(&["native", "stop"]);
            let stop_deadline = Instant::now() + Duration::from_secs(15);
            for process in &guard.processes {
                process.wait_exited(stop_deadline);
            }
        }
    }
}
