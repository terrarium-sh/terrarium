//! Integration checks for bundled self-tests and native VM behavior.
//! `TERRA_BIN` overrides the Cargo-built binary; VM tests require `--ignored`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::assert_matches;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// Forked siblings can retain a concurrent copy's writable descriptor until exec.
static INSTALLED_BINARY_FIXTURES: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn assets_dir() -> PathBuf {
    std::env::var_os("TERRA_TEST_ASSETS").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/assets"),
        PathBuf::from,
    )
}

fn copy_installed_binary(directory: &Path) -> PathBuf {
    let binary = std::env::var_os("TERRA_BIN")
        .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_terra")), PathBuf::from);
    let installed = directory.join(if cfg!(windows) { "terra.exe" } else { "terra" });
    std::fs::copy(binary, &installed).unwrap();
    installed
}

#[test]
fn bundled_self_test_runs_without_a_source_checkout_or_generation_tools() {
    let _guard = INSTALLED_BINARY_FIXTURES.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let installed = copy_installed_binary(directory.path());
    let result = Command::new(installed)
        .arg("self-test")
        .current_dir(directory.path())
        .env("PATH", "")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!directory.path().join("terra-seccomp").exists());
}

#[test]
#[ignore = "requires native virtualization"]
fn bundled_guest_self_test_runs_with_an_empty_path() {
    let _guard = INSTALLED_BINARY_FIXTURES.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let installed = copy_installed_binary(directory.path());
    let diagnostics = directory.path().join("diagnostics");
    let result = Command::new(installed)
        .args(["self-test", "--validate-vm", "--diagnostics"])
        .arg(&diagnostics)
        .current_dir(directory.path())
        .env("PATH", "")
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("self-test: passed; diagnostics:"),
        "{result:?}"
    );
    let guest_log = std::fs::read_dir(&diagnostics)
        .unwrap()
        .map(|entry| entry.unwrap().path().join("self_test.built_in_guest.log"))
        .find(|path| path.is_file())
        .expect("guest self-test diagnostics");
    assert!(
        std::fs::read_to_string(guest_log)
            .unwrap()
            .contains("self-test: passed"),
        "guest self-test did not report success"
    );
    assert!(!directory.path().join("terra-seccomp").exists());
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn assert_generated_policy(output: &Path, binary: &Path, vm_validated: bool) -> serde_json::Value {
    fn hash_bytes(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        use std::fmt::Write as _;

        let mut hash = String::new();
        for byte in Sha256::digest(bytes) {
            write!(hash, "{byte:02x}").unwrap();
        }
        hash
    }

    assert!(output.symlink_metadata().unwrap().is_symlink());
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(output.join("manifest.json")).unwrap()).unwrap();
    let binary_hash = hash_bytes(&std::fs::read(binary).unwrap());
    assert_eq!(manifest["executable_sha256"], binary_hash);
    assert_eq!(manifest["roles"].as_object().unwrap().len(), 3);
    for role in ["supervisor", "vm", "network"] {
        let policy_bytes = std::fs::read(output.join(format!("{role}.seccomp.json"))).unwrap();
        let bpf = std::fs::read(output.join(format!("{role}.seccomp.bpf"))).unwrap();
        let policy: serde_json::Value = serde_json::from_slice(&policy_bytes).unwrap();
        assert_eq!(
            manifest["roles"][role]["policy_sha256"],
            hash_bytes(&policy_bytes)
        );
        assert_eq!(manifest["roles"][role]["bpf_sha256"], hash_bytes(&bpf));
        assert!(manifest["roles"][role]["verified_execs"].as_u64().unwrap() > 0);
        assert!((8..=4096 * 8).contains(&bpf.len()) && bpf.len().is_multiple_of(8));
        assert_eq!(manifest["target"], policy["target"]);
        assert_eq!(policy["default_action"], "kill_process");
        assert_ne!(
            policy["rules"].as_array().unwrap().as_slice(),
            [] as [serde_json::Value; 0]
        );
    }
    assert_eq!(
        std::fs::read_to_string(output.join(".validated"))
            .unwrap()
            .trim(),
        binary_hash
    );
    assert_eq!(manifest["format_version"], 1);
    assert_eq!(manifest["policy_compiler"], "seccompiler_0_5_0");
    assert_eq!(manifest["validation"]["passed"], true);
    assert_eq!(manifest["validation"]["vm_validated"], vm_validated);
    assert!(manifest["validation"]["traced_execs"].as_u64().unwrap() > 0);
    assert!(
        manifest["validation"]["traced_processes"].as_u64().unwrap()
            >= manifest["validation"]["traced_execs"].as_u64().unwrap()
    );
    for result in manifest["validation"]["workload_results"]
        .as_array()
        .unwrap()
    {
        assert_eq!(result["passed"], true);
    }
    manifest
}

/// A copied binary generates without tools, and timeout or failure preserves the published policy.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
fn bundled_policy_generation_needs_no_tools_and_preserves_previous_publication() {
    let _guard = INSTALLED_BINARY_FIXTURES.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let installed = copy_installed_binary(directory.path());
    let output = directory.path().join("policy");
    let diagnostics = directory.path().join("diagnostics");
    let mut command = Command::new(&installed);
    command
        .args(["self-test", "--generate-policy", "--policy-output"])
        .arg(&output)
        .arg("--policy-diagnostics")
        .arg(&diagnostics)
        .current_dir(directory.path())
        .env("PATH", "")
        .env_remove("RUST_LOG");
    let result = command.output().unwrap();
    assert!(result.status.success(), "{result:?}");
    let manifest = assert_generated_policy(&output, &installed, false);
    assert_eq!(manifest["validation"]["scope"], "host_components");
    assert_eq!(
        manifest["validation"]["workloads"],
        serde_json::json!(["self_test.host_components"])
    );
    let previous = std::fs::read_link(&output).unwrap();
    let started = Instant::now();
    let mut generation = command
        .args(["--policy-timeout", "1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let children = format!("/proc/{0}/task/{0}/children", generation.id());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        // Stopping before exec blocks Command::spawn before the workload timeout starts.
        if let Some(pid) = std::fs::read_to_string(&children)
            .unwrap_or_default()
            .split_whitespace()
            .next()
            .and_then(|pid| pid.parse().ok())
            && std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|arguments| {
                arguments.split(|byte| *byte == 0).nth(1) == Some(b"__sandbox_policy".as_slice())
            })
        {
            rustix::process::kill_process(
                rustix::process::Pid::from_raw(pid).unwrap(),
                rustix::process::Signal::STOP,
            )
            .unwrap();
            break;
        }
        if generation.try_wait().unwrap().is_some() || Instant::now() >= deadline {
            let _ = generation.kill();
            let result = generation.wait_with_output().unwrap();
            panic!("generation did not launch its supervised child: {result:?}");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let result = generation.wait_with_output().unwrap();
    assert!(!result.status.success(), "{result:?}");
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("timed out"),
        "{result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_eq!(std::fs::read_link(&output).unwrap(), previous);
    assert_eq!(
        assert_generated_policy(&output, &installed, false),
        manifest
    );

    std::fs::remove_dir_all(&diagnostics).unwrap();
    std::fs::write(&diagnostics, b"blocked diagnostics directory").unwrap();
    let result = command.output().unwrap();
    assert!(!result.status.success(), "{result:?}");
    assert_eq!(std::fs::read_link(&output).unwrap(), previous);
    assert_eq!(
        assert_generated_policy(&output, &installed, false),
        manifest
    );
}

/// The installed binary embeds the guest suite, tracer, and compiler needed for VM validation.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
#[ignore = "requires native KVM and Bubblewrap user namespaces"]
fn bundled_guest_policy_generation_runs_with_an_empty_path() {
    let _guard = INSTALLED_BINARY_FIXTURES.lock().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let installed = copy_installed_binary(directory.path());
    let output = directory.path().join("policy");
    let result = Command::new(&installed)
        .args([
            "self-test",
            "--generate-policy",
            "--validate-vm",
            "--policy-output",
        ])
        .arg(&output)
        .arg("--policy-diagnostics")
        .arg(directory.path().join("diagnostics"))
        .current_dir(directory.path())
        .env("PATH", "")
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    assert!(result.status.success(), "{result:?}");
    let manifest = assert_generated_policy(&output, &installed, true);
    assert_eq!(manifest["validation"]["scope"], "host_components");
    assert_eq!(
        manifest["validation"]["workloads"],
        serde_json::json!(["self_test.host_components", "self_test.built_in_guest"])
    );
    assert_eq!(
        manifest["trace_exclusions"][0]["name"],
        "self_test.built_in_guest"
    );
}

struct Suite {
    terra: PathBuf,
    home: PathBuf,
    #[cfg(unix)]
    host_uid: u32,
    // Owns WORK; removed on drop, after the Drop impl stopped the server VM.
    tmp: tempfile::TempDir,
}

impl Suite {
    fn new() -> Self {
        let terra = std::env::var_os("TERRA_BIN")
            .map_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_terra")), PathBuf::from);
        assert!(
            terra.exists(),
            "terra binary not found: {}",
            terra.display()
        );
        // HOME under WORK too, so tearing WORK down removes every box this run
        // made - a real home would collect one per VM booted.
        let tmp = tempfile::tempdir().unwrap();
        let home = tmp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir(home.join(".terra")).unwrap();
        std::fs::write(home.join(".terra/config.yaml"), "vm:\n  init: direct\n").unwrap();
        #[cfg(unix)]
        let host_uid = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(tmp.path()).unwrap().uid()
        };
        Self {
            terra,
            home,
            #[cfg(unix)]
            host_uid,
            tmp,
        }
    }

    fn get_work_dir(&self) -> &Path {
        self.tmp.path()
    }

    /// Run terra, returning stdout and reporting stderr on failure.
    fn run_terra_command(&self, args: &[&str]) -> String {
        self.run_terra_status(args).0
    }

    fn run_terra_status(&self, args: &[&str]) -> (String, i32) {
        let out = Command::new(&self.terra)
            .args(args)
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .output()
            .expect("running terra");
        let stderr = String::from_utf8_lossy(&out.stderr);
        if !out.status.success() {
            eprintln!(
                "terra command {args:?} exited {:?}: {stderr}",
                out.status.code()
            );
        }
        (
            String::from_utf8_lossy_owned(out.stdout),
            out.status.code().unwrap_or(-1),
        )
    }

    /// Where terra keeps `name`'s files - asked via `ls --tsv`, the
    /// format scripts may parse, not guessed: the state directory's name is a
    /// hash.
    fn get_box_files_path(&self, name: &str) -> PathBuf {
        let path = self.get_work_dir().join(name);
        let out = self.run_terra_command(&["ls", "--tsv", "--project", path.to_str().unwrap()]);
        let files = out
            .lines()
            .find_map(|l| l.split('\t').nth(3))
            .unwrap_or_else(|| {
                panic!("`terra ls --tsv` did not say where '{name}'s files are:\n{out}")
            });
        PathBuf::from(files)
    }

    /// Boot `recipe` in a fresh box named `name` under WORK: `setup` pins the
    /// recipe and bakes `on_create` with its console on setup's stdout, then
    /// the bare form boots it. The
    /// recipes live outside any share, so nothing is ever asked about.
    /// Foreground, because this harness has no terminal and wants the VM's
    /// whole run as one captured process; a failed boot also appends the box
    /// log, which preserves guest output for its assertion.
    fn boot_recipe(&self, recipe: &Path, name: &str, extra: &[&str]) -> String {
        let path = self.create_project_dir(name);
        let project = path.to_str().unwrap();
        let setup =
            self.run_terra_command(&[recipe.to_str().unwrap(), "setup", "--project", project]);
        let mut args = vec![name, "--foreground", "--project", project];
        args.extend_from_slice(extra);
        let (boot, code) = self.run_terra_status(&args);
        if code == 0 {
            setup + &boot
        } else {
            let logs = self.run_terra_command(&["logs", "--project", project]);
            format!("{setup}{boot}\nbox logs:\n{logs}")
        }
    }

    /// `name`'s project directory under WORK, created - terra refuses a
    /// `--project` that does not exist rather than minting one for a typo.
    fn create_project_dir(&self, name: &str) -> PathBuf {
        let path = self.get_work_dir().join(name);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    /// The common case: boot `<name>.yaml` from the assets directory.
    fn boot(&self, name: &str, extra: &[&str]) -> String {
        self.boot_recipe(&assets_dir().join(format!("{name}.yaml")), name, extra)
    }

    /// The asset plus a `mounts:` entry pointing /work at a directory this
    /// suite owns - nothing is shared with a sandbox unless its recipe says so.
    fn boot_with_share(&self, name: &str, extra: &[&str]) -> (String, PathBuf) {
        let prj = self.get_work_dir().join(format!("{name}-proj"));
        std::fs::create_dir_all(&prj).unwrap();
        let recipe = self.get_work_dir().join(format!("{name}.yaml"));
        let base = std::fs::read_to_string(assets_dir().join(format!("{name}.yaml"))).unwrap();
        std::fs::write(
            &recipe,
            format!(
                "{base}\nmounts:\n  - {{host: {}, guest: /work}}\n",
                prj.display()
            ),
        )
        .unwrap();
        (self.boot_recipe(&recipe, name, extra), prj)
    }

    fn boot_with_repository_mount(
        &self,
        name: &str,
        host: &Path,
        readonly: bool,
        script: &str,
    ) -> String {
        let recipe = self.get_work_dir().join(format!("{name}.yaml"));
        let script = script.replace('\n', "\n      ");
        let readonly = if readonly { "    readonly: true\n" } else { "" };
        std::fs::write(
            &recipe,
            format!(
                "network:\n  mode: unrestricted-public\nhooks:\n  on_create:\n    - apk add --no-cache git python3\nworkload:\n  entrypoint: /bin/sh\n  args:\n    - -ec\n    - |\n      {script}\nmounts:\n  - host: {}\n    guest: /work\n{readonly}",
                host.display()
            ),
        )
        .unwrap();
        self.boot_recipe(&recipe, name, &[])
    }

    fn exec(&self, root: bool, cmd: &[&str]) -> (String, i32) {
        let server = self.get_work_dir().join("server");
        self.exec_in("server", &server, root, cmd)
    }

    fn exec_in(&self, name: &str, project: &Path, root: bool, cmd: &[&str]) -> (String, i32) {
        let mut args = vec!["exec"];
        if root {
            args.push("--root");
        }
        args.extend(["--project", project.to_str().unwrap(), "--"]);
        args.extend_from_slice(cmd);
        let mut named = vec![name];
        named.extend(args);
        self.run_terra_status(&named)
    }

    #[cfg(unix)]
    fn read_file_uid(path: &Path) -> Option<u32> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| m.uid())
    }

    fn compile_probe(&self, name: &str) -> PathBuf {
        let directory = self.get_work_dir().join("probes");
        std::fs::create_dir_all(&directory).unwrap();
        if let Some(reader) = std::env::var_os("TERRA_SOCKET_KMSG_READER") {
            std::fs::copy(reader, directory.join("kmsg-reader")).unwrap();
        }
        let probe = directory.join(format!("terra-{name}-probe"));
        let source = assets_dir().join(format!("{name}_probe.c"));
        let status = Command::new("zig")
            .args([
                "cc",
                "-target",
                &format!("{}-linux-musl", std::env::consts::ARCH),
            ])
            .args(["-static", "-O2", "-o"])
            .arg(&probe)
            .arg(format!(
                "-DTERRA_SOCKET_ABI={}",
                terra_protocol::socket::VERSION
            ))
            .arg(format!(
                "-DTERRA_NETWORK_ABI={}",
                terra_protocol::application::VERSION
            ))
            .arg(source)
            .status()
            .expect("compiling guest probe");
        assert!(status.success(), "compiling guest probe failed: {status}");
        probe
    }
}

impl Drop for Suite {
    fn drop(&mut self) {
        // `stop` waits for the guest by default; without that wait the tempdir
        // would be deleted out from under a VM still running `pre_stop`.
        let server = self.get_work_dir().join("server");
        let _ = Command::new(&self.terra)
            .args(["stop", "--project", server.to_str().unwrap()])
            .env("HOME", &self.home)
            .env("USERPROFILE", &self.home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Foreground generation repeats writes in one existing box and refuses a running VM.
/// An enforced-pass failure retains the old policy and both passes' writes in a usable box.
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[test]
#[ignore = "requires native KVM and Bubblewrap user namespaces"]
#[allow(clippy::too_many_lines)]
fn generated_foreground_policy_reuses_box_storage_and_refuses_a_running_box() {
    use std::os::unix::fs::MetadataExt as _;

    let suite = Suite::new();
    let project = suite.create_project_dir("server");
    let recipe = suite.get_work_dir().join("server.yaml");
    std::fs::write(
        &recipe,
        format!(
            "hooks:\n  on_create:\n    - cat /proc/sys/kernel/random/uuid > /policy-created\nworkload:\n  entrypoint: /bin/sleep\n  args: [infinity]\nmounts:\n  - host: {}\n    guest: /work\n",
            project.display()
        ),
    )
    .unwrap();
    assert_eq!(
        suite
            .run_terra_status(&[
                recipe.to_str().unwrap(),
                "setup",
                "--project",
                project.to_str().unwrap(),
            ])
            .1,
        0
    );
    let rootfs = suite.get_box_files_path("server").join("rootfs.img");
    let rootfs_before = rootfs.metadata().unwrap();
    let output = suite.get_work_dir().join("policy");
    let script = r#"test -f /policy-created
count=$(cat /policy-count 2>/dev/null || printf 0)
count=$((count + 1))
printf '%s\n' "$count" > /policy-count
printf '%s\n' "$count" >> /work/effects
cat /policy-created >> /work/created
"#;
    let mut generation = prepare_foreground_generation_command(&suite, &project, &output, script);
    let result = generation.output().unwrap();
    assert!(result.status.success(), "{result:?}");
    let manifest = assert_generated_policy(&output, &suite.terra, true);
    assert_eq!(manifest["validation"]["scope"], "guest");
    assert_eq!(
        manifest["validation"]["workloads"],
        serde_json::json!(["workload.foreground"])
    );
    assert_eq!(
        std::fs::read_to_string(project.join("effects")).unwrap(),
        "1\n2\n"
    );
    let created = std::fs::read_to_string(project.join("created")).unwrap();
    let creations: Vec<_> = created.lines().collect();
    assert_eq!(creations.len(), 2);
    assert_ne!(creations[0], "");
    assert_eq!(
        creations[0], creations[1],
        "on_create ran again between generation passes"
    );
    let rootfs_after = rootfs.metadata().unwrap();
    assert_eq!(rootfs_before.ino(), rootfs_after.ino());
    assert_eq!(rootfs_before.dev(), rootfs_after.dev());
    assert_eq!(rootfs_before.len(), rootfs_after.len());

    assert_eq!(
        suite
            .run_terra_status(&["server", "-d", "--project", project.to_str().unwrap()])
            .1,
        0
    );
    let previous = std::fs::read_link(&output).unwrap();
    let result = generation.output().unwrap();
    assert!(!result.status.success(), "{result:?}");
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("already running"),
        "{result:?}"
    );
    assert_eq!(std::fs::read_link(&output).unwrap(), previous);
    assert_eq!(
        std::fs::read_to_string(project.join("effects")).unwrap(),
        "1\n2\n"
    );
    assert_eq!(
        suite.exec(true, &["cat", "/policy-count"]),
        ("2\n".to_owned(), 0)
    );

    assert_eq!(
        suite
            .run_terra_status(&["server", "stop", "--project", project.to_str().unwrap()])
            .1,
        0
    );
    let failing_script = format!("{script}test \"$count\" -ne 4\n");
    let result = prepare_foreground_generation_command(&suite, &project, &output, &failing_script)
        .output()
        .unwrap();
    assert!(!result.status.success(), "{result:?}");
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("enforce-workload.foreground.log"),
        "{result:?}"
    );
    assert_eq!(std::fs::read_link(&output).unwrap(), previous);
    assert_eq!(
        assert_generated_policy(&output, &suite.terra, true),
        manifest
    );
    assert_eq!(
        std::fs::read_to_string(project.join("effects")).unwrap(),
        "1\n2\n3\n4\n"
    );
    assert_eq!(
        suite
            .run_terra_status(&["server", "-d", "--project", project.to_str().unwrap()])
            .1,
        0
    );
    assert_eq!(
        suite.exec(true, &["cat", "/policy-count"]),
        ("4\n".to_owned(), 0)
    );
    let rootfs_after_failure = rootfs.metadata().unwrap();
    assert_eq!(rootfs_before.ino(), rootfs_after_failure.ino());
    assert_eq!(rootfs_before.dev(), rootfs_after_failure.dev());
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn prepare_foreground_generation_command(
    suite: &Suite,
    project: &Path,
    output: &Path,
    script: &str,
) -> Command {
    let mut command = Command::new(&suite.terra);
    command
        .args(["server", "--generate-policy", "--root", "--project"])
        .arg(project)
        .arg("--policy-output")
        .arg(output)
        .arg("--policy-diagnostics")
        .arg(suite.get_work_dir().join("diagnostics"))
        .args(["--", "/bin/sh", "-ec", script])
        .env("HOME", &suite.home)
        .env("PATH", "")
        .env_remove("RUST_LOG")
        .stdin(Stdio::null());
    command
}

/// One plain HTTP/1.0 GET against the host loopback; `None` until it answers.
fn http_get(addr: &str, host: &str) -> Option<String> {
    use std::io::{Read, Write};
    let mut conn = std::net::TcpStream::connect(addr).ok()?;
    conn.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    conn.write_all(format!("GET / HTTP/1.0\r\nHost: {host}\r\n\r\n").as_bytes())
        .ok()?;
    let mut body = String::new();
    let _ = conn.read_to_string(&mut body);
    (!body.is_empty()).then_some(body)
}

#[test]
#[ignore = "boots a real microVM - requires a native hypervisor: cargo test --test boot -- --ignored"]
fn pending_network_reads_do_not_block_other_downloads() {
    let s = Suite::new();
    let payloads = s.get_work_dir().join("payloads");
    std::fs::create_dir(&payloads).unwrap();
    let first: Vec<u8> = (0_u8..=255)
        .cycle()
        .map(|byte| byte.wrapping_mul(73).wrapping_add(19))
        .take(512 * 1024 + 137)
        .collect();
    let second: Vec<u8> = (0_u8..=255)
        .cycle()
        .map(|byte| byte.wrapping_mul(37).wrapping_add(101))
        .take(64 * 1024 + 29)
        .collect();
    std::fs::write(payloads.join("first"), &first).unwrap();
    std::fs::write(payloads.join("second"), &second).unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        use std::io::{BufRead, Write};

        let deadline = Instant::now() + Duration::from_secs(90);
        let mut pending = Vec::new();
        let mut completed = 0;
        while completed < 2 && Instant::now() < deadline {
            let Ok((mut stream, _)) = listener.accept() else {
                std::thread::sleep(Duration::from_millis(10));
                continue;
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            let mut request = String::new();
            std::io::BufReader::new(&stream)
                .read_line(&mut request)
                .unwrap();
            if request.starts_with("GET /idle ") {
                stream
                    .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 999999\r\n\r\nx")
                    .unwrap();
                pending.push(stream);
                continue;
            }
            assert!(pending.len() >= 2, "active download preceded idle streams");
            let body = match request.split_whitespace().nth(1) {
                Some("/first") => &first,
                Some("/second") => &second,
                _ => panic!("unexpected HTTP request: {request}"),
            };
            stream
                .write_all(
                    format!("HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).as_bytes(),
                )
                .unwrap();
            for chunk in body.chunks(1371) {
                stream.write_all(chunk).unwrap();
            }
            completed += 1;
        }
        assert_eq!(pending.len(), 2, "guest did not open both idle streams");
        assert_eq!(completed, 2, "guest did not complete both downloads");
    });

    let recipe = s.get_work_dir().join("network-buffer-reuse.yaml");
    let script = format!(
        "wget -q -T 20 -O /tmp/idle-one http://buffer.test:{port}/idle &\n\
         idle_one=$!\n\
         wget -q -T 20 -O /tmp/idle-two http://buffer.test:{port}/idle &\n\
         idle_two=$!\n\
         timeout 10 sh -c 'until test -s /tmp/idle-one && test -s /tmp/idle-two; do sleep 0.05; done'\n\
         wget -q -T 10 -O /tmp/first http://buffer.test:{port}/first\n\
         cmp /work/first /tmp/first\n\
         wget -q -T 10 -O /tmp/second http://buffer.test:{port}/second\n\
         cmp /work/second /tmp/second\n\
         kill \"$idle_one\" \"$idle_two\" 2>/dev/null || true\n\
         wait \"$idle_one\" \"$idle_two\" 2>/dev/null || true\n\
         echo NETWORK_BUFFER_REUSE_OK"
    )
    .replace('\n', "\n      ");
    std::fs::write(
        &recipe,
        format!(
            "network:\n  allow: [\"buffer.test:{port}\"]\n  hosts:\n    - {{name: buffer.test, addr: HOST_LOOPBACK}}\nworkload:\n  entrypoint: /bin/sh\n  args:\n    - -ec\n    - |\n      {script}\nmounts:\n  - host: {}\n    guest: /work\n    readonly: true\n",
            payloads.display()
        ),
    )
    .unwrap();
    let out = s.boot_recipe(&recipe, "network-buffer-reuse", &[]);
    assert!(out.contains("NETWORK_BUFFER_REUSE_OK"), "{out}");
    server.join().unwrap();
}

fn select_socket_probe_flags() -> &'static [&'static str] {
    if std::env::var_os("TERRA_SOCKET_DMESG").is_some() {
        &["--root"]
    } else {
        &[]
    }
}

fn render_socket_probe_workload(arguments: Vec<String>) -> String {
    let collect_kernel_log = !select_socket_probe_flags().is_empty();
    let (entrypoint, arguments) = if collect_kernel_log {
        let mut shell_arguments = vec![
            "-c".into(),
            "mknod /dev/kmsg c 1 11 2>/dev/null || true; /work/kmsg-reader & kernel_log_reader=$!; /work/terra-socket-probe \"$@\"; status=$?; kill \"$kernel_log_reader\"; wait \"$kernel_log_reader\" || true; dmesg; exit \"$status\"".into(),
            "socket-probe".into(),
        ];
        shell_arguments.extend(arguments);
        ("/bin/sh", shell_arguments)
    } else {
        ("/work/terra-socket-probe", arguments)
    };
    format!(
        "workload:\n  entrypoint: {entrypoint}\n  args: {}\n",
        serde_json::to_string(&arguments).unwrap()
    )
}

/// A 24-KiB raw TCP carrier refills after consuming its separate 4-KiB first skb,
/// even when the resulting 20-KiB queue is below `SO_RCVLOWAT=21` KiB.
#[cfg(unix)]
#[test]
#[ignore = "boots a real microVM; requires a native hypervisor and Zig"]
fn raw_vsock_tcp_receive_credit_preserves_high_lowat() {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpListener};
    use std::sync::atomic::{AtomicBool, Ordering};
    use terra_protocol::application::{Message, TcpTarget};

    fn serve_credit_payload(
        listener: &TcpListener,
        marker: &Path,
        payload: &[u8],
        stop: &AtomicBool,
    ) -> std::io::Result<()> {
        let deadline = Instant::now() + Duration::from_secs(90);
        let (mut stream, _) = loop {
            if stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "raw receive-credit connection",
                ));
            }
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error),
            }
        };
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        stream.write_all(&payload[..4 * 1024])?;
        while !std::fs::read_to_string(marker).is_ok_and(|value| value.trim() == "4096 1") {
            if stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "guest did not confirm separately queued first payload",
                ));
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        stream.write_all(&payload[4 * 1024..])?;
        stream.shutdown(Shutdown::Write)?;
        let mut byte = [0];
        assert_eq!(
            stream.read(&mut byte)?,
            0,
            "guest sent no application payload"
        );
        Ok(())
    }

    let suite = Suite::new();
    let probe = suite.compile_probe("vsock");
    let directory = probe.parent().unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = SocketAddr::new(IpAddr::V4(terra_protocol::socket::HOST_SERVICE_IPV4), port);
    let opening = Message::TcpOpen {
        target: TcpTarget::Peer(peer),
        inline_urgent: false,
    }
    .encode()
    .unwrap();
    let opened = Message::TcpOpened(Ok(peer)).encode().unwrap();
    assert_eq!(opening.len(), 36);
    assert_eq!(opened.len(), 32);
    let payload: Vec<_> = (0..32 * 1024)
        .map(|offset| u8::try_from(offset % 251).unwrap())
        .collect();
    std::fs::write(directory.join("VSOCK_CREDIT_OPEN"), opening).unwrap();
    std::fs::write(directory.join("VSOCK_CREDIT_OPENED"), opened).unwrap();
    std::fs::write(directory.join("VSOCK_CREDIT_PAYLOAD"), &payload).unwrap();
    let marker = directory.join("VSOCK_CREDIT_INITIAL");
    let recipe = suite.get_work_dir().join("raw-vsock-credit-lowat.yaml");
    let configuration = serde_json::json!({
        "network": {"allow": [format!("HOST_LOOPBACK:{port}")]},
        "mounts": [{"host": directory, "guest": "/work", "readonly": false}],
        "workload": {
            "entrypoint": "/bin/sh",
            "args": ["-ec", "exec /work/terra-vsock-probe receive-credit-lowat > /work/VSOCK_CREDIT_PROBE_LOG 2>&1"],
        },
    });
    std::fs::write(&recipe, serde_json::to_vec(&configuration).unwrap()).unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|threads| {
        let server = threads.spawn(|| serve_credit_payload(&listener, &marker, &payload, &stop));
        let output = suite.boot_recipe(&recipe, "raw-vsock-credit-lowat", &["--root"]);
        let guest_log = std::fs::read_to_string(directory.join("VSOCK_CREDIT_PROBE_LOG"))
            .unwrap_or_else(|error| format!("guest probe log unavailable: {error}"));
        stop.store(true, Ordering::Relaxed);
        let result = server.join().unwrap();
        assert!(result.is_ok(), "{result:?}\n{output}\n{guest_log}");
        assert!(
            guest_log.contains("VSOCK_RECEIVE_CREDIT_LOWAT_OK"),
            "{output}\n{guest_log}"
        );
    });
}

#[test]
#[ignore = "boots real microVMs; requires a native hypervisor and Zig"]
fn static_vsock_endpoint_classes_reject_unknown_duplicate_and_malformed_connections() {
    let suite = Suite::new();
    let probe = suite.compile_probe("vsock");
    for enabled in [false, true] {
        let name = if enabled {
            "vsock-network"
        } else {
            "vsock-local"
        };
        let mode = if enabled {
            "endpoints-network"
        } else {
            "endpoints"
        };
        let recipe = suite.get_work_dir().join(format!("{name}.yaml"));
        std::fs::write(&recipe, format!(
            "network:\n  enabled: {enabled}\nworkload:\n  entrypoint: /work/terra-vsock-probe\n  args: [{mode}]\nmounts:\n  - host: {}\n    guest: /work\n    readonly: true\n", probe.parent().unwrap().display()
        )).unwrap();
        let output = suite.boot_recipe(&recipe, name, &["--root"]);
        assert!(
            output.contains("VSOCK_ENDPOINT_CLASSES_OK"),
            "{name}: {output}"
        );
    }
}

#[test]
#[ignore = "boots real microVMs; requires a native hypervisor"]
fn static_socket_selection_preserves_local_and_namespace_routes() {
    let suite = Suite::new();
    let probe = suite.compile_probe("socket");
    for (name, enabled, mode, marker) in [
        (
            "socket-local",
            false,
            "--namespaces",
            "SOCKET_NAMESPACES_OK",
        ),
        ("socket-tsi", true, "--namespaces", "SOCKET_NAMESPACES_OK"),
        ("socket-routes", true, "--routes", "SOCKET_ROUTES_OK"),
        ("socket-errors", true, "--errors", "SOCKET_ERRORS_OK"),
    ] {
        let recipe = suite.get_work_dir().join(format!("{name}.yaml"));
        std::fs::write(
            &recipe,
            format!(
                "network:\n  enabled: {enabled}\n{}mounts:\n  - host: {}\n    guest: /work\n    readonly: true\n",
                render_socket_probe_workload(vec![mode.into()]),
                probe.parent().unwrap().display()
            ),
        )
        .unwrap();
        let output = suite.boot_recipe(&recipe, name, select_socket_probe_flags());
        assert!(output.contains("SOCKET_LOCAL_OK"), "{name}: {output}");
        assert!(output.contains(marker), "{name}: {output}");
    }
}

#[test]
#[ignore = "boots real microVMs; requires a native hypervisor"]
fn static_libc_dns_resolves_configured_names() {
    let suite = Suite::new();
    let probe = suite.compile_probe("socket");
    let recipe = suite.get_work_dir().join("socket-dns.yaml");
    let text = format!(
        "network:\n  hosts:\n    - name: many.test\n      addr: 192.0.2.1\nworkload:\n  entrypoint: /work/terra-socket-probe\n  args: [--dns]\nmounts:\n  - host: {}\n    guest: /work\n    readonly: true\n",
        probe.parent().unwrap().display()
    );
    std::fs::write(&recipe, text).unwrap();
    let output = suite.boot_recipe(&recipe, "socket-dns", &[]);
    assert!(output.contains("SOCKET_DNS_OK"), "{output}");
}

fn serve_socket_probe_tcp(listener: &std::net::TcpListener, stop: &std::sync::atomic::AtomicBool) {
    use std::io::{Read, Write};

    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(90);
    while !stop.load(std::sync::atomic::Ordering::Relaxed) && Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                let mut bytes = Vec::new();
                std::io::Read::by_ref(&mut stream)
                    .take(8 << 20)
                    .read_to_end(&mut bytes)
                    .unwrap();
                stream.write_all(&bytes).unwrap();
                stream.shutdown(std::net::Shutdown::Write).unwrap();
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("socket probe accept: {error}"),
        }
    }
}

fn serve_socket_probe_udp(
    socket: &std::net::UdpSocket,
    stop: &std::sync::atomic::AtomicBool,
    reply_marker: &Path,
) -> Vec<usize> {
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut bytes = [0; 8192];
    let mut datagram_lengths = Vec::new();
    while !stop.load(std::sync::atomic::Ordering::Relaxed) && Instant::now() < deadline {
        match socket.recv_from(&mut bytes) {
            Ok((length, peer)) => {
                assert_ne!(&bytes[..length], b"TERRA_NESTED_FORWARDING");
                datagram_lengths.push(length);
                assert_eq!(socket.send_to(&bytes[..length], peer).unwrap(), length);
                if &bytes[..length] == b"TERRA_ERRQUEUE_RESUME" {
                    std::fs::write(reply_marker, []).unwrap();
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => panic!("socket probe UDP: {error}"),
        }
    }
    datagram_lengths
}

#[test]
#[ignore = "boots a real microVM; requires a native hypervisor and matching kernel"]
fn static_tcp_send_limits_preserve_user_overrides_and_queued_fin() {
    use std::io::{Read, Write};

    let suite = Suite::new();
    let probe = suite.compile_probe("socket");
    let directory = probe.parent().unwrap();
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let refused = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let refused_port = refused.local_addr().unwrap().port();
    drop(refused);
    let stop = std::sync::atomic::AtomicBool::new(false);
    let output = std::thread::scope(|threads| {
        let server = threads.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(90);
            let mut connections = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) && Instant::now() < deadline {
                let (mut stream, _) = match listener.accept() {
                    Ok(stream) => stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("send limit peer: {error}"),
                };
                connections += 1;
                stream
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                let mut expected_prefix = None;
                if connections == 6 {
                    std::fs::write(directory.join("SEND_LIMIT_PEER_READY"), []).unwrap();
                    loop {
                        expected_prefix =
                            std::fs::read_to_string(directory.join("SEND_LIMIT_SHRINK_READY"))
                                .ok()
                                .and_then(|length| length.trim().parse::<usize>().ok());
                        if expected_prefix.is_some()
                            || stop.load(std::sync::atomic::Ordering::Relaxed)
                        {
                            break;
                        }
                        assert!(
                            Instant::now() < deadline,
                            "guest did not release paused peer"
                        );
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
                let mut bytes = Vec::new();
                Read::by_ref(&mut stream)
                    .take((16 << 20) + 1)
                    .read_to_end(&mut bytes)
                    .unwrap();
                assert_eq!(bytes.len(), expected_prefix.unwrap_or(0));
                stream.write_all(&bytes).unwrap();
                stream.shutdown(std::net::Shutdown::Write).unwrap();
            }
            connections
        });
        let recipe = suite.get_work_dir().join("socket-send-limits.yaml");
        std::fs::write(&recipe, format!(
            "network:\n  allow: [HOST_LOOPBACK:{port}, HOST_LOOPBACK:{refused_port}]\n{}mounts:\n  - host: {}\n    guest: /work\n    readonly: false\n",
            render_socket_probe_workload(vec!["--send-limits".into(), "100.96.0.1".into(), port.to_string(), refused_port.to_string()]),
            directory.display()
        )).unwrap();
        let mut flags = select_socket_probe_flags().to_vec();
        if !flags.contains(&"--root") {
            flags.push("--root");
        }
        let output = suite.boot_recipe(&recipe, "socket-send-limits", &flags);
        eprintln!("{output}");
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(server.join().unwrap(), 6, "{output}");
        output
    });
    assert!(output.contains("SOCKET_SEND_LIMITS_OK"), "{output}");
    assert!(output.contains("SOCKET_SEND_LIMIT_SHRINK_OK"), "{output}");
}

/// Consuming only `MSG_ERRQUEUE` frees the shared UDP receive budget and resumes a buffered reply.
#[test]
#[ignore = "boots a real microVM; requires a native hypervisor and matching kernel"]
fn static_udp_error_queue_consumption_resumes_buffered_reply() {
    let suite = Suite::new();
    let probe = suite.compile_probe("socket");
    let socket = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let port = socket.local_addr().unwrap().port();
    let reply_marker = probe.parent().unwrap().join("UDP_ERROR_REPLY_SENT");
    let stop = std::sync::atomic::AtomicBool::new(false);
    let output = std::thread::scope(|threads| {
        threads.spawn(|| serve_socket_probe_udp(&socket, &stop, &reply_marker));
        let recipe = suite.get_work_dir().join("socket-udp-error-budget.yaml");
        std::fs::write(&recipe, format!(
            "network:\n  allow: [HOST_LOOPBACK:{port}]\n{}mounts:\n  - host: {}\n    guest: /work\n    readonly: true\n",
            render_socket_probe_workload(vec!["--udp-error-budget".into(), "100.96.0.1".into(), port.to_string()]),
            probe.parent().unwrap().display()
        )).unwrap();
        let output = suite.boot_recipe(
            &recipe,
            "socket-udp-error-budget",
            select_socket_probe_flags(),
        );
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        output
    });
    assert!(
        output.contains("SOCKET_ERROR_QUEUE_BUDGET_PAUSED"),
        "{output}"
    );
    assert!(output.contains("SOCKET_ERROR_QUEUE_BUDGET_OK"), "{output}");
}

/// QUIC options survive the first external send; ECN/GSO controls preserve native delivery,
/// external GSO reaches the host as separate intact datagrams, and rejected controls send nothing.
#[test]
#[ignore = "boots a real microVM; requires a native hypervisor and matching kernel"]
fn static_quic_socket_options_and_gso_preserve_udp_boundaries() {
    let suite = Suite::new();
    let probe = suite.compile_probe("socket");
    let ipv4 = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let port = ipv4.local_addr().unwrap().port();
    let ipv6 = std::net::UdpSocket::bind(("::1", port)).unwrap();
    let reply_marker = probe.parent().unwrap().join("UDP_ERROR_REPLY_SENT");
    let stop = std::sync::atomic::AtomicBool::new(false);
    let output = std::thread::scope(|threads| {
        let ipv4_server = threads.spawn(|| serve_socket_probe_udp(&ipv4, &stop, &reply_marker));
        let ipv6_server = threads.spawn(|| serve_socket_probe_udp(&ipv6, &stop, &reply_marker));
        let recipe = suite.get_work_dir().join("socket-quic.yaml");
        std::fs::write(&recipe, format!(
            "network:\n  allow: [HOST_LOOPBACK:{port}]\n{}mounts:\n  - host: {}\n    guest: /work\n    readonly: true\n",
            render_socket_probe_workload(vec!["--quic-socket".into(), "100.96.0.1".into(), port.to_string()]),
            probe.parent().unwrap().display()
        )).unwrap();
        let output = suite.boot_recipe(&recipe, "socket-quic", select_socket_probe_flags());
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            ipv4_server.join().unwrap(),
            [
                7, 7, 7, 7, 1200, 1200, 1200, 1200, 1200, 1200, 1200, 1200, 1000, 1000, 401, 7, 7
            ],
            "IPv4 host datagrams: {output}"
        );
        assert_eq!(
            ipv6_server.join().unwrap(),
            [
                7, 7, 7, 1200, 1200, 1200, 1200, 1200, 1200, 1200, 1200, 1000, 1000, 401, 7, 7
            ],
            "IPv6 host datagrams: {output}"
        );
        output
    });
    assert!(output.contains("SOCKET_QUIC_OK"), "{output}");
}

/// A consumed seven-byte datagram leaves 49,117 bytes of a 48-KiB peer window available.
/// A 49,120-byte GSO batch must request fresh credit from a peer that sends no replies.
#[test]
#[ignore = "boots a real microVM; requires a native hypervisor and matching kernel"]
fn static_quic_gso_requests_credit_for_an_atomic_batch() {
    let suite = Suite::new();
    let probe = suite.compile_probe("socket");
    let socket = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let directory = probe.parent().unwrap();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let output = std::thread::scope(|threads| {
        let sink = threads.spawn(|| {
            let deadline = Instant::now() + Duration::from_secs(90);
            let mut datagrams = 0;
            let mut bytes = [0; 1201];
            while !stop.load(std::sync::atomic::Ordering::Relaxed) && Instant::now() < deadline {
                match socket.recv_from(&mut bytes) {
                    Ok((length, _peer)) => {
                        if datagrams == 0 {
                            assert_eq!(&bytes[..length], b"CREDIT!");
                            std::fs::write(directory.join("UDP_CREDIT_FIRST_RECEIVED"), [])
                                .unwrap();
                        } else {
                            assert!(datagrams <= 40);
                            assert_eq!(length, 1200);
                            let payload_start = (datagrams - 1) * 1200;
                            assert!(bytes[..length].iter().enumerate().all(|(offset, byte)| {
                                let index = payload_start + offset;
                                usize::from(*byte) == (index * 17 + index / 1200) % 251
                            }));
                        }
                        datagrams += 1;
                        if datagrams == 41 {
                            std::fs::write(directory.join("UDP_CREDIT_BATCH_RECEIVED"), [])
                                .unwrap();
                        }
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(error) => panic!("one-way QUIC credit sink: {error}"),
                }
            }
            datagrams
        });
        let recipe = suite.get_work_dir().join("socket-quic-credit.yaml");
        std::fs::write(&recipe, format!(
            "network:\n  allow: [HOST_LOOPBACK:{port}]\n{}mounts:\n  - host: {}\n    guest: /work\n    readonly: true\n",
            render_socket_probe_workload(vec!["--quic-credit".into(), "100.96.0.1".into(), port.to_string()]),
            directory.display()
        )).unwrap();
        let output = suite.boot_recipe(&recipe, "socket-quic-credit", select_socket_probe_flags());
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(sink.join().unwrap(), 41, "{output}");
        output
    });
    assert!(output.contains("SOCKET_QUIC_CREDIT_OK"), "{output}");
}

#[test]
#[ignore = "boots a real microVM; requires a native hypervisor"]
fn static_socket_calls_forward_tcp_and_udp_through_authorized_broker() {
    let suite = Suite::new();
    let probe = suite.compile_probe("socket");
    let tcp = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let first_udp = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let second_udp = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    let ports = [
        tcp.local_addr().unwrap().port(),
        first_udp.local_addr().unwrap().port(),
        second_udp.local_addr().unwrap().port(),
    ];
    let ipv6_udp = std::net::UdpSocket::bind(("::1", ports[1])).unwrap();
    let reply_marker = probe.parent().unwrap().join("UDP_ERROR_REPLY_SENT");
    let stop = std::sync::atomic::AtomicBool::new(false);
    let output = std::thread::scope(|threads| {
        threads.spawn(|| serve_socket_probe_tcp(&tcp, &stop));
        threads.spawn(|| serve_socket_probe_udp(&first_udp, &stop, &reply_marker));
        threads.spawn(|| serve_socket_probe_udp(&second_udp, &stop, &reply_marker));
        threads.spawn(|| serve_socket_probe_udp(&ipv6_udp, &stop, &reply_marker));
        let recipe = suite.get_work_dir().join("socket-external.yaml");
        std::fs::write(&recipe, format!(
            "network:\n  allow: [HOST_LOOPBACK:{}, HOST_LOOPBACK:{}, HOST_LOOPBACK:{}]\n{}mounts:\n  - host: {}\n    guest: /work\n    readonly: true\n",
            ports[0], ports[1], ports[2],
            render_socket_probe_workload(vec!["--external".into(), "100.96.0.1".into(), ports[0].to_string(), ports[1].to_string(), ports[2].to_string()]),
            probe.parent().unwrap().display()
        )).unwrap();
        let output = suite.boot_recipe(&recipe, "socket-external", select_socket_probe_flags());
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        output
    });
    assert!(output.contains("SOCKET_EXTERNAL_OK"), "{output}");
    assert!(output.contains("SOCKET_TCP_PEEK_OFFSET_OK"), "{output}");
    assert!(
        output.contains("SOCKET_NESTED_FORWARDING_UNSUPPORTED_OK"),
        "{output}"
    );
}

/// UDP publication retains datagrams and distinct relay peers, excludes loopback-only services,
/// and releases both transport listeners on stop before the same box restarts.
#[test]
#[ignore = "boots a real microVM; requires a native hypervisor and Zig"]
#[allow(clippy::too_many_lines)]
fn published_udp_preserves_peers_datagrams_and_transport_isolation() {
    use std::io::{Read as _, Write as _};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};

    let suite = Suite::new();
    let probe = suite.compile_probe("socket");
    let project = suite.create_project_dir("server");
    let (tcp_reservation, udp_reservation) = loop {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        match UdpSocket::bind(tcp.local_addr().unwrap()) {
            Ok(udp) => break (tcp, udp),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(error) => panic!("reserve publication port: {error}"),
        }
    };
    let port = udp_reservation.local_addr().unwrap().port();
    let local_reservation = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let local_port = local_reservation.local_addr().unwrap().port();
    let recipe = suite.get_work_dir().join("server.yaml");
    let configuration = serde_json::json!({
        "network": {"ports": [format!("{port}:18083/udp"), format!("{port}:18085/tcp"), format!("{local_port}:18084/udp")]},
        "mounts": [{"host": probe.parent().unwrap(), "guest": "/work", "readonly": true}],
        "daemons": [
            "/work/terra-socket-probe --published-udp 18083 > /tmp/udp-published.log 2>&1",
            "/work/terra-socket-probe --published-udp-loopback 18084 > /tmp/udp-loopback.log 2>&1",
            "while true; do printf 'TCP_PUBLICATION' | busybox nc -l -p 18085; done",
        ],
        "workload": {"entrypoint": "/bin/sleep", "args": ["infinity"]},
    });
    std::fs::write(&recipe, serde_json::to_vec(&configuration).unwrap()).unwrap();
    let project = project.to_str().unwrap();
    assert_eq!(
        suite
            .run_terra_status(&[recipe.to_str().unwrap(), "setup", "--project", project])
            .1,
        0
    );
    drop((tcp_reservation, udp_reservation, local_reservation));
    let clients = [
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap(),
        UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).unwrap(),
    ];
    for client in &clients {
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    let mut bytes = [0; 4097];
    for _ in 1..=2 {
        assert_eq!(
            suite
                .run_terra_status(&["server", "-d", "--project", project])
                .1,
            0
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let (logs, _) = suite.exec_in(
                "server",
                Path::new(project),
                false,
                &[
                    "sh",
                    "-c",
                    "cat /tmp/udp-published.log /tmp/udp-loopback.log 2>/dev/null || true",
                ],
            );
            if logs.matches("UDP_PUBLISHED_READY").count() == 2 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "UDP publication guest service did not start: {logs}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        for (index, client) in clients.iter().enumerate() {
            let address = SocketAddr::new(client.local_addr().unwrap().ip(), port);
            for payload in [
                vec![u8::try_from(index).unwrap(), 0, 255, 7],
                Vec::new(),
                vec![91; 4096],
            ] {
                client.send_to(&payload, address).unwrap();
                let received = client.recv_from(&mut bytes);
                if let Err(error) = &received {
                    let (guest_logs, _) = suite.exec_in(
                        "server",
                        Path::new(project),
                        false,
                        &[
                            "sh",
                            "-c",
                            "cat /tmp/udp-published.log /tmp/udp-loopback.log",
                        ],
                    );
                    let diagnostics = suite.run_terra_command(&[
                        "server",
                        "logs",
                        "--diagnostics",
                        "--project",
                        project,
                    ]);
                    panic!(
                        "UDP peer {index}, payload {} bytes: {error}\nguest services:\n{guest_logs}\ndiagnostics:\n{diagnostics}",
                        payload.len()
                    );
                }
                let (length, peer) = received.unwrap();
                assert_eq!(peer, address);
                assert_eq!(&bytes[..length], payload);
            }
        }
        let client = &clients[0];
        client
            .set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        client
            .send_to(&[73; 4097], (Ipv4Addr::LOCALHOST, port))
            .unwrap();
        let oversized = client.recv_from(&mut bytes).unwrap_err();
        assert_matches!(
            oversized.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        );
        client
            .send_to(b"local-only", (Ipv4Addr::LOCALHOST, local_port))
            .unwrap();
        let isolated = client.recv_from(&mut bytes).unwrap_err();
        assert_matches!(
            isolated.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        );
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .send_to(b"after-oversize", (Ipv4Addr::LOCALHOST, port))
            .unwrap();
        let (length, _) = client.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..length], b"after-oversize");
        let address = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
        let mut tcp = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        tcp.write_all(b"tcp-request").unwrap();
        tcp.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = Vec::new();
        tcp.read_to_end(&mut response).unwrap();
        assert_eq!(response, b"TCP_PUBLICATION");
        let (logs, status) = suite.exec_in(
            "server",
            Path::new(project),
            false,
            &["cat", "/tmp/udp-published.log"],
        );
        assert_eq!(status, 0);
        let relay_ports: std::collections::BTreeSet<_> = logs
            .lines()
            .filter_map(|line| {
                line.split_once("UDP_PUBLISHED_PEER_OK port=")?
                    .1
                    .split_whitespace()
                    .next()
            })
            .collect();
        assert!(
            relay_ports.len() == 3,
            "UDP publication must keep one distinct guest relay socket per host peer: {logs}"
        );
        assert_eq!(
            suite
                .exec_in(
                    "server",
                    Path::new(project),
                    false,
                    &[
                        "rm",
                        "-f",
                        "/tmp/udp-published.log",
                        "/tmp/udp-loopback.log"
                    ]
                )
                .1,
            0
        );
        assert_eq!(
            suite
                .run_terra_status(&["server", "stop", "--project", project])
                .1,
            0
        );
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
        assert!(UdpSocket::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
        assert!(UdpSocket::bind((Ipv6Addr::LOCALHOST, port)).is_ok());
        assert!(UdpSocket::bind((Ipv4Addr::LOCALHOST, local_port)).is_ok());
    }
}

/// A native reset after remote FIN reaches the guest while the guest write half remains open.
#[cfg(unix)]
#[test]
#[ignore = "boots a real microVM; requires a native hypervisor and Zig"]
fn native_tcp_reset_after_fin_preserves_the_socket_error() {
    use std::io::Read as _;
    use std::net::{Ipv4Addr, Shutdown, TcpListener};

    let suite = Suite::new();
    let probe = suite.compile_probe("socket");
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut observed_fin = [0];
        stream.read_exact(&mut observed_fin).unwrap();
        assert_eq!(&observed_fin, b"R");
        rustix::net::sockopt::set_socket_linger(&stream, Some(Duration::ZERO)).unwrap();
    });
    let recipe = suite.get_work_dir().join("socket-reset-after-fin.yaml");
    let configuration = serde_json::json!({
        "network": {"allow": [format!("HOST_LOOPBACK:{port}")]},
        "mounts": [{"host": probe.parent().unwrap(), "guest": "/work", "readonly": true}],
        "workload": {"entrypoint": "/work/terra-socket-probe", "args": ["--reset-after-fin", "100.96.0.1", port.to_string()]},
    });
    std::fs::write(&recipe, serde_json::to_vec(&configuration).unwrap()).unwrap();
    let output = suite.boot_recipe(
        &recipe,
        "socket-reset-after-fin",
        select_socket_probe_flags(),
    );
    server.join().unwrap();
    assert!(output.contains("SOCKET_RESET_AFTER_FIN_OK"), "{output}");
}

/// Completed execs release their agent streams and client slots before the 64-stream limit.
#[test]
#[ignore = "boots a real microVM - requires a native hypervisor: cargo test --test boot -- --ignored"]
fn sequential_execs_reuse_agent_client_slots() {
    let suite = Suite::new();
    let project = suite.create_project_dir("server");
    let recipe = suite.get_work_dir().join("server.yaml");
    std::fs::write(
        &recipe,
        "workload:\n  entrypoint: /bin/sleep\n  args: [infinity]\n",
    )
    .unwrap();
    let project = project.to_str().unwrap();
    assert_eq!(
        suite
            .run_terra_status(&[recipe.to_str().unwrap(), "setup", "--project", project])
            .1,
        0
    );
    assert_eq!(
        suite
            .run_terra_status(&["server", "-d", "--project", project])
            .1,
        0
    );

    for attempt in 1..=70 {
        let mut command = Command::new(&suite.terra)
            .args(["server", "exec", "--project", project, "--", "/bin/true"])
            .env("HOME", &suite.home)
            .env("USERPROFILE", &suite.home)
            .env_remove("RUST_LOG")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = command.try_wait().unwrap() {
                assert!(status.success(), "exec {attempt} failed: {status}");
                break;
            }
            if Instant::now() >= deadline {
                command.kill().unwrap();
                command.wait().unwrap();
                panic!("exec {attempt} stalled");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

/// One sequential run: later groups lean on the detached server VM the ports
/// group boots, so the order is part of the suite.
#[allow(clippy::too_many_lines)]
#[test]
#[ignore = "boots real microVMs - requires a native hypervisor: cargo test --test boot -- --ignored"]
fn run_boot_suite() {
    let s = Suite::new();
    let listener = std::net::TcpListener::bind("127.0.0.1:18080")
        .expect("the boot suite needs host port 18080 free for its server VM");
    drop(listener);

    // == egress: a name is exact, and the subtree is opted into ==
    let out = s.boot("egress", &[]);
    assert!(
        out.contains("ALLOWED_OK"),
        "allowed host unreachable:\n{out}"
    );
    assert!(
        out.contains("SUB_BLOCKED"),
        "a subdomain of an exact rule got out:\n{out}"
    );
    assert!(
        out.contains("DENIED_BLOCKED"),
        "denied host reachable:\n{out}"
    );
    // Host diagnostics stay out of the workload's terminal: they belong in the
    // box's log - and the refusal message is terra's own policy talking.
    let log = std::fs::read_to_string(s.get_box_files_path("egress").join("terra.log"))
        .unwrap_or_default();
    assert!(
        log.contains("policy denied name lookup"),
        "the log does not name the refused query:\n{log}"
    );
    assert!(
        !out.contains("virtio-net:"),
        "guest stream carries host log lines:\n{out}"
    );

    let out = s.boot("egress-wildcard", &[]);
    assert!(
        out.contains("SUB_OK"),
        "wildcard did not reach the subtree:\n{out}"
    );
    assert!(
        out.contains("APEX_BLOCKED"),
        "wildcard reached the apex:\n{out}"
    );

    // == on_create: baked once, stamped in the guest, skipped after ==
    let first = s.boot("bake", &[]);
    let second = s.boot("bake", &[]);
    let when = |out: &str| {
        out.lines()
            .find_map(|l| l.strip_prefix("WHEN=").map(str::to_owned))
    };
    assert!(
        first.contains("STAMP=mkdir -p /opt/baked;"),
        "the recipe is not stamped inside the guest:\n{first}"
    );
    assert!(
        when(&first).is_some() && when(&first) == when(&second),
        "on_create re-ran: {:?} vs {:?}",
        when(&first),
        when(&second)
    );

    // == ports + isolation: one VM publishes, another reaches it via hosts ==
    let server = s.create_project_dir("server");
    s.run_terra_command(&[
        &assets_dir().join("server.yaml").to_string_lossy(),
        "setup",
        "--project",
        server.to_str().unwrap(),
    ]);
    s.run_terra_command(&["server", "-d", "--project", server.to_str().unwrap()]);
    // The gateway binds the host port before the guest listens, so poll for
    // content; ~60s covers the server VM's boot plus its `apk add`.
    let deadline = Instant::now() + Duration::from_mins(1);
    let mut body = String::new();
    while Instant::now() < deadline {
        if let Some(b) = http_get("127.0.0.1:18080", "127.0.0.1")
            && b.contains("HELLO_FROM_VMA")
        {
            body = b;
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let (server_logs, server_logs_status) =
        s.run_terra_status(&["logs", "--project", server.to_str().unwrap()]);
    assert!(
        body.contains("HELLO_FROM_VMA"),
        "published port never answered on the host loopback (logs status {server_logs_status}):\n{server_logs}"
    );

    // == the state directory is what guards the agent's port ==
    // The VMM binds `a` itself, and its exec service runs commands as guest
    // root, so the one thing between another account on this host and that
    // port is the mode of the directory it is bound in. terra's own umask
    // cannot be it. Asserted on a box that is *running*, since that is when
    // the sockets exist.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let files = s.get_box_files_path("server");
        let mode = std::fs::metadata(&files).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o700,
            "{} is {mode:o} - another account can reach the root-capable exec service",
            files.display()
        );
        assert!(
            files.join("a").exists(),
            "a running box is missing its agent socket"
        );
    }

    let out = s.boot("client-allowed", &[]);
    assert!(
        out.contains("HELLO_FROM_VMA"),
        "VM with a hosts rule could not reach the exposed port:\n{out}"
    );
    let out = s.boot("client-isolated", &[]);
    assert!(
        !out.contains("HELLO_FROM_VMA") && !out.contains("REACHED"),
        "VM without a hosts rule reached the port:\n{out}"
    );

    let (namespaces, status) = s.exec(
        false,
        &[
            "sh",
            "-ec",
            "test -d /proc/self/ns; test -e /proc/self/ns/user; test -e /proc/self/ns/pid; test -e /proc/self/ns/net; test -e /proc/self/ns/ipc; test -e /proc/self/ns/uts; test -e /proc/self/ns/mnt; test -r /proc/sys/user/max_user_namespaces; test $(cat /proc/sys/user/max_user_namespaces) -gt 0",
        ],
    );
    assert_eq!(status, 0, "unprivileged namespace basics: {namespaces}");
    let namespace_probe = s.compile_probe("namespace");
    s.run_terra_command(&[
        "server",
        "sync",
        namespace_probe.to_str().unwrap(),
        ":/tmp/terra-namespace-probe",
        "--project",
        server.to_str().unwrap(),
    ]);
    let (namespace_probe, status) = s.exec(false, &["/tmp/terra-namespace-probe"]);
    assert_eq!(
        status, 0,
        "unprivileged namespace creation: {namespace_probe}"
    );
    let (kernel_basics, status) = s.exec(
        true,
        &[
            "sh",
            "-ec",
            "mkdir -p /dev/net; if test ! -e /dev/net/tun; then mknod /dev/net/tun c 10 200; fi; test -c /dev/net/tun; : <> /dev/net/tun; apk add --no-cache iproute2; ip link add terra-veth0 type veth peer name terra-veth1; ip link add terra-br0 type bridge; ip link set terra-veth0 master terra-br0; ip link del terra-veth0; ip link del terra-br0",
        ],
    );
    assert_eq!(status, 0, "guest kernel container basics: {kernel_basics}");
    // The workload beside it is untouched: still uid 1000, no standing
    // escalation of its own - a `sudo:` grant is the thing this is not.
    assert!(s.exec(false, &["id", "-u"]).0.contains("1000"));
    // == detach: -d hands the box to a background VM ==
    // Fire-and-forget once the box is confirmed up: exit 0 whatever the
    // workload later does; console and state stay reachable via logs/status.
    // (A child that dies *before* owning the box replays its logs and exit
    // code - boot/lock failure, which no recipe can arrange.)
    let oneshot = s.get_work_dir().join("oneshot.yaml");
    std::fs::write(
        &oneshot,
        "workload:\n  entrypoint: /bin/sh\n  args: [-c, 'echo ONESHOT_RAN; exit 7']\n",
    )
    .unwrap();
    let oneshot_box = s.create_project_dir("oneshot");
    s.run_terra_command(&[
        oneshot.to_str().unwrap(),
        "setup",
        "--project",
        oneshot_box.to_str().unwrap(),
    ]);
    let out = Command::new(&s.terra)
        .args(["oneshot", "-d", "--project", oneshot_box.to_str().unwrap()])
        .env("HOME", &s.home)
        .env("USERPROFILE", &s.home)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .output()
        .expect("running terra");
    let narration = String::from_utf8_lossy(&out.stderr);
    assert!(
        narration.contains("started"),
        "-d did not say the box started:\n{narration}"
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "-d did not exit 0 after handing the box over"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline
        && !s
            .run_terra_command(&["ls", "--project", oneshot_box.to_str().unwrap()])
            .contains("stopped")
    {
        std::thread::sleep(Duration::from_secs(1));
    }
    assert!(
        s.run_terra_command(&["ls", "--project", oneshot_box.to_str().unwrap()])
            .contains("stopped"),
        "the box did not run to completion in the background"
    );
    // The log is the box's diagnostics - the boot is in it, the workload's
    // terminal is not. A detached run nobody attaches to is broadcast to the
    // session and to nothing else, which is why a box that wants a record of
    // its own output writes one to a volume it keeps.
    let log = s.run_terra_command(&["logs", "--project", oneshot_box.to_str().unwrap()]);
    assert!(
        log.contains("starting"),
        "the boot is not in the log:\n{log}"
    );
    assert!(
        !log.contains("ONESHOT_RAN"),
        "the workload's terminal reached the log:\n{log}"
    );

    // == daemons: background commands restarted on failure ==
    // Each line runs beside the workload as guest root; a non-zero exit
    // respawns it after a second, exit 0 leaves it done. The workload waits a
    // few seconds, so the console shows both the one-shot daemon and the
    // crash loop's restarts - then the box exits 0.
    let daemon_recipe = s.get_work_dir().join("daemon.yaml");
    std::fs::write(
        &daemon_recipe,
        "daemons:\n  - echo DAEMON_STARTED\n  - \"echo CRASH; exit 3\"\n\
         workload:\n  entrypoint: /bin/sh\n  args: [-c, 'sleep 4; echo WORKLOAD_DONE']\n",
    )
    .unwrap();
    let daemon_project = s.create_project_dir("daemon");
    let daemon_dir = daemon_project.to_str().unwrap();
    s.run_terra_command(&[
        daemon_recipe.to_str().unwrap(),
        "setup",
        "--project",
        daemon_dir,
    ]);
    let (out, code) = s.run_terra_status(&["daemon", "--foreground", "--project", daemon_dir]);
    assert_eq!(
        code, 0,
        "a box with daemons did not exit with its workload:\n{out}"
    );
    assert!(out.contains("DAEMON_STARTED"), "{out}");
    assert!(out.contains("WORKLOAD_DONE"), "{out}");
    assert!(
        out.matches("CRASH").count() >= 2,
        "the crashing daemon was not restarted:\n{out}"
    );

    let status_recipe = s.get_work_dir().join("exit-status.yaml");
    std::fs::write(&status_recipe, "workload:\n  entrypoint: /bin/true\n").unwrap();
    let status_project = s.create_project_dir("exit-status");
    let status_dir = status_project.to_str().unwrap();
    s.run_terra_command(&[
        status_recipe.to_str().unwrap(),
        "setup",
        "--project",
        status_dir,
    ]);
    let boot_with = |cmd: &str| {
        s.run_terra_status(&[
            "exit-status",
            "--foreground",
            "--project",
            status_dir,
            "--",
            "sh",
            "-c",
            cmd,
        ])
        .1
    };
    // A signal death is `128 + signal`, the way a shell spells it - and the way
    // `terra exec` already reports one, so a box and a command agree.
    assert_eq!(
        boot_with("kill -TERM $$"),
        128 + 15,
        "a signalled workload was not reported as 128 + signal"
    );
}

#[test]
#[ignore = "requires a native hypervisor"]
#[allow(clippy::too_many_lines)]
fn run_mount_boot_suite() {
    let s = Suite::new();

    // == workdir: created when missing, owned by the workload user ==
    let (out, _) = s.boot_with_share("workdir", &[]);
    assert!(out.contains("PWD=/work/nested/deep"), "{out}");
    assert!(out.contains("OWNER=1000:1000"), "{out}");
    assert!(out.contains("WRITE_OK"), "{out}");

    // == ownership: the FS always maps to terri; --root is exec-only ==
    let (out, prj) = s.boot_with_share("ownership", &[]);
    assert!(
        out.contains("EXEC=1000"),
        "default workload not terri:\n{out}"
    );
    assert!(out.contains("WORK=1000:1000"), "{out}");
    assert!(out.contains("WF_OK"), "{out}");
    assert!(out.contains("VOL=1000:1000"), "{out}");
    assert_eq!(std::fs::read(prj.join("wf")).unwrap(), b"w\n");
    #[cfg(unix)]
    assert_eq!(
        Suite::read_file_uid(&prj.join("wf")),
        Some(s.host_uid),
        "host file not owned by the launching user"
    );
    let (out, prj) = s.boot_with_share("ownership", &["--root"]);
    assert!(out.contains("EXEC=0"), "--root workload not root:\n{out}");
    assert!(
        out.contains("WORK=1000:1000"),
        "--root changed the FS mapping:\n{out}"
    );
    assert!(out.contains("WF_OK"), "{out}");
    assert_eq!(std::fs::read(prj.join("wf")).unwrap(), b"w\n");
    #[cfg(unix)]
    assert_eq!(Suite::read_file_uid(&prj.join("wf")), Some(s.host_uid));

    // == a guest repository keeps Git metadata, links, mmap writes, and atomic replaces ==
    let repository = s.get_work_dir().join("mount-repository");
    std::fs::create_dir(&repository).unwrap();
    let out = s.boot_with_repository_mount(
        "mount-repository",
        &repository,
        false,
        &r#"
git -C /work init
git -C /work config user.email terra@example.test
git -C /work config user.name terra
printf base > /work/base
ln /work/base /work/hard
ln -s base /work/link
git -C /work add base hard link
git -C /work commit -m base
base=$(git -C /work branch --show-current)
git -C /work checkout -b feature
printf feature > /work/feature
git -C /work add feature
git -C /work commit -m feature
git -C /work checkout "$base"
printf main > /work/main
git -C /work add main
git -C /work commit -m main
git -C /work merge --no-edit feature
git -C /work repack -ad
git -C /work fsck --no-dangling
inode=$(stat -c %i /work/link)
test "$(stat -c %i /work/link)" = "$inode"
git -C /work status --porcelain
git -C /work --no-pager diff
test -z "$(git -C /work status --porcelain)"
test -z "$(git -C /work diff)"
python3 - <<'PY'
import glob
import errno
import mmap
import os
import py_compile
from pathlib import Path
path = '/work/mapped'
with open(path, 'wb') as file:
    file.truncate(4096)
with open(path, 'r+b') as file:
    mapped = mmap.mmap(file.fileno(), 0)
    mapped[:4] = b'mmap'
    mapped.flush()
    mapped.close()
with open(path, 'r+b') as file:
    file.truncate(2)
with open(path, 'r+b') as file:
    assert file.read() == b'mm'
with open(glob.glob('/work/.git/objects/pack/*.pack')[0], 'rb') as file:
    packed = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
    assert len(packed) > 0
    packed.close()
Path('/work/edited').write_text('old')
with open('/work/edited') as previous:
    Path('/work/edited.tmp').write_text('new')
    os.replace('/work/edited.tmp', '/work/edited')
    assert previous.read() == 'old'
assert Path('/work/edited').read_text() == 'new'
Path('/work/build.py').write_text('answer = 42\n')
py_compile.compile('/work/build.py', cfile='/work/build.pyc', doraise=True)
assert Path('/work/build.pyc').stat().st_size > 0

def unsupported(name, operation):
    try:
        operation()
    except OSError as error:
        assert error.errno == errno.EOPNOTSUPP, (name, error)
    else:
        raise AssertionError(f'{name} unexpectedly succeeded')

HOST_MODE_ASSERTIONS
for _ in range(2):
    unsupported('setxattr', lambda: os.setxattr(path, 'user.terra', b'guest-value'))
    unsupported('getxattr', lambda: os.getxattr(path, 'user.terra'))
    unsupported('listxattr', lambda: os.listxattr(path))
    unsupported('removexattr', lambda: os.removexattr(path, 'user.terra'))
with open(path, 'r+b') as file:
    unsupported('fallocate', lambda: os.posix_fallocate(file.fileno(), 0, 1))
    unsupported('seek-data', lambda: os.lseek(file.fileno(), 0, os.SEEK_DATA))
try:
    os.open(b'/work/\xff', os.O_WRONLY | os.O_CREAT, 0o600)
except OSError as error:
    assert error.errno == errno.EILSEQ, error
else:
    raise AssertionError('non-UTF-8 name unexpectedly succeeded')
print('UNSUPPORTED_MOUNT_OPERATIONS_OK')
PY
git -C /work add mapped edited build.py build.pyc
git -C /work commit -m mmap
echo REPOSITORY_OK
"#
        .replace(
            "HOST_MODE_ASSERTIONS",
            if cfg!(windows) {
                "unsupported('chmod', lambda: os.chmod(path, 0o600))"
            } else {
                "os.chmod(path, 0o600)\nassert os.stat(path).st_mode & 0o7777 == 0o600"
            },
        ),
    );
    assert!(out.contains("REPOSITORY_OK"), "{out}");
    assert!(out.contains("UNSUPPORTED_MOUNT_OPERATIONS_OK"), "{out}");
    assert!(repository.join(".git/objects/pack").is_dir());
    assert_eq!(std::fs::read(repository.join("mapped")).unwrap(), b"mm");
    let out = s.boot_with_repository_mount(
        "mount-repo-ro",
        &repository,
        true,
        r#"
git -C /work fsck --no-dangling
git -C /work status --porcelain
test -z "$(git -C /work status --porcelain)"
test "$(cat /work/feature)" = feature
echo REPOSITORY_READONLY_OK
"#,
    );
    assert!(out.contains("REPOSITORY_READONLY_OK"), "{out}");
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn console_input() -> (std::fs::File, std::fs::File) {
    use std::os::fd::FromRawFd;
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: openpty writes two owned descriptors; optional output/configuration pointers are null.
    let result = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    // SAFETY: successful openpty returned distinct descriptors, each transferred exactly once.
    unsafe {
        (
            std::fs::File::from_raw_fd(master),
            std::fs::File::from_raw_fd(slave),
        )
    }
}

/// Foreground owns the VM process and lock, so killing the command cannot leave a detached VM.
#[test]
#[ignore = "boots a real VM and requires a native hypervisor"]
fn foreground_process_owns_the_vm_and_releases_its_lock_on_death() {
    use std::io::BufRead as _;

    let suite = Suite::new();
    let project = suite.create_project_dir("server");
    let recipe = suite.get_work_dir().join("server.yaml");
    std::fs::write(
        &recipe,
        "workload:\n  entrypoint: /bin/sh\n  args: [-c, 'echo FOREGROUND_READY; sleep 300']\n",
    )
    .unwrap();
    let (_, setup_code) = suite.run_terra_status(&[
        recipe.to_str().unwrap(),
        "setup",
        "--project",
        project.to_str().unwrap(),
    ]);
    assert_eq!(setup_code, 0);
    let box_dir = suite.get_box_files_path("server");
    let mut child = Command::new(&suite.terra)
        .args([
            "server",
            "--foreground",
            "--project",
            project.to_str().unwrap(),
        ])
        .env("HOME", &suite.home)
        .env("USERPROFILE", &suite.home)
        .env_remove("RUST_LOG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let result = std::io::BufReader::new(stdout).read_line(&mut line);
        let _ = sender.send(result.map(|_| line));
    });
    let ready = receiver.recv_timeout(Duration::from_secs(90));
    let published = std::fs::read_to_string(box_dir.join("terra.pid"));
    let _ = child.kill();
    child.wait().unwrap();
    let ready = ready.unwrap().unwrap();
    assert!(ready.trim_end().ends_with("FOREGROUND_READY"), "{ready:?}");
    let published_pid: u32 = published
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    assert_ne!(published_pid, child.id(), "foreground VM ran in the parent");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (listing, code) =
            suite.run_terra_status(&["ls", "--json", "--project", project.to_str().unwrap()]);
        assert_eq!(code, 0);
        let boxes: serde_json::Value = serde_json::from_str(&listing).unwrap();
        let stopped = boxes[0]["state"] == "stopped";
        #[cfg(target_os = "linux")]
        let vm_exited = !linux_process_is_live(published_pid);
        #[cfg(not(target_os = "linux"))]
        let vm_exited = true;
        if stopped && vm_exited {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "foreground death left VM running: {listing}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
#[test]
#[ignore = "boots a real VM and requires a native hypervisor"]
fn attached_console_streams_hooks_before_workload_and_exit() {
    use std::io::Read;
    let suite = Suite::new();
    let project = suite.create_project_dir("server");
    let recipe = suite.get_work_dir().join("hooks.yaml");
    std::fs::write(
        &recipe,
        "hw: {cpus: 2, mem_mib: 512}\nhooks:\n  on_start:\n    - printf 'HOOK_START\\n'; sleep 2; printf 'HOOK_STDERR\\n' >&2\n  pre_stop:\n    - printf 'HOOK_STOP\\n'; printf 'STOP_STDERR\\n' >&2; exit 9\nworkload:\n  entrypoint: /bin/sh\n  args: [-c, \"printf 'WORKLOAD_READY\\n'; exit 7\"]\n",
    )
    .unwrap();
    let (_, setup_code) = suite.run_terra_status(&[
        recipe.to_str().unwrap(),
        "setup",
        "--project",
        project.to_str().unwrap(),
    ]);
    assert_eq!(setup_code, 0);
    let (_master, slave) = console_input();
    let mut child = Command::new(&suite.terra)
        .args(["hooks", "--project", project.to_str().unwrap()])
        .env("HOME", &suite.home)
        .env("USERPROFILE", &suite.home)
        .env_remove("RUST_LOG")
        .stdin(slave)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = [0; 4096];
        while let Ok(len) = stdout.read(&mut bytes) {
            if len == 0 || sender.send(bytes[..len].to_vec()).is_err() {
                break;
            }
        }
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut output = String::new();
    let mut hook_started = None;
    let mut workload_started = None;
    loop {
        if let Ok(bytes) = receiver.recv_timeout(Duration::from_millis(50)) {
            output.push_str(&String::from_utf8_lossy(&bytes));
        }
        if hook_started.is_none() && output.contains("HOOK_START") {
            hook_started = Some(Instant::now());
        }
        if workload_started.is_none() && output.contains("WORKLOAD_READY") {
            workload_started = Some(Instant::now());
        }
        if child.try_wait().unwrap().is_some() {
            for bytes in receiver {
                output.push_str(&String::from_utf8_lossy(&bytes));
            }
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("hook console timed out: {output}");
        }
    }
    assert_eq!(child.wait().unwrap().code(), Some(7), "{output}");
    if workload_started.is_none() && output.contains("WORKLOAD_READY") {
        workload_started = Some(Instant::now());
    }
    assert!(
        workload_started
            .unwrap()
            .duration_since(hook_started.unwrap())
            >= Duration::from_secs(1),
        "startup output was delayed until after the hook: {output}"
    );
    for marker in ["HOOK_STDERR", "HOOK_STOP", "STOP_STDERR"] {
        assert!(output.contains(marker), "missing {marker}: {output}");
    }
    assert!(
        output.contains("HOOK_START\r\n"),
        "terminal line endings: {output:?}"
    );
    assert!(output.find("WORKLOAD_READY").unwrap() < output.find("HOOK_STOP").unwrap());
}

#[test]
#[ignore = "boots a VM at platform CPU/storage capacity and requires a native hypervisor"]
fn capacity_machine_vcpus_and_storage_devices() {
    const STORAGE_PER_KIND: usize = terra_runtime::machine::MAX_GUEST_STORAGE_DEVICES / 2;
    let cpus = terra_runtime::machine::MAX_VCPUS;
    let last_cpu = cpus - 1;
    let last_mount = STORAGE_PER_KIND - 1;
    let suite = Suite::new();
    let host_dirs = (0..STORAGE_PER_KIND)
        .map(|index| {
            let path = suite.get_work_dir().join(format!("capacity-mount-{index}"));
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("host-seed"), format!("host-{index}")).unwrap();
            path
        })
        .collect::<Vec<_>>();
    let recipe = suite.get_work_dir().join("capacity.yaml");
    let volumes = (0..STORAGE_PER_KIND)
        .map(|index| {
            format!("  - name: volume-{index}\n    guest: /volume-{index}\n    size_mib: 8")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let targets = (0..STORAGE_PER_KIND)
        .map(|index| format!("/mount-{index}"))
        .chain((0..STORAGE_PER_KIND).map(|index| format!("/volume-{index}")))
        .collect::<Vec<_>>()
        .join(" ");
    let mounts = host_dirs
        .iter()
        .enumerate()
        .map(|(index, host)| format!("  - host: {}\n    guest: /mount-{index}", host.display()))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(
        &recipe,
        format!(
            "hw: {{cpus: {cpus}, mem_mib: 512}}\nvolumes:\n{volumes}\nmounts:\n{mounts}\nworkload:\n  entrypoint: /bin/sh\n  args:\n    - -ec\n    - |\n      test \"$(nproc)\" = {cpus}\n      test \"$(cat /sys/devices/system/cpu/online)\" = 0-{last_cpu}\n      grep -Eq '0x0*5' /sys/bus/virtio/devices/*/device\n      for target in {targets}; do\n        (\n          i=0\n          while test \"$i\" -lt 16; do\n            value=\"$target:$i\"\n            printf '%s' \"$value\" > \"$target/roundtrip\"\n            test \"$(cat \"$target/roundtrip\")\" = \"$value\"\n            i=$((i + 1))\n          done\n        ) &\n      done\n      wait\n      for index in $(seq 0 {last_mount}); do test \"$(cat /mount-$index/host-seed)\" = host-$index; done\n      echo CAPACITY_OK\n"
        ),
    )
    .unwrap();

    let output = suite.boot_recipe(&recipe, "capacity", &[]);
    assert!(output.contains("CAPACITY_OK"), "{output}");
    for (index, host) in host_dirs.iter().enumerate() {
        assert_eq!(
            std::fs::read_to_string(host.join("roundtrip")).unwrap(),
            format!("/mount-{index}:15")
        );
    }
}

#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "boots a VM with 32 volumes and requires a native hypervisor"]
fn capacity_32_volumes_reaches_vdah() {
    const VOLUMES: usize = 32;
    let suite = Suite::new();
    let recipe = suite.get_work_dir().join("capacity-volumes.yaml");
    let volumes = (0..VOLUMES)
        .map(|index| {
            format!("  - name: volume-{index}\n    guest: /volume-{index}\n    size_mib: 8")
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(
        &recipe,
        format!(
            "hw: {{cpus: 2, mem_mib: 512}}\nvolumes:\n{volumes}\nworkload:\n  entrypoint: /bin/sh\n  args:\n    - -ec\n    - |\n      test -b /dev/vdah\n      for index in $(seq 0 31); do\n        value=volume-$index\n        printf '%s' \"$value\" > \"/volume-$index/roundtrip\"\n        test \"$(cat \"/volume-$index/roundtrip\")\" = \"$value\"\n      done\n      echo VOLUME_CAPACITY_OK\n"
        ),
    )
    .unwrap();

    let output = suite.boot_recipe(&recipe, "capacity-volumes", &[]);
    assert!(output.contains("VOLUME_CAPACITY_OK"), "{output}");
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
#[ignore = "requires x86 KVM with a known TSC frequency and an always-running APIC timer"]
fn local_apic_timers_work_without_a_legacy_clockevent() {
    let suite = Suite::new();
    for cpus in [1, 2] {
        let name = format!("pitless-{cpus}");
        let recipe = suite.get_work_dir().join(format!("{name}.yaml"));
        std::fs::write(
            &recipe,
            format!(
                r#"hw: {{cpus: {cpus}, mem_mib: 512}}
workload:
  entrypoint: /bin/sh
  args:
    - -ec
    - |
      ! grep -Eq '^[[:space:]]*0:' /proc/interrupts
      for timer in /sys/devices/system/clockevents/clockevent[0-9]*/current_device; do
        grep -Eq '^lapic(-deadline)?$' "$timer"
      done
      before=$(awk '/LOC:/ {{for (i=2; i<=NF; i++) n+=$i; print n}}' /proc/interrupts)
      sleep 1
      after=$(awk '/LOC:/ {{for (i=2; i<=NF; i++) n+=$i; print n}}' /proc/interrupts)
      test "$after" -gt "$before"
      echo PITLESS_TIMERS_OK
"#
            ),
        )
        .unwrap();
        let output = suite.boot_recipe(&recipe, &name, &[]);
        assert!(output.contains("PITLESS_TIMERS_OK"), "{output}");
    }
}

/// Readiness ends the boot deadline before either kind of hook runs. Detached
/// startup acknowledges readiness while the startup hook is still blocked.
#[test]
#[ignore = "requires a native hypervisor and about 130 seconds for hooks"]
fn agent_readiness_precedes_long_bake_and_start_hooks() {
    let suite = Suite::new();
    let project = suite.create_project_dir("server");
    let share = suite.get_work_dir().join("hook-share");
    std::fs::create_dir(&share).unwrap();
    let recipe = suite.get_work_dir().join("server.yaml");
    std::fs::write(&recipe, format!(
        "hw: {{cpus: 2, mem_mib: 512}}\nhooks:\n  on_create:\n    - sleep 65; touch /baked\n  on_start:\n    - while [ ! -e /work/release ]; do sleep 1; done; touch /work/finished\nworkload:\n  entrypoint: /bin/sleep\n  args: [infinity]\nmounts:\n  - host: {}\n    guest: /work\n",
        share.display(),
    )).unwrap();
    let project = project.to_str().unwrap();
    let (_, setup_code) =
        suite.run_terra_status(&[recipe.to_str().unwrap(), "setup", "--project", project]);
    assert_eq!(setup_code, 0, "long bake was mistaken for a stalled boot");
    let (_, start_code) = suite.run_terra_status(&["server", "-d", "--project", project]);
    assert_eq!(start_code, 0);
    assert!(
        !share.join("finished").exists(),
        "detached startup waited for hooks"
    );
    std::thread::sleep(Duration::from_secs(65));
    std::fs::write(share.join("release"), b"").unwrap();
    let (_, code) = suite.exec_in(
        "server",
        Path::new(project),
        false,
        &["/bin/sh", "-ec", "test -e /baked; test -e /work/finished"],
    );
    assert_eq!(code, 0, "long startup hook was mistaken for a stalled boot");
}

#[cfg(target_os = "linux")]
fn linux_process_is_live(pid: u32) -> bool {
    let status = match std::fs::read_to_string(format!("/proc/{pid}/status")) {
        Ok(status) => status,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(error) => panic!("reading VM status: {error}"),
    };
    !status
        .lines()
        .any(|line| line.starts_with("State:") && line.split_whitespace().nth(1) == Some("Z"))
}

#[cfg(target_os = "linux")]
fn linux_descendant_pids(pid: u32) -> Vec<u32> {
    let children = std::fs::read_dir(format!("/proc/{pid}/task"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|task| std::fs::read_to_string(task.path().join("children")).unwrap_or_default())
        .collect::<String>();
    let mut descendants = Vec::new();
    for child in children.split_whitespace() {
        let child = child.parse().unwrap();
        descendants.push(child);
        descendants.extend(linux_descendant_pids(child));
    }
    descendants
}

#[cfg(target_os = "linux")]
fn read_linux_process_identity(path: &Path) -> u32 {
    std::fs::read_to_string(path)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

#[cfg(target_os = "linux")]
fn find_network_broker(workers: &[u32]) -> u32 {
    let brokers = workers
        .iter()
        .copied()
        .filter(|worker| {
            std::fs::read(format!("/proc/{worker}/cmdline"))
                .unwrap_or_default()
                .split(|byte| *byte == 0)
                .nth(1)
                == Some(b"__network".as_slice())
        })
        .collect::<Vec<_>>();
    assert_eq!(brokers.len(), 1, "box must own exactly one network broker");
    brokers[0]
}

/// Broker loss disables networking while agent exec and stop remain live;
/// supervisor loss tears down all workers, and the same box can start again.
/// Pidfds wait for every thread even when a process leader is already a zombie.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires native KVM and Bubblewrap user namespaces"]
#[allow(clippy::too_many_lines)]
fn broker_loss_preserves_agent_and_supervisor_loss_stops_the_box() {
    let suite = Suite::new();
    std::fs::remove_file(suite.home.join(".terra/config.yaml")).unwrap();
    let project = suite.create_project_dir("server");
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    let recipe = suite.get_work_dir().join("server.yaml");
    std::fs::write(
        &recipe,
        format!("network:\n  ports: ['{port}:8080']\nworkload:\n  entrypoint: /bin/sleep\n  args: [infinity]\n"),
    )
    .unwrap();
    let project = project.to_str().unwrap();
    assert_eq!(
        suite
            .run_terra_status(&[recipe.to_str().unwrap(), "setup", "--project", project])
            .1,
        0
    );
    drop(reservation);
    for kill_supervisor in [true, false] {
        assert_eq!(
            suite
                .run_terra_status(&["server", "-d", "--project", project])
                .1,
            0
        );
        let directory = suite.get_box_files_path("server");
        let supervisor = read_linux_process_identity(&directory.join("supervisor.pid"));
        let vm = read_linux_process_identity(&directory.join("host.pid"));
        let mut workers = linux_descendant_pids(supervisor);
        assert!(
            workers.contains(&vm),
            "VM {vm} is outside supervisor {supervisor} descendants: {workers:?}",
        );
        let broker = find_network_broker(&workers);
        workers.push(supervisor);
        let worker_exit_handles = workers
            .iter()
            .map(|worker| {
                let pid = rustix::process::Pid::from_raw(i32::try_from(*worker).unwrap()).unwrap();
                let descriptor =
                    rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap();
                (*worker, descriptor)
            })
            .collect::<Vec<_>>();
        assert!(std::net::TcpListener::bind(("127.0.0.1", port)).is_err());
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(
                i32::try_from(if kill_supervisor { supervisor } else { broker }).unwrap(),
            )
            .unwrap(),
            rustix::process::Signal::KILL,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        if !kill_supervisor {
            loop {
                let diagnostics =
                    std::fs::read_to_string(directory.join("diagnostics.log")).unwrap_or_default();
                if !linux_process_is_live(broker)
                    && diagnostics.contains("network unavailable: owner: Network is down")
                    && std::net::TcpListener::bind(("127.0.0.1", port)).is_ok()
                {
                    break;
                }
                assert!(
                    Instant::now() < deadline,
                    "broker loss did not retire networking: {diagnostics}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            assert!(linux_process_is_live(vm), "VM died with broker");
            assert!(
                linux_process_is_live(supervisor),
                "supervisor died with broker"
            );
            assert_eq!(
                suite.exec_in(
                    "server",
                    Path::new(project),
                    false,
                    &["printf", "agent-after-broker-loss"]
                ),
                ("agent-after-broker-loss".into(), 0),
            );
            assert_eq!(
                suite
                    .run_terra_status(&["server", "stop", "--project", project])
                    .1,
                0,
                "agent stop failed after broker loss",
            );
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        for (worker, descriptor) in worker_exit_handles {
            let timeout = rustix::event::Timespec::try_from(
                deadline.saturating_duration_since(Instant::now()),
            )
            .unwrap();
            let mut exited = [rustix::event::PollFd::new(
                &descriptor,
                rustix::event::PollFlags::IN,
            )];
            assert_eq!(
                rustix::event::poll(&mut exited, Some(&timeout)).unwrap(),
                1,
                "worker {worker} survived {}",
                if kill_supervisor {
                    "supervisor loss"
                } else {
                    "agent stop"
                }
            );
        }
        drop(std::net::TcpListener::bind(("127.0.0.1", port)).unwrap());
    }
}

/// The enforced policy reaches the live VM and every thread, including vCPUs.
/// Trace mode runs the same VM lifecycle before the policy exists.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a native hypervisor and an enforced Bubblewrap policy"]
#[allow(clippy::too_many_lines)]
fn bwrap_enforces_vm_and_vcpu_threads() {
    let suite = Suite::new();
    let enforced = std::env::var("TERRA_SECCOMP_ENFORCED").as_deref() == Ok("1");
    if enforced {
        std::fs::remove_file(suite.home.join(".terra/config.yaml")).unwrap();
    }
    let project = suite.create_project_dir("server");
    let recipe = suite.get_work_dir().join("server.yaml");
    std::fs::write(
        &recipe,
        "hw: {cpus: 2, mem_mib: 512}\nworkload:\n  entrypoint: /bin/sleep\n  args: [infinity]\n",
    )
    .unwrap();
    let project = project.to_str().unwrap();
    assert_eq!(
        suite
            .run_terra_status(&[recipe.to_str().unwrap(), "setup", "--project", project])
            .1,
        0
    );
    assert_eq!(
        suite
            .run_terra_status(&["server", "-d", "--project", project])
            .1,
        0
    );

    let box_dir = suite.get_box_files_path("server");
    let identity = if enforced { "host.pid" } else { "terra.pid" };
    let pid = read_linux_process_identity(&box_dir.join(identity));
    let mut workers = vec![pid];
    if enforced {
        let supervisor = read_linux_process_identity(&box_dir.join("supervisor.pid"));
        assert_ne!(supervisor, pid);
        workers.extend(linux_descendant_pids(supervisor));
        workers.push(supervisor);
        let broker = find_network_broker(&workers);
        assert_eq!(
            std::fs::read_link(format!("/proc/{broker}/ns/net")).unwrap(),
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            "broker lost host networking"
        );
        assert_ne!(
            std::fs::read_link(format!("/proc/{broker}/ns/mnt")).unwrap(),
            std::fs::read_link(format!("/proc/{pid}/ns/mnt")).unwrap(),
            "broker shares VM filesystem grants"
        );
        for namespace in ["pid", "mnt", "user", "ipc", "uts", "net"] {
            let parent_ns = std::fs::read_link(format!("/proc/self/ns/{namespace}")).unwrap();
            let vm_ns = std::fs::read_link(format!("/proc/{pid}/ns/{namespace}")).unwrap();
            assert_ne!(
                vm_ns, parent_ns,
                "VM still uses the parent's {namespace} namespace"
            );
        }

        let task_dir = format!("/proc/{pid}/task");
        let tasks = std::fs::read_dir(&task_dir)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(tasks.len() > 1, "VM has no visible vCPU or worker threads");
        let mut checked_threads = 0;
        for task in tasks {
            let status = match std::fs::read_to_string(task.path().join("status")) {
                Ok(status) => status,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => panic!("reading thread {}: {error}", task.path().display()),
            };
            checked_threads += 1;
            for (field, expected) in [("Seccomp:", "2"), ("NoNewPrivs:", "1")] {
                let actual = status
                    .lines()
                    .find_map(|line| line.strip_prefix(field))
                    .map(str::trim);
                assert_eq!(
                    actual,
                    Some(expected),
                    "thread {} has wrong {field}: {status}",
                    task.path().display()
                );
            }
        }
        assert!(
            checked_threads > 1,
            "VM threads exited before policy inspection"
        );
    }

    if enforced {
        std::fs::write(box_dir.join("terra.pid"), b"forged by a guest").unwrap();
        std::fs::remove_file(box_dir.join("c")).unwrap();
    }

    let stop_args: &[&str] = if enforced {
        &["server", "stop", "--timeout", "0", "--project", project]
    } else {
        &["server", "stop", "--project", project]
    };
    assert_eq!(suite.run_terra_status(stop_args).1, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    while let Some(worker) = workers
        .iter()
        .copied()
        .find(|pid| linux_process_is_live(*pid))
    {
        assert!(
            Instant::now() < deadline,
            "box worker {worker} survived stop"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
