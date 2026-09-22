//! Boot suite - the product gate. Boots real microVMs with the native hypervisor and
//! asserts what host-side tests cannot: egress enforcement, the uid/ownership
//! model, the guest-side `on_create` bake, cross-VM port publishing and
//! isolation, exec, cp, and detach. Excluded from a default `cargo test`:
//!
//!   cargo test -p terra --test boot -- --ignored
//!
//! `TERRA_BIN` overrides the binary under test (CI points it at `dist/terra`,
//! the shipped artifact); default is the cargo-built one.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ASSETS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/assets");

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
            String::from_utf8_lossy(&out.stdout).into_owned(),
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
    /// recipe (and bakes `on_create` in its isolated VM - whose console goes to
    /// the box's log, not setup's stdout), then the bare form boots it. The
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
        self.boot_recipe(&Path::new(ASSETS).join(format!("{name}.yaml")), name, extra)
    }

    /// The asset plus a `mounts:` entry pointing /work at a directory this
    /// suite owns - nothing is shared with a sandbox unless its recipe says so.
    fn boot_with_share(&self, name: &str, extra: &[&str]) -> (String, PathBuf) {
        let prj = self.get_work_dir().join(format!("{name}-proj"));
        std::fs::create_dir_all(&prj).unwrap();
        let recipe = self.get_work_dir().join(format!("{name}.yaml"));
        let base = std::fs::read_to_string(Path::new(ASSETS).join(format!("{name}.yaml"))).unwrap();
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

    fn boot_with_mount(&self, name: &str, host: &Path, readonly: bool, script: &str) -> String {
        let recipe = self.get_work_dir().join(format!("{name}.yaml"));
        let script = script.replace('\n', "\n      ");
        let readonly = if readonly { "    readonly: true\n" } else { "" };
        std::fs::write(
            &recipe,
            format!(
                "workload:\n  entrypoint: /bin/sh\n  args:\n    - -ec\n    - |\n      {script}\nmounts:\n  - host: {}\n    guest: /work\n{readonly}",
                host.display()
            ),
        )
        .unwrap();
        self.boot_recipe(&recipe, name, &[])
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
        let probe = self.get_work_dir().join(format!("terra-{name}-probe"));
        let source = Path::new(ASSETS).join(format!("{name}_probe.c"));
        let status = Command::new("zig")
            .args([
                "cc",
                "-target",
                &format!("{}-linux-musl", std::env::consts::ARCH),
            ])
            .args(["-static", "-O2", "-o"])
            .arg(&probe)
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
        &format!("{ASSETS}/server.yaml"),
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

    // == exec: a second process beside the workload, root on request ==
    // An exec inherits the agent's cwd - the plan's `workdir` - not the home
    // dir: `exec pwd` must answer the recipe's `/work`, not `/home/terri`.
    assert_eq!(
        s.exec(false, &["pwd"]).0.trim(),
        "/work",
        "exec did not start in the plan workdir"
    );
    assert!(s.exec(false, &["id", "-u"]).0.contains("1000"));
    assert!(s.exec(true, &["id", "-u"]).0.contains('0'));
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
            "grep -q ' - cgroup2 ' /proc/self/mountinfo; d=/tmp/terra-kernel-probe; rm -rf $d; mkdir -p $d/lower $d/upper $d/work $d/merged; echo lower > $d/lower/file; mount -t overlay overlay -o lowerdir=$d/lower,upperdir=$d/upper,workdir=$d/work $d/merged; test $(cat $d/merged/file) = lower; echo upper > $d/merged/file; test $(cat $d/upper/file) = upper; umount $d/merged; rm -rf $d; mkdir -p /dev/net; if test ! -e /dev/net/tun; then mknod /dev/net/tun c 10 200; fi; test -c /dev/net/tun; : <> /dev/net/tun; apk add --no-cache iproute2; ip link add terra-veth0 type veth peer name terra-veth1; ip link add terra-br0 type bridge; ip link set terra-veth0 master terra-br0; ip link del terra-veth0; ip link del terra-br0",
        ],
    );
    assert_eq!(status, 0, "guest kernel container basics: {kernel_basics}");
    // The workload beside it is untouched: still uid 1000, no standing
    // escalation of its own - a `sudo:` grant is the thing this is not.
    assert!(s.exec(false, &["id", "-u"]).0.contains("1000"));
    let (_, denied) = s.exec(false, &["sh", "-c", "id -u > /dev/null; doas id -u"]);
    assert_ne!(denied, 0, "doas succeeded without a sudo: grant");

    // The exit status is the command's - what makes exec usable from scripts.
    assert_eq!(s.exec(false, &["sh", "-c", "exit 7"]).1, 7);
    assert_eq!(s.exec(false, &["true"]).1, 0);

    s.exec(
        true,
        &["sh", "-c", "echo ROOTWROTE > /etc/terra-exec-probe"],
    );
    assert!(
        s.exec(false, &["cat", "/etc/terra-exec-probe"])
            .0
            .contains("ROOTWROTE"),
        "exec --root did not write a root-only path"
    );

    // No terminal on this end, so the command gets pipes, not a PTY: line
    // endings kept, isatty says no, stderr separate (it was suppressed).
    assert_eq!(s.exec(false, &["printf", "a\\nb\\n"]).0, "a\nb\n");
    assert!(
        s.exec(false, &["sh", "-c", "test -t 1 && echo yes || echo no"])
            .0
            .contains("no")
    );
    let split = s.exec(false, &["sh", "-c", "echo OUT; echo ERR >&2"]).0;
    assert!(
        split.contains("OUT") && !split.contains("ERR"),
        "pipe exec merged the streams: {split:?}"
    );

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

    // == sessions/detach: the agent names and drops attached clients ==
    #[cfg(unix)]
    {
        let project = server.to_str().unwrap();
        let sessions =
            |s: &Suite| s.run_terra_command(&["server", "sessions", "--project", project]);
        assert!(
            sessions(&s).trim().is_empty(),
            "a box nobody is attached to lists clients:\n{}",
            sessions(&s)
        );

        // The PTY master stays open until the client detaches.
        let attach = |s: &Suite| {
            let (terminal, input) = console_input();
            let child = Command::new(&s.terra)
                .args(["server", "--project", project])
                .env("HOME", &s.home)
                .env("USERPROFILE", &s.home)
                .stdin(input)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawning a terminal client");
            (child, terminal)
        };
        let (mut client, _terminal) = attach(&s);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut listed = String::new();
        while Instant::now() < deadline {
            listed = sessions(&s);
            if listed.trim().starts_with("0\t") {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        assert!(
            listed.trim().starts_with("0\t"),
            "the attached client never reached the session:\n{listed}"
        );

        // The detach closes the client's connection from the agent's side, so the
        // client's process ends on its own - and the session is empty again.
        s.run_terra_command(&["server", "detach", "0", "--project", project]);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = client.try_wait().expect("waiting on the attach") {
                assert_eq!(
                    status.code(),
                    Some(0),
                    "the detached client did not exit cleanly"
                );
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the detached client never exited"
            );
            std::thread::sleep(Duration::from_secs(1));
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && !sessions(&s).trim().is_empty() {
            std::thread::sleep(Duration::from_secs(1));
        }
        assert!(
            sessions(&s).trim().is_empty(),
            "a detached client is still listed:\n{}",
            sessions(&s)
        );
        // A client that is already gone is refused, not silently re-detached.
        let (_, code) = s.run_terra_status(&["server", "detach", "0", "--project", project]);
        assert_ne!(code, 0, "re-detaching a gone client must fail");

        // Two clients, and `--all` takes both of them.
        let (mut a, _a_terminal) = attach(&s);
        let (mut b, _b_terminal) = attach(&s);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut listed = String::new();
        while Instant::now() < deadline {
            listed = sessions(&s);
            let ids: Vec<&str> = listed
                .lines()
                .filter_map(|l| l.split('\t').next())
                .collect();
            if ids.len() >= 2 {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        assert!(
            sessions(&s).lines().count() >= 2,
            "the second client never reached the session:\n{listed}"
        );
        s.run_terra_command(&["server", "detach", "--all", "--project", project]);
        for client in [&mut a, &mut b] {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if client.try_wait().expect("waiting on the attach").is_some() {
                    break;
                }
                assert!(Instant::now() < deadline, "a detached client never exited");
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline && !sessions(&s).trim().is_empty() {
            std::thread::sleep(Duration::from_secs(1));
        }
        assert!(
            sessions(&s).trim().is_empty(),
            "clients survive a detach --all:\n{}",
            sessions(&s)
        );
    }

    // == sync: files travel in and out of the running box ==
    let payload = format!("sync-roundtrip-{}", std::process::id());
    let src = s.get_work_dir().join("sync-src.txt");
    std::fs::write(&src, &payload).unwrap();
    let dst = s.get_work_dir().join("sync-out.txt");
    s.run_terra_command(&[
        "server",
        "sync",
        src.to_str().unwrap(),
        ":/tmp/sync.txt",
        "--project",
        server.to_str().unwrap(),
    ]);
    // …and back out with the box left off, which is the directory's only one:
    // named or defaulted, both have to reach the same agent.
    s.run_terra_command(&[
        "sync",
        ":/tmp/sync.txt",
        dst.to_str().unwrap(),
        "--project",
        server.to_str().unwrap(),
    ]);
    assert_eq!(
        std::fs::read_to_string(&dst).unwrap_or_default(),
        payload,
        "sync did not round-trip through the guest"
    );

    // == sync tree: directory tree synchronization, deletion, and checksum ==
    let tree_dir = s.get_work_dir().join("sync-tree-src");
    std::fs::create_dir_all(tree_dir.join("subdir")).unwrap();
    std::fs::write(tree_dir.join("file1.txt"), b"file1-content").unwrap();
    std::fs::write(tree_dir.join("subdir/file2.txt"), b"file2-content").unwrap();

    s.run_terra_command(&[
        "server",
        "sync",
        &format!("{}/", tree_dir.display()),
        ":/tmp/synced-tree/",
        "--project",
        server.to_str().unwrap(),
    ]);

    let tree_out = s.get_work_dir().join("sync-tree-out");
    s.run_terra_command(&[
        "sync",
        ":/tmp/synced-tree/",
        &format!("{}/", tree_out.display()),
        "--project",
        server.to_str().unwrap(),
    ]);
    assert_eq!(
        std::fs::read(tree_out.join("file1.txt")).unwrap(),
        b"file1-content"
    );
    assert_eq!(
        std::fs::read(tree_out.join("subdir/file2.txt")).unwrap(),
        b"file2-content"
    );

    std::fs::remove_file(tree_dir.join("file1.txt")).unwrap();
    std::fs::write(tree_dir.join("file3.txt"), b"file3-content").unwrap();
    s.run_terra_command(&[
        "server",
        "sync",
        "--delete",
        &format!("{}/", tree_dir.display()),
        ":/tmp/synced-tree/",
        "--project",
        server.to_str().unwrap(),
    ]);

    let (ls_out, status) = s.exec(false, &["sh", "-c", "ls /tmp/synced-tree"]);
    assert_eq!(status, 0);
    assert!(
        !ls_out.contains("file1.txt"),
        "file1.txt should have been deleted: {ls_out}"
    );
    assert!(
        ls_out.contains("file3.txt"),
        "file3.txt should exist: {ls_out}"
    );
    assert!(ls_out.contains("subdir"), "subdir should exist: {ls_out}");

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

    // == exit status: the workload's own, out of a VM that cannot carry one ==
    // The hypervisor exits with 0 however the guest ended - its own exit-code
    // channel wants a virtiofs root, and a box roots on a block device - so the
    // status rides the control connection instead. Without it every boot looked
    // successful to a script, and a failed `on_create` bake did too (below).
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
    assert_eq!(boot_with("exit 0"), 0, "a clean boot did not exit 0");
    assert_eq!(
        boot_with("exit 7"),
        7,
        "a boot did not exit with its workload's status"
    );
    // A signal death is `128 + signal`, the way a shell spells it - and the way
    // `terra exec` already reports one, so a box and a command agree.
    assert_eq!(
        boot_with("kill -TERM $$"),
        128 + 15,
        "a signalled workload was not reported as 128 + signal"
    );

    // == a failing on_create fails the command that ran it ==
    // It used to exit 0 and call the box ready, leaving a filesystem with no
    // stamp - so the *next* boot refused instead, naming a bake nobody knew had
    // failed.
    let bad_bake = s.get_work_dir().join("bad-bake.yaml");
    std::fs::write(
        &bad_bake,
        "hooks:\n  on_create:\n    - \"echo BAKE_RAN; exit 9\"\n",
    )
    .unwrap();
    let bad_project = s.create_project_dir("bad-bake");
    let (_, bake_code) = s.run_terra_status(&[
        bad_bake.to_str().unwrap(),
        "setup",
        "--project",
        bad_project.to_str().unwrap(),
    ]);
    assert_ne!(bake_code, 0, "a failing on_create bake reported success");
    assert!(
        s.run_terra_command(&[
            "logs",
            "--diagnostics",
            "--project",
            bad_project.to_str().unwrap()
        ])
        .contains("BAKE_RAN"),
        "the failed bake's console did not reach the log"
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

    // == a writable share preserves ordinary repository-file operations ==
    let writable = s.get_work_dir().join("mount-writable");
    std::fs::create_dir(&writable).unwrap();
    std::fs::write(writable.join("host.txt"), "host-visible").unwrap();
    let executable = writable.join("run");
    std::fs::write(&executable, "#!/bin/sh\necho EXECUTABLE\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = std::fs::metadata(&executable).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&executable, permissions).unwrap();
    }
    std::fs::write(s.get_work_dir().join("outside-sentinel"), "host-secret").unwrap();
    let out = s.boot_with_mount(
        "mount-writable",
        &writable,
        false,
        r#"
test "$(cat /work/host.txt)" = host-visible
test "$(/work/run)" = EXECUTABLE
printf guest-visible > /work/guest.txt
ln /work/host.txt /work/hard.txt
printf hard-linked > /work/hard.txt
test "$(cat /work/host.txt)" = hard-linked
ln -s host.txt /work/relative
test "$(cat /work/relative)" = hard-linked
if ln -s /work/host.txt /work/absolute; then
  echo absolute symlink accepted
  exit 1
fi
if ln -s /outside-sentinel /work/outside; then
  echo escaping absolute symlink accepted
  exit 1
fi
test ! -e /work/outside
printf open-unlink > /work/open
exec 3</work/open
rm /work/open
test "$(cat <&3)" = open-unlink
printf renamed > /work/before
mv /work/before /work/after
test "$(cat /work/after)" = renamed
echo WRITABLE_OK
"#,
    );
    assert!(out.contains("WRITABLE_OK"), "{out}");
    assert_eq!(
        std::fs::read_to_string(writable.join("guest.txt")).unwrap(),
        "guest-visible"
    );
    assert_eq!(
        std::fs::read_to_string(writable.join("host.txt")).unwrap(),
        "hard-linked"
    );
    // == a read-only alias sees the writer's files but cannot mutate any alias ==
    let out = s.boot_with_mount(
        "mount-readonly",
        &writable,
        true,
        r#"
test "$(cat /work/guest.txt)" = guest-visible
for command in \
  ': > /work/new' \
  'ln /work/host.txt /work/extra-link' \
  'ln -s host.txt /work/extra-symlink' \
  'mv /work/host.txt /work/renamed' \
  'rm -f /work/guest.txt'; do
  if sh -c "$command"; then
    echo "readonly accepted: $command"
    exit 1
  fi
done
echo READONLY_OK
"#,
    );
    assert!(out.contains("READONLY_OK"), "{out}");
    assert_eq!(
        std::fs::read_to_string(writable.join("guest.txt")).unwrap(),
        "guest-visible"
    );
    assert!(writable.join("host.txt").is_file());

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
unsupported('xattr', lambda: os.setxattr(path, 'user.terra', b'guest-value'))
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
