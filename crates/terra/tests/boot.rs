//! Boot suite - the product gate. Boots real microVMs (needs /dev/kvm) and
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
        let host_uid = {
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(tmp.path()).unwrap().uid()
        };
        Self {
            terra,
            home,
            host_uid,
            tmp,
        }
    }

    fn work(&self) -> &Path {
        self.tmp.path()
    }

    /// Run terra, returning stdout (stderr suppressed, as a script would).
    fn terra(&self, args: &[&str]) -> String {
        self.terra_status(args).0
    }

    fn terra_status(&self, args: &[&str]) -> (String, i32) {
        let out = Command::new(&self.terra)
            .args(args)
            .env("HOME", &self.home)
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .expect("running terra");
        (
            String::from_utf8_lossy(&out.stdout).into_owned(),
            out.status.code().unwrap_or(-1),
        )
    }

    /// Where terra keeps `name`'s files - asked via `ls --tsv`, the
    /// format scripts may parse, not guessed: the state directory's name is a
    /// hash.
    fn box_files(&self, name: &str) -> PathBuf {
        let path = self.work().join(name);
        let out = self.terra(&["ls", "--tsv", "--project", path.to_str().unwrap()]);
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
    /// whole run as one captured process; the transcript is both commands'
    /// stdout, which the bake's assertions read from the workload's own output.
    fn boot_recipe(&self, recipe: &Path, name: &str, extra: &[&str]) -> String {
        let path = self.project(name);
        let project = path.to_str().unwrap();
        let setup = self.terra(&[recipe.to_str().unwrap(), "setup", "--project", project]);
        let mut args = vec![name, "--foreground", "--project", project];
        args.extend_from_slice(extra);
        setup + &self.terra(&args)
    }

    /// `name`'s project directory under WORK, created - terra refuses a
    /// `--project` that does not exist rather than minting one for a typo.
    fn project(&self, name: &str) -> PathBuf {
        let path = self.work().join(name);
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
        let prj = self.work().join(format!("{name}-proj"));
        std::fs::create_dir_all(&prj).unwrap();
        let recipe = self.work().join(format!("{name}.yaml"));
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

    fn exec(&self, root: bool, cmd: &[&str]) -> (String, i32) {
        let server = self.work().join("server");
        let mut args = vec!["exec"];
        if root {
            args.push("--root");
        }
        args.extend(["--project", server.to_str().unwrap(), "--"]);
        args.extend_from_slice(cmd);
        self.terra_status(&args)
    }

    fn file_uid(path: &Path) -> Option<u32> {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|m| m.uid())
    }
}

impl Drop for Suite {
    fn drop(&mut self) {
        // `stop` waits for the guest by default; without that wait the tempdir
        // would be deleted out from under a VM still running `pre_stop`.
        let server = self.work().join("server");
        let _ = Command::new(&self.terra)
            .args(["stop", "--project", server.to_str().unwrap()])
            .env("HOME", &self.home)
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
#[ignore = "boots real microVMs - needs /dev/kvm: cargo test --test boot -- --ignored"]
fn boot_suite() {
    let s = Suite::new();

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
    let log = std::fs::read_to_string(s.box_files("egress").join("terra.log")).unwrap_or_default();
    assert!(
        log.contains("no allow rule names"),
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
    assert_eq!(
        Suite::file_uid(&prj.join("wf")),
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
    assert_eq!(Suite::file_uid(&prj.join("wf")), Some(s.host_uid));

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
    let server = s.project("server");
    s.terra(&[
        &format!("{ASSETS}/server.yaml"),
        "setup",
        "--project",
        server.to_str().unwrap(),
    ]);
    s.terra(&["server", "-d", "--project", server.to_str().unwrap()]);
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
    assert!(
        body.contains("HELLO_FROM_VMA"),
        "published port never answered on the host loopback"
    );

    // == the state directory is what guards the agent's port ==
    // libkrun binds `a` itself, and its exec service runs commands as guest
    // root, so the one thing between another account on this host and that
    // port is the mode of the directory it is bound in. terra's own umask
    // cannot be it: libkrun's virtiofs clears the process umask when the guest
    // mounts a share. Asserted on a box that is *running*, since that is when
    // the sockets exist.
    {
        use std::os::unix::fs::PermissionsExt;
        let files = s.box_files("server");
        let mode = std::fs::metadata(&files).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode,
            0o700,
            "{} is {mode:o} - another account can reach the root-capable exec service",
            files.display()
        );
        for sock in ["c", "a"] {
            assert!(
                files.join(sock).exists(),
                "a running box is missing its {sock} socket - the mode above then \
                 guards nothing"
            );
        }
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
    assert!(s.exec(false, &["id", "-u"]).0.contains("1000"));
    assert!(s.exec(true, &["id", "-u"]).0.contains('0'));
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
    let oneshot = s.work().join("oneshot.yaml");
    std::fs::write(
        &oneshot,
        "workload:\n  entrypoint: /bin/sh\n  args: [-c, 'echo ONESHOT_RAN; exit 7']\n",
    )
    .unwrap();
    let oneshot_box = s.project("oneshot");
    s.terra(&[
        oneshot.to_str().unwrap(),
        "setup",
        "--project",
        oneshot_box.to_str().unwrap(),
    ]);
    let out = Command::new(&s.terra)
        .args(["oneshot", "-d", "--project", oneshot_box.to_str().unwrap()])
        .env("HOME", &s.home)
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
            .terra(&["ls", "--project", oneshot_box.to_str().unwrap()])
            .contains("stopped")
    {
        std::thread::sleep(Duration::from_secs(1));
    }
    assert!(
        s.terra(&["ls", "--project", oneshot_box.to_str().unwrap()])
            .contains("stopped"),
        "the box did not run to completion in the background"
    );
    // The log is the box's diagnostics - the boot is in it, the workload's
    // terminal is not. A detached run nobody attaches to is broadcast to the
    // session and to nothing else, which is why a box that wants a record of
    // its own output writes one to a volume it keeps.
    let log = s.terra(&["logs", "--project", oneshot_box.to_str().unwrap()]);
    assert!(
        log.contains("starting"),
        "the boot is not in the log:\n{log}"
    );
    assert!(
        !log.contains("ONESHOT_RAN"),
        "the workload's terminal reached the log:\n{log}"
    );

    // == cp: files travel in and out of the running box ==
    let payload = format!("cp-roundtrip-{}", std::process::id());
    let src = s.work().join("cp-src.txt");
    std::fs::write(&src, &payload).unwrap();
    let dst = s.work().join("cp-out.txt");
    s.terra(&[
        "server",
        "put",
        src.to_str().unwrap(),
        "/tmp/cp.txt",
        "--project",
        server.to_str().unwrap(),
    ]);
    // …and back out with the box left off, which is the directory's only one:
    // named or defaulted, both have to reach the same agent.
    s.terra(&[
        "get",
        "/tmp/cp.txt",
        dst.to_str().unwrap(),
        "--project",
        server.to_str().unwrap(),
    ]);
    assert_eq!(
        std::fs::read_to_string(&dst).unwrap_or_default(),
        payload,
        "cp did not round-trip through the guest"
    );

    // == exit status: the workload's own, out of a VM that cannot carry one ==
    // The hypervisor exits with 0 however the guest ended - its own exit-code
    // channel wants a virtiofs root, and a box roots on a block device - so the
    // status rides the control connection instead. Without it every boot looked
    // successful to a script, and a failed `on_create` bake did too (below).
    let status_recipe = s.work().join("exit-status.yaml");
    std::fs::write(&status_recipe, "workload:\n  entrypoint: /bin/true\n").unwrap();
    let status_project = s.project("exit-status");
    let status_dir = status_project.to_str().unwrap();
    s.terra(&[
        status_recipe.to_str().unwrap(),
        "setup",
        "--project",
        status_dir,
    ]);
    let boot_with = |cmd: &str| {
        s.terra_status(&[
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
    let bad_bake = s.work().join("bad-bake.yaml");
    std::fs::write(
        &bad_bake,
        "hooks:\n  on_create:\n    - \"echo BAKE_RAN; exit 9\"\n",
    )
    .unwrap();
    let bad_project = s.project("bad-bake");
    let (_, bake_code) = s.terra_status(&[
        bad_bake.to_str().unwrap(),
        "setup",
        "--project",
        bad_project.to_str().unwrap(),
    ]);
    assert_ne!(bake_code, 0, "a failing on_create bake reported success");
    assert!(
        s.terra(&["logs", "--project", bad_project.to_str().unwrap()])
            .contains("BAKE_RAN"),
        "the failed bake's console did not reach the log"
    );
}
