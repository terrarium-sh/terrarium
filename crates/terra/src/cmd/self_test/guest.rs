use std::ffi::OsStr;
use std::fs::{self, File, FileTimes};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

mod network;
mod sessions;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);
const STORAGE_TIMEOUT: Duration = Duration::from_secs(240);

struct SelfTest {
    directory: PathBuf,
    binary: PathBuf,
    project: PathBuf,
    boxes: Vec<String>,
}

impl SelfTest {
    fn command(&self, arguments: impl IntoIterator<Item = impl AsRef<OsStr>>) -> Command {
        let mut command = Command::new(&self.binary);
        command.arg("--project").arg(&self.project).args(arguments);
        command
    }

    fn run(&self, arguments: &[&str]) -> Result<Output> {
        self.run_expected(arguments, Some(0), COMMAND_TIMEOUT)
    }

    fn run_expected(
        &self,
        arguments: &[&str],
        expected: Option<i32>,
        timeout: Duration,
    ) -> Result<Output> {
        Self::capture(&mut self.command(arguments), expected, timeout)
    }

    fn capture(command: &mut Command, expected: Option<i32>, timeout: Duration) -> Result<Output> {
        command.stdin(Stdio::null());
        let output = crate::process::run_capture(command, timeout)?;
        let matches = expected.map_or_else(
            || !output.status.success(),
            |code| output.status.code() == Some(code),
        );
        ensure!(
            matches,
            "{command:?}: exit {} (expected {expected:?})\n{}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(output)
    }

    fn setup(&mut self, name: &str, recipe: &Value, expected: Option<i32>) -> Result<Output> {
        self.boxes.push(name.to_owned());
        let path = self.directory.join(format!("{name}.yaml"));
        fs::write(&path, serde_json::to_vec(recipe)?)?;
        Self::capture(
            self.command([path.as_os_str()])
                .args(["setup", "--trust-recipe"]),
            expected,
            STORAGE_TIMEOUT,
        )
    }

    fn execute(&self, script: &str, flags: &[&str]) -> Result<Output> {
        self.execute_expected(script, flags, Some(0))
    }

    fn execute_expected(
        &self,
        script: &str,
        flags: &[&str],
        expected: Option<i32>,
    ) -> Result<Output> {
        Self::capture(
            self.command(["exercise", "exec"])
                .args(flags)
                .args(["--", "sh", "-ec", script]),
            expected,
            COMMAND_TIMEOUT,
        )
    }

    fn read_json(&self, arguments: &[&str]) -> Result<Value> {
        serde_json::from_slice(&self.run(arguments)?.stdout)
            .with_context(|| format!("decoding terra {} output", arguments.join(" ")))
    }

    fn list_boxes(&self) -> Result<Vec<Value>> {
        serde_json::from_slice(&self.run(&["ls", "--json"])?.stdout).context("decoding box listing")
    }

    fn require_box_state(&self, name: &str, expected: &str) -> Result<()> {
        let boxes = self.list_boxes()?;
        let bx = boxes
            .iter()
            .find(|bx| bx["name"] == name)
            .with_context(|| format!("{name} missing from box listing"))?;
        ensure!(
            bx["state"] == expected,
            "{name}: expected {expected}, got {bx}"
        );
        Ok(())
    }

    fn cleanup(&self) -> Result<()> {
        let mut failures = Vec::new();
        for name in self.boxes.iter().rev() {
            if let Err(error) = self.run_expected(
                &[name, "rm", "--force", "--purge", "--timeout", "5"],
                Some(0),
                Duration::from_secs(60),
            ) {
                failures.push(format!("{error:#}"));
            }
        }
        ensure!(
            failures.is_empty(),
            "self-test cleanup failed:\n{}",
            failures.join("\n")
        );
        Ok(())
    }
}

pub(super) fn run_suite(project: &Path) -> Result<()> {
    let directory = tempfile::Builder::new()
        .prefix("terra-self-test-")
        .tempdir_in(project)?;
    let mut self_test = SelfTest {
        directory: directory.path().to_owned(),
        binary: std::env::current_exe()?,
        project: project.to_owned(),
        boxes: Vec::new(),
    };
    let result = run_exercises(&mut self_test);
    let cleanup = self_test.cleanup();
    match (result, cleanup) {
        (Ok(()), Ok(())) => {
            println!("self-test: passed");
            Ok(())
        }
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(error.context(format!("{cleanup:#}"))),
    }
}

fn wait_until(
    mut check: impl FnMut() -> Result<bool>,
    description: &str,
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check()? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
    anyhow::bail!("timed out waiting for {description}");
}

fn require_output(output: &Output, marker: &str) -> Result<()> {
    ensure!(
        String::from_utf8_lossy(&output.stdout).contains(marker),
        "missing {marker:?} in output:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn require_file(path: &Path, expected: &[u8]) -> Result<()> {
    ensure!(
        fs::read(path)? == expected,
        "unexpected contents in {}",
        path.display()
    );
    Ok(())
}

fn run_exercises(self_test: &mut SelfTest) -> Result<()> {
    let allowed = network::HostService::start()?;
    let denied = network::HostService::start()?;
    println!("self-test: setup, bake, hooks and detached service");
    let writable = self_test.directory.join("writable");
    let readonly = self_test.directory.join("readonly");
    fs::create_dir(&writable)?;
    fs::create_dir(&readonly)?;
    fs::write(writable.join("host"), "HOST_SEED")?;
    fs::write(writable.join("host-update"), "INITIAL")?;
    fs::write(readonly.join("seed"), "READ_ONLY")?;
    let reservation = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let published_port = reservation.local_addr()?.port();
    drop(reservation);
    let allowed_port = allowed.port();
    let recipe = json!({
        "hw": {"cpus": 2, "mem_mib": 512, "rootfs_mib": 128},
        "network": {
            "allow": [format!("gate.test:{allowed_port}")],
            "hosts": [{"name": "gate.test", "addr": "HOST_LOOPBACK"}],
            "ports": [format!("{published_port}:18080")],
        },
        "mounts": [{"host": writable, "guest": "/work"},
                   {"host": readonly, "guest": "/readonly", "readonly": true}],
        "volumes": [{"name": "data", "guest": "/data", "size_mib": 8}],
        "env": {"WORKLOAD_ENV": "recipe-value"},
        "hooks": {
            "on_create": ["mkdir -p /opt/workload; echo baked >> /opt/workload/bake; echo BAKE_OK"],
            "on_start": ["echo start >> /work/hooks; echo START_OK"],
            "pre_stop": ["echo stop >> /work/hooks; echo STOP_OK"],
        },
        "daemons": [
            "echo daemon >> /work/daemon; test $(wc -l < /work/daemon) -ge 2",
            "echo $$ > /tmp/workload-watcher-pid; exec busybox inotifyd - /work/host-update:c /work:nmdy > /tmp/workload-events",
            "while true; do printf 'HTTP/1.1 200 OK\\r\\nContent-Length: 13\\r\\nConnection: close\\r\\n\\r\\nGUEST_NETWORK' | busybox nc -l -p 18080; done"
        ],
        "workload": {"entrypoint": "/bin/sh", "workdir": "/work/nested/deep",
            "args": ["-ec", "echo ready > /work/ready; while true; do sleep 60; done"]},
    });
    require_output(&self_test.setup("exercise", &recipe, Some(0))?, "BAKE_OK")?;
    self_test.run(&["exercise", "setup"])?;
    let resolved = self_test.read_json(&["exercise", "show", "--json", "--with-env-values"])?;
    ensure!(
        resolved["env"]["WORKLOAD_ENV"] == "recipe-value",
        "recipe environment missing: {resolved}"
    );
    self_test.run(&["exercise", "-d"])?;
    self_test.execute(
        "for i in $(seq 1 100); do test ! -f /work/ready || break; sleep .1; done; \
         test -f /work/ready; test $(wc -l < /opt/workload/bake) = 1; \
         test -s /terra/recipe; test $(nproc) = 2",
        &[],
    )?;
    self_test.require_box_state("exercise", "running")?;
    wait_until(
        || Ok(network::read_published_port(published_port)),
        "published HTTP port",
        Duration::from_secs(60),
    )?;
    ensure!(
        allowed.requests() == 0 && denied.requests() == 0,
        "unexpected host network request"
    );

    exercise_exec(self_test)?;
    exercise_shares(self_test, &writable, &readonly)?;
    exercise_sync(self_test)?;
    exercise_network(self_test, &allowed, &denied, &recipe["hw"])?;
    exercise_storage(self_test, &writable, &recipe["hw"])?;
    Ok(())
}

fn exercise_network(
    self_test: &mut SelfTest,
    allowed: &network::HostService,
    denied: &network::HostService,
    hardware: &Value,
) -> Result<()> {
    let allowed_port = allowed.port();
    let denied_port = denied.port();
    println!("self-test: local DNS, host services, ports and denial");
    self_test.execute(
        &format!(
            "test \"$(wget -q -T 5 -O - http://gate.test:{allowed_port}/)\" = HOST_NETWORK; \
             if wget -q -T 2 -O - http://gate.test:{denied_port}/; then exit 1; fi; \
             if wget -q -T 2 -O - http://blocked.invalid:{allowed_port}/; then exit 1; fi; \
             if nslookup blocked.invalid; then exit 1; fi"
        ),
        &[],
    )?;
    ensure!(
        allowed.requests() == 1 && denied.requests() == 0,
        "network allow/deny request counts differ"
    );
    let isolated = json!({
        "hw": hardware,
        "network": {"hosts": [{"name": "gate.test", "addr": "HOST_LOOPBACK"}]},
        "workload": {"entrypoint": "/bin/sh", "args": ["-ec", format!(
            "if wget -q -T 2 -O - http://gate.test:{allowed_port}/; then exit 1; fi; echo ISOLATED_OK"
        )]},
    });
    self_test.setup("isolated", &isolated, Some(0))?;
    require_output(
        &self_test.run(&["isolated", "--foreground"])?,
        "ISOLATED_OK",
    )?;
    ensure!(
        allowed.requests() == 1 && denied.requests() == 0,
        "isolated box reached host services"
    );
    Ok(())
}

fn exercise_exec(self_test: &SelfTest) -> Result<()> {
    println!("self-test: exec identities, pipes, PTY and sessions");
    for (script, flags, expected) in [
        ("id -u", &[][..], "1000"),
        ("id -u", &["--root"][..], "0"),
        ("pwd", &[][..], "/work/nested/deep"),
    ] {
        let output = self_test.execute(script, flags)?;
        ensure!(
            String::from_utf8_lossy(&output.stdout).trim() == expected,
            "unexpected {script} output: {output:?}"
        );
    }
    self_test.execute(
        "test \"$WORKLOAD_ENV\" = exec-value; test \"$(pwd)\" = /tmp",
        &["--env", "WORKLOAD_ENV=exec-value", "--workdir", "/tmp"],
    )?;
    self_test.execute_expected("exit 7", &[], Some(7))?;
    self_test.execute_expected("doas id -u", &[], None)?;
    let streams = self_test.execute(
        "printf 'one\\ntwo\\n'; echo ERROR >&2; test ! -t 1",
        &["--no-tty"],
    )?;
    ensure!(
        streams.stdout == b"one\ntwo\n"
            && String::from_utf8_lossy(&streams.stderr).contains("ERROR"),
        "exec streams differ: {streams:?}"
    );
    self_test.execute("test -t 0; test -t 1; echo TTY_OK", &["--tty"])?;
    sessions::exercise(self_test)?;
    self_test.execute("echo ROOT_WRITE > /etc/workload-probe", &["--root"])?;
    self_test.execute(
        "test \"$(cat /etc/workload-probe)\" = ROOT_WRITE; \
         test -e /proc/self/ns/user; test -e /proc/self/ns/net; test -e /proc/self/ns/pid",
        &[],
    )?;
    self_test.execute(
        "grep -q ' - cgroup2 ' /proc/self/mountinfo; \
         mkdir -p /tmp/overlay/lower /tmp/overlay/upper /tmp/overlay/work /tmp/overlay/merged; \
         echo lower > /tmp/overlay/lower/value; \
         mount -t overlay overlay -o lowerdir=/tmp/overlay/lower,upperdir=/tmp/overlay/upper,workdir=/tmp/overlay/work /tmp/overlay/merged; \
         test $(cat /tmp/overlay/merged/value) = lower; echo upper > /tmp/overlay/merged/value; \
         test $(cat /tmp/overlay/upper/value) = upper; umount /tmp/overlay/merged",
        &["--root"],
    )?;
    Ok(())
}

fn exercise_shares(self_test: &SelfTest, writable: &Path, readonly: &Path) -> Result<()> {
    println!("self-test: writable/read-only shares, file events and synchronization");
    self_test.execute(
        "test \"$(cat /work/host)\" = HOST_SEED; \
         printf linked > /work/host; ln /work/host /work/hard; \
         ln -s host /work/link; test \"$(cat /work/link)\" = linked; \
         printf open-unlink > /work/open; exec 3</work/open; rm /work/open; \
         test \"$(cat <&3)\" = open-unlink; \
         printf renamed > /work/before; mv /work/before /work/after; \
         test \"$(cat /work/after)\" = renamed; \
         printf \"#!/bin/sh\\necho EXECUTABLE\\n\" > /work/run; chmod 755 /work/run; \
         test \"$(/work/run)\" = EXECUTABLE; \
         if ln -s /etc/passwd /work/escape; then exit 1; fi; \
         test \"$(cat /readonly/seed)\" = READ_ONLY; \
         for command in \": > /readonly/new\" \"rm /readonly/seed\" \
         \"mv /readonly/seed /readonly/moved\" \"ln /readonly/seed /readonly/link\"; do \
         if sh -c \"$command\"; then exit 1; fi; done",
        &[],
    )?;
    require_file(&writable.join("host"), b"linked")?;
    require_file(&writable.join("after"), b"renamed")?;
    require_file(&readonly.join("seed"), b"READ_ONLY")?;
    let readonly_names: Vec<_> = fs::read_dir(readonly)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<_>>()?;
    ensure!(
        readonly_names == [OsStr::new("seed")],
        "read-only share was modified: {readonly_names:?}"
    );
    exercise_file_events(self_test, writable)?;
    self_test.execute(
        "test \"$(cat /work/host-update)\" = LIVE_UPDATE; \
         for i in $(seq 1 100); do test $(wc -l < /work/daemon) -lt 2 || break; sleep .1; done; \
         test $(wc -l < /work/daemon) -ge 2; echo PERSISTED > /data/value; sync",
        &[],
    )?;
    Ok(())
}

fn exercise_file_events(self_test: &SelfTest, writable: &Path) -> Result<()> {
    self_test.execute(
        "busybox --list | grep -qx inotifyd; \
         for i in $(seq 1 100); do if test -f /tmp/workload-watcher-pid; then \
         pid=$(cat /tmp/workload-watcher-pid); \
         test $(grep -h '^inotify wd:' /proc/$pid/fdinfo/* | wc -l) -lt 2 || exit 0; \
         fi; sleep .1; done; exit 1",
        &["--root"],
    )?;
    fs::write(writable.join("host-update"), "LIVE_UPDATE")?;
    fs::write(writable.join("host-created"), "CREATED")?;
    self_test.execute(
        "for i in $(seq 1 100); do \
         if grep -q '^c.*host-update' /tmp/workload-events && grep -q '^n.*host-created' /tmp/workload-events; then \
         test $(cat /work/host-update) = LIVE_UPDATE; test $(cat /work/host-created) = CREATED; exit 0; fi; \
         sleep .1; done; cat /tmp/workload-events; exit 1",
        &["--root"],
    )?;
    fs::remove_file(writable.join("host-created"))?;
    self_test.execute(
        "for i in $(seq 1 100); do if grep -q '^d.*host-created' /tmp/workload-events; then \
         test ! -e /work/host-created; exit 0; fi; \
         sleep .1; done; cat /tmp/workload-events; exit 1",
        &["--root"],
    )?;
    Ok(())
}

fn exercise_sync(self_test: &SelfTest) -> Result<()> {
    let source = self_test.directory.join("sync-source");
    fs::create_dir_all(source.join("nested"))?;
    let payload: Vec<u8> = (0..=255).cycle().take(256 * 257).collect();
    fs::write(source.join("nested/binary"), &payload)?;
    fs::write(source.join("value"), "first")?;
    let source_directory = format!("{}/", source.display());
    self_test.run(&["exercise", "sync", &source_directory, ":/tmp/synced/"])?;
    let downloaded = self_test.directory.join("sync-download");
    let downloaded_directory = format!("{}/", downloaded.display());
    self_test.run(&["exercise", "sync", ":/tmp/synced/", &downloaded_directory])?;
    require_file(&downloaded.join("nested/binary"), &payload)?;
    require_file(&downloaded.join("value"), b"first")?;
    let value = source.join("value");
    let original_times = fs::metadata(&value)?;
    fs::write(&value, "other")?;
    File::options().write(true).open(&value)?.set_times(
        FileTimes::new()
            .set_accessed(original_times.accessed()?)
            .set_modified(original_times.modified()?),
    )?;
    self_test.execute("printf extra > /tmp/synced/extra", &[])?;
    self_test.run(&[
        "exercise",
        "sync",
        "--delete",
        "--checksum",
        "--dry-run",
        &source_directory,
        ":/tmp/synced/",
    ])?;
    self_test.execute(
        "test \"$(cat /tmp/synced/value)\" = first; test -f /tmp/synced/extra",
        &[],
    )?;
    self_test.run(&[
        "exercise",
        "sync",
        "--delete",
        "--checksum",
        &source_directory,
        ":/tmp/synced/",
    ])?;
    self_test.execute(
        "test \"$(cat /tmp/synced/value)\" = other; test ! -e /tmp/synced/extra",
        &[],
    )?;
    fs::write(downloaded.join("extra"), "remove")?;
    self_test.run(&[
        "exercise",
        "sync",
        "--delete",
        "--checksum",
        ":/tmp/synced/",
        &downloaded_directory,
    ])?;
    ensure!(
        !downloaded.join("extra").try_exists()?,
        "sync retained deleted file"
    );
    require_file(&downloaded.join("value"), b"other")?;
    let single = self_test.directory.join("single");
    SelfTest::capture(
        self_test
            .command(["exercise", "sync"])
            .arg(value)
            .arg(":/tmp/single"),
        Some(0),
        COMMAND_TIMEOUT,
    )?;
    SelfTest::capture(
        self_test.command(["sync", ":/tmp/single"]).arg(&single),
        Some(0),
        COMMAND_TIMEOUT,
    )?;
    require_file(&single, b"other")?;
    Ok(())
}

fn exercise_storage(self_test: &mut SelfTest, writable: &Path, hardware: &Value) -> Result<()> {
    println!("self-test: stop, persistent restart, storage export/import and removal");
    self_test.run(&["exercise", "stop"])?;
    self_test.require_box_state("exercise", "stopped")?;
    require_file(&writable.join("hooks"), b"start\nstop\n")?;
    let storage = self_test.read_json(&["exercise", "storage", "show", "--json"])?;
    let images = storage["images"]
        .as_array()
        .context("storage images missing")?;
    let mut names: Vec<_> = images.iter().map(|image| image["name"].as_str()).collect();
    names.sort_unstable();
    ensure!(
        names == [Some("rootfs.img"), Some("vol-data.img")],
        "unexpected storage images: {storage}"
    );
    ensure!(
        images.iter().all(
            |image| image["virtual_bytes"].as_u64().is_some_and(|size| size > 0)
                && image["is_unused"] == false
        ),
        "invalid storage image: {storage}"
    );
    let artifact = self_test.directory.join("storage.terra");
    SelfTest::capture(
        self_test
            .command(["exercise", "storage", "export"])
            .arg(&artifact),
        Some(0),
        STORAGE_TIMEOUT,
    )?;
    ensure!(fs::metadata(&artifact)?.len() > 0, "empty storage export");
    self_test.run(&["exercise", "storage", "prune"])?;
    let foreground = self_test.run(&[
        "exercise",
        "--foreground",
        "--root",
        "--",
        "sh",
        "-ec",
        "test $(id -u) = 0; test $(cat /data/value) = PERSISTED; \
         test $(wc -l < /opt/workload/bake) = 1; echo CHANGED > /data/value; sync; echo RESTART_OK",
    ])?;
    for marker in ["START_OK", "RESTART_OK", "STOP_OK"] {
        require_output(&foreground, marker)?;
    }
    require_file(&writable.join("hooks"), b"start\nstop\nstart\nstop\n")?;
    SelfTest::capture(
        self_test
            .command(["exercise", "storage", "import"])
            .arg(&artifact),
        Some(0),
        STORAGE_TIMEOUT,
    )?;
    require_output(
        &self_test.run(&[
            "exercise",
            "--foreground",
            "--",
            "sh",
            "-ec",
            "test $(id -u) = 1000; test $(cat /data/value) = PERSISTED; echo RESTORED_OK",
        ])?,
        "RESTORED_OK",
    )?;
    self_test.run_expected(
        &["exercise", "--foreground", "--", "sh", "-c", "exit 7"],
        Some(7),
        COMMAND_TIMEOUT,
    )?;
    self_test.run(&["exercise", "logs", "--tail", "20"])?;
    self_test.run(&["exercise", "logs", "--diagnostics", "--tail", "20"])?;
    let bad_bake = self_test.setup(
        "bad-bake",
        &json!({
            "hw": hardware, "hooks": {"on_create": ["echo FAILED_BAKE; exit 9"]},
        }),
        None,
    )?;
    require_output(&bad_bake, "FAILED_BAKE")?;
    self_test.run(&["exercise", "rm"])?;
    self_test.require_box_state("exercise", "not_created")?;
    self_test.run(&["exercise", "rm", "--purge"])?;
    ensure!(
        !self_test
            .list_boxes()?
            .iter()
            .any(|bx| bx["name"] == "exercise"),
        "purged box is still listed"
    );
    self_test.boxes.retain(|name| name != "exercise");
    Ok(())
}
