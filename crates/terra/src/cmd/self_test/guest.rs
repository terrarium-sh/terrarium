use std::ffi::OsStr;
use std::fs::{self, File, FileTimes};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, ensure};
use serde_json::Value;

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
        fs::write(&path, yaml_serde::to_string(recipe)?)?;
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

fn fill_share_path(host: &mut Value, placeholder: &str, path: &Path) -> Result<()> {
    let path = path
        .to_str()
        .context("self-test shares require a UTF-8 project path")?;
    *host = Value::String(
        host.as_str()
            .context("self-test share path must be a string")?
            .replace(placeholder, path),
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let executable = writable.join("host-run");
        fs::write(&executable, "#!/bin/sh\necho HOST_EXECUTABLE\n")?;
        fs::set_permissions(executable, fs::Permissions::from_mode(0o755))?;
    }
    let reservation = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    let published_port = reservation.local_addr()?.port();
    drop(reservation);
    let allowed_port = allowed.port();
    let mut recipe: Value = yaml_serde::from_str(
        &include_str!("recipes/exercise.yaml")
            .replace("{allowed_port}", &allowed_port.to_string())
            .replace("{published_port}", &published_port.to_string()),
    )?;
    fill_share_path(&mut recipe["mounts"][0]["host"], "{writable}", &writable)?;
    fill_share_path(&mut recipe["mounts"][1]["host"], "{readonly}", &readonly)?;
    require_output(&self_test.setup("exercise", &recipe, Some(0))?, "BAKE_OK")?;
    self_test.run(&["exercise", "setup"])?;
    let resolved = self_test.read_json(&["exercise", "show", "--json", "--with-env-values"])?;
    ensure!(
        resolved["env"]["WORKLOAD_ENV"] == "recipe-value",
        "recipe environment missing: {resolved}"
    );
    self_test.run(&["exercise", "-d"])?;
    self_test.execute(include_str!("scripts/exercise-ready.sh"), &[])?;
    self_test.require_box_state("exercise", "running")?;
    wait_until(
        || Ok(network::read_published_port(published_port)),
        "published HTTP port",
        Duration::from_secs(60),
    )?;
    wait_until(
        || Ok(network::read_published_datagram(published_port)),
        "published UDP port",
        Duration::from_secs(60),
    )?;
    ensure!(
        allowed.requests() == 0
            && denied.requests() == 0
            && allowed.datagrams() == 0
            && denied.datagrams() == 0,
        "unexpected host network request"
    );

    exercise_exec(self_test)?;
    exercise_shares(self_test, &writable, &readonly)?;
    exercise_sync(self_test)?;
    exercise_network(self_test, &allowed, &denied, &recipe["hw"])?;
    exercise_local_only_network(self_test, &recipe["hw"])?;
    exercise_storage(self_test, &writable, &recipe["hw"])?;
    Ok(())
}

fn exercise_network(
    self_test: &mut SelfTest,
    allowed: &network::HostService,
    denied: &network::HostService,
    hardware: &Value,
) -> Result<()> {
    const CONCURRENT_NETWORK_FLOWS: usize = 8;
    let allowed_port = allowed.port();
    let denied_port = denied.port();
    println!("self-test: local DNS, TCP/UDP host services, ports and denial");
    self_test.execute(
        &include_str!("scripts/network.sh")
            .replace(
                "{concurrent_network_flows}",
                &CONCURRENT_NETWORK_FLOWS.to_string(),
            )
            .replace("{allowed_port}", &allowed_port.to_string())
            .replace("{denied_port}", &denied_port.to_string()),
        &[],
    )?;
    ensure!(
        allowed.requests() == CONCURRENT_NETWORK_FLOWS
            && denied.requests() == 0
            && allowed.datagrams() == 1
            && denied.datagrams() == 0,
        "network allow/deny request counts differ"
    );
    let isolated: Value = yaml_serde::from_str(
        &include_str!("recipes/isolated.yaml")
            .replace("{hardware}", &serde_json::to_string(hardware)?)
            .replace("{allowed_port}", &allowed_port.to_string()),
    )?;
    self_test.setup("isolated", &isolated, Some(0))?;
    require_output(
        &self_test.run(&["isolated", "--foreground"])?,
        "ISOLATED_OK",
    )?;
    ensure!(
        allowed.requests() == CONCURRENT_NETWORK_FLOWS
            && denied.requests() == 0
            && allowed.datagrams() == 1
            && denied.datagrams() == 0,
        "isolated box reached host services"
    );
    network::exercise_quic(self_test, allowed)
}

fn exercise_local_only_network(self_test: &mut SelfTest, hardware: &Value) -> Result<()> {
    println!("self-test: local-only loopback, agent exec and shutdown");
    let recipe: Value = yaml_serde::from_str(
        &include_str!("recipes/local-only.yaml")
            .replace("{hardware}", &serde_json::to_string(hardware)?),
    )?;
    self_test.setup("local-only", &recipe, Some(0))?;
    self_test.run(&["local-only", "-d"])?;
    let script = include_str!("scripts/local-only.sh");
    let output = SelfTest::capture(
        &mut self_test.command(["local-only", "exec", "--", "/bin/sh", "-ec", script]),
        Some(0),
        COMMAND_TIMEOUT,
    )?;
    require_output(&output, "LOCAL_ONLY_OK")?;
    self_test.run(&["local-only", "stop"])?;
    self_test.require_box_state("local-only", "stopped")
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
    self_test.execute(include_str!("scripts/namespaces.sh"), &[])?;
    self_test.execute(include_str!("scripts/overlay.sh"), &["--root"])?;
    Ok(())
}

fn exercise_shares(self_test: &SelfTest, writable: &Path, readonly: &Path) -> Result<()> {
    println!("self-test: writable/read-only shares, file events and synchronization");
    self_test.execute(include_str!("scripts/shares.sh"), &[])?;
    #[cfg(unix)]
    self_test.execute("test \"$(/work/host-run)\" = HOST_EXECUTABLE", &[])?;
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
    self_test.execute(include_str!("scripts/shares-persisted.sh"), &[])?;
    Ok(())
}

fn exercise_file_events(self_test: &SelfTest, writable: &Path) -> Result<()> {
    self_test.execute(include_str!("scripts/watcher-ready.sh"), &["--root"])?;
    fs::write(writable.join("host-update"), "LIVE_UPDATE")?;
    fs::write(writable.join("host-created"), "CREATED")?;
    self_test.execute(include_str!("scripts/file-events-created.sh"), &["--root"])?;
    fs::remove_file(writable.join("host-created"))?;
    self_test.execute(include_str!("scripts/file-events-deleted.sh"), &["--root"])?;
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
        include_str!("scripts/storage-restart.sh"),
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
    let recipe: Value = yaml_serde::from_str(
        &include_str!("recipes/bad-bake.yaml")
            .replace("{hardware}", &serde_json::to_string(hardware)?),
    )?;
    let bad_bake = self_test.setup("bad-bake", &recipe, None)?;
    require_output(&bad_bake, "FAILED_BAKE")?;
    require_output(
        &self_test.run(&["bad-bake", "logs", "--diagnostics"])?,
        "init failed",
    )?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_recipes_preserve_escaped_share_paths_and_recipe_settings() -> Result<()> {
        let mut exercise: Value = yaml_serde::from_str(
            &include_str!("recipes/exercise.yaml")
                .replace("{allowed_port}", "12345")
                .replace("{published_port}", "54321"),
        )?;
        let writable = Path::new(
            "C:\\self test\\{readonly}\\'quoted' \"double\"
next: value",
        );
        let readonly = Path::new(
            "/self test/{writable}/'quoted' \"double\"
next: value",
        );
        fill_share_path(&mut exercise["mounts"][0]["host"], "{writable}", writable)?;
        fill_share_path(&mut exercise["mounts"][1]["host"], "{readonly}", readonly)?;
        let serialized = yaml_serde::to_string(&exercise)?;
        let reparsed: Value = yaml_serde::from_str(&serialized)?;
        assert_eq!(reparsed, exercise);
        let config: crate::config::Config = yaml_serde::from_str(&serialized)?;
        assert_eq!(config.mounts[0].host, writable);
        assert_eq!(config.mounts[1].host, readonly);
        assert_eq!(config.hw.cpus, 2);
        assert_eq!(config.hw.mem_mib, 512);
        assert_eq!(config.hw.rootfs_mib, 128);
        assert_eq!(
            exercise["network"]["allow"],
            serde_json::json!(["gate.test:12345"])
        );
        assert_eq!(
            exercise["network"]["ports"],
            serde_json::json!(["54321:18080", "54321:18082/udp"])
        );
        assert!(config.daemons[2].contains("200 OK\\r\\nContent-Length: 13"));
        let hardware = serde_json::to_string(&exercise["hw"])?;
        for template in [
            include_str!("recipes/isolated.yaml"),
            include_str!("recipes/local-only.yaml"),
            include_str!("recipes/bad-bake.yaml"),
        ] {
            let recipe = template
                .replace("{hardware}", &hardware)
                .replace("{allowed_port}", "12345");
            let config: crate::config::Config = yaml_serde::from_str(&recipe)?;
            assert_eq!(config.hw.cpus, 2);
            assert_eq!(config.hw.mem_mib, 512);
            assert_eq!(config.hw.rootfs_mib, 128);
        }
        Ok(())
    }
}
