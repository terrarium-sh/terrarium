use anyhow::{Result, ensure};

use super::SelfTest;

pub(super) fn exercise(self_test: &SelfTest) -> Result<()> {
    ensure!(
        self_test.read_json(&["exercise", "sessions", "--json"])? == serde_json::json!([]),
        "unexpected initial terminal sessions"
    );
    ensure!(
        String::from_utf8(self_test.run(&["exercise", "sessions"])?.stdout)?
            .trim()
            .is_empty(),
        "unexpected initial terminal sessions output"
    );
    #[cfg(unix)]
    exercise_attachment(self_test)?;
    #[cfg(not(unix))]
    {
        println!("self-test: terminal attachment skipped on this host");
        self_test.run(&["exercise", "detach", "--all"])?;
    }
    Ok(())
}

#[cfg(unix)]
fn exercise_attachment(self_test: &SelfTest) -> Result<()> {
    use std::time::Duration;

    use anyhow::Context as _;

    let (mut client, _terminal) = attach_terminal_client(self_test)?;
    super::wait_until(
        || {
            let sessions = self_test.read_json(&["exercise", "sessions", "--json"])?;
            Ok(sessions
                .as_array()
                .is_some_and(|sessions| !sessions.is_empty()))
        },
        "terminal attachment",
        Duration::from_secs(30),
    )?;
    let sessions = self_test.read_json(&["exercise", "sessions", "--json"])?;
    let id = sessions[0]["id"]
        .as_u64()
        .context("terminal session ID missing")?
        .to_string();
    ensure!(id == "0", "first terminal session ID: expected 0, got {id}");
    ensure!(
        String::from_utf8(self_test.run(&["exercise", "sessions"])?.stdout)?
            .trim()
            .starts_with("0\t"),
        "first terminal session output is missing its ID row"
    );
    self_test.run(&["exercise", "detach", &id])?;
    client.wait_for_exit()?;
    ensure!(
        self_test.read_json(&["exercise", "sessions", "--json"])? == serde_json::json!([]),
        "terminal session survived detach"
    );
    ensure!(
        String::from_utf8(self_test.run(&["exercise", "sessions"])?.stdout)?
            .trim()
            .is_empty(),
        "terminal session output survived detach"
    );
    self_test.run_expected(&["exercise", "detach", &id], None, super::COMMAND_TIMEOUT)?;
    self_test.run(&["exercise", "detach", "--all"])?;
    let (mut first_client, _first_terminal) = attach_terminal_client(self_test)?;
    let (mut second_client, _second_terminal) = attach_terminal_client(self_test)?;
    super::wait_until(
        || {
            let sessions = self_test.read_json(&["exercise", "sessions", "--json"])?;
            Ok(sessions
                .as_array()
                .is_some_and(|sessions| sessions.len() == 2))
        },
        "two terminal attachments",
        Duration::from_secs(30),
    )?;
    self_test.run(&["exercise", "detach", "--all"])?;
    first_client.wait_for_exit()?;
    second_client.wait_for_exit()?;
    ensure!(
        self_test.read_json(&["exercise", "sessions", "--json"])? == serde_json::json!([]),
        "terminal sessions survived detach --all"
    );
    ensure!(
        String::from_utf8(self_test.run(&["exercise", "sessions"])?.stdout)?
            .trim()
            .is_empty(),
        "terminal session output survived detach --all"
    );

    Ok(())
}

#[cfg(unix)]
fn attach_terminal_client(self_test: &SelfTest) -> Result<(AttachedClient, std::os::fd::OwnedFd)> {
    use std::process::Stdio;

    use anyhow::Context as _;

    let (terminal, slave) = open_terminal_pair()?;
    let client = self_test
        .command(["exercise"])
        .stdin(Stdio::from(slave))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("attaching terminal client")?;
    Ok((AttachedClient(client), terminal))
}

#[cfg(unix)]
struct AttachedClient(std::process::Child);

#[cfg(unix)]
impl AttachedClient {
    fn wait_for_exit(&mut self) -> Result<()> {
        super::wait_until(
            || {
                let Some(status) = self.0.try_wait()? else {
                    return Ok(false);
                };
                ensure!(status.success(), "detached terminal client: {status}");
                Ok(true)
            },
            "terminal client exit",
            std::time::Duration::from_secs(10),
        )
    }
}

#[cfg(unix)]
impl Drop for AttachedClient {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
#[allow(unsafe_code)]
fn open_terminal_pair() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::{FromRawFd as _, OwnedFd};

    let mut master = -1;
    let mut slave = -1;
    // SAFETY: openpty initializes both descriptors; optional name and terminal settings are null.
    let result = unsafe {
        libc::openpty(
            &raw mut master,
            &raw mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful openpty returns two newly owned descriptors.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    rustix::io::fcntl_setfd(&master, rustix::io::FdFlags::CLOEXEC)?;
    rustix::io::fcntl_setfd(&slave, rustix::io::FdFlags::CLOEXEC)?;
    Ok((master, slave))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn attachment_uses_a_real_terminal_pair() -> Result<()> {
        let (master, slave) = open_terminal_pair()?;
        assert!(rustix::termios::isatty(&master));
        assert!(rustix::termios::isatty(&slave));
        Ok(())
    }
}
