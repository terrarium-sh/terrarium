use anyhow::{Result, ensure};

use super::SelfTest;

pub(super) fn exercise(self_test: &SelfTest) -> Result<()> {
    ensure!(
        self_test.read_json(&["exercise", "sessions", "--json"])? == serde_json::json!([]),
        "unexpected initial terminal sessions"
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
    use std::process::Stdio;
    use std::time::Duration;

    use anyhow::Context as _;

    let (_master, slave) = open_terminal_pair()?;
    let mut client = AttachedClient(
        self_test
            .command(["exercise"])
            .stdin(Stdio::from(slave))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("attaching terminal client")?,
    );
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
    self_test.run(&["exercise", "detach", &id])?;
    super::wait_until(
        || {
            let Some(status) = client.0.try_wait()? else {
                return Ok(false);
            };
            ensure!(status.success(), "detached terminal client: {status}");
            Ok(true)
        },
        "terminal client exit",
        Duration::from_secs(10),
    )?;
    ensure!(
        self_test.read_json(&["exercise", "sessions", "--json"])? == serde_json::json!([]),
        "terminal session survived detach"
    );
    self_test.run_expected(&["exercise", "detach", &id], None, super::COMMAND_TIMEOUT)?;
    self_test.run(&["exercise", "detach", "--all"])?;
    Ok(())
}

#[cfg(unix)]
struct AttachedClient(std::process::Child);

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
            std::ptr::null(),
            std::ptr::null(),
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
