//! The `terra` binary: everything it does is [`terra::run`].

use std::process::ExitCode;

fn main() -> ExitCode {
    if let Some(role) = std::env::args_os()
        .nth(1)
        .and_then(|argument| terra::role::from_argument(&argument))
    {
        return role();
    }
    terra::exit_code_of(terra::run_with_runtime(terra::run()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    #[test]
    fn process_exits_with_a_permanently_blocked_host_operation() {
        const CHILD: &str = "TERRA_TEST_BLOCKED_SHUTDOWN";
        if std::env::var_os(CHILD).is_some() {
            terra::run_with_runtime(async {
                let (started, ready) = tokio::sync::oneshot::channel();
                tokio::task::spawn_blocking(move || {
                    let _ = started.send(());
                    loop {
                        std::thread::park();
                    }
                });
                ready.await?;
                Ok(())
            })
            .unwrap();
            return;
        }
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::process_exits_with_a_permanently_blocked_host_operation",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("process teardown waited for a blocked host operation");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
