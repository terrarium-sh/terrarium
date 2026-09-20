//! The `terra` binary: everything it does is [`terra::run`].

use std::process::ExitCode;

fn main() -> ExitCode {
    match run_with_runtime(terra::run()) {
        Ok(code) => code,
        Err(error) if terra::is_stdout_broken_pipe(&error) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("terra: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run_with_runtime<F, T>(operation: F) -> anyhow::Result<T>
where
    F: std::future::Future<Output = anyhow::Result<T>>,
{
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(operation);
    runtime.shutdown_timeout(std::time::Duration::from_secs(1));
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    #[test]
    fn process_exits_with_a_permanently_blocked_host_operation() {
        const CHILD: &str = "TERRA_TEST_BLOCKED_SHUTDOWN";
        if std::env::var_os(CHILD).is_some() {
            super::run_with_runtime(async {
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
