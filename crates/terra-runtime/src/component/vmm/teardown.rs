use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::machine::DeviceKind;

type Outcome = Result<(), String>;
type Close = futures_util::future::BoxFuture<'static, Outcome>;
type CleanupTask = super::reaper::NativeTask<()>;

#[derive(Default)]
struct TeardownGrants {
    machine: Option<super::virtualization::MachineRecovery>,
    devices: Vec<DeviceShutdown>,
    interrupts: Option<Close>,
}

impl TeardownGrants {
    fn has_work(&self) -> bool {
        self.machine.is_some() || !self.devices.is_empty() || self.interrupts.is_some()
    }
}

enum TeardownState {
    Collecting(TeardownGrants),
    Running(CleanupTask),
}

impl TeardownState {
    fn grants_mut(&mut self) -> wasmtime::Result<&mut TeardownGrants> {
        match self {
            Self::Collecting(grants) => Ok(grants),
            Self::Running(_) => wasmtime::bail!("native teardown already started"),
        }
    }

    fn task(&mut self) -> CleanupTask {
        match self {
            Self::Collecting(grants) => {
                let grants = std::mem::take(grants);
                let task = CleanupTask::new(
                    move || {
                        let result = run_teardown(grants);
                        if let Err(error) = &result {
                            log::warn!("native teardown failed: {error}");
                        }
                        result
                    },
                    None,
                );
                *self = Self::Running(task.clone());
                task
            }
            Self::Running(task) => task.clone(),
        }
    }

    fn has_work(&self) -> bool {
        match self {
            Self::Collecting(grants) => grants.has_work(),
            Self::Running(_) => true,
        }
    }
}

impl Drop for TeardownState {
    fn drop(&mut self) {
        if let Self::Collecting(grants) = self
            && grants.has_work()
        {
            self.task().start();
        }
    }
}

#[derive(Clone)]
pub struct NativeTeardown(Arc<Mutex<TeardownState>>);

impl NativeTeardown {
    #[must_use]
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(TeardownState::Collecting(
            TeardownGrants::default(),
        ))))
    }

    pub(crate) fn install_machine(
        &self,
        machine: super::virtualization::MachineRecovery,
    ) -> wasmtime::Result<()> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let grants = state.grants_mut()?;
        wasmtime::ensure!(
            grants.machine.is_none(),
            "native teardown already installed"
        );
        grants.machine = Some(machine);
        Ok(())
    }

    pub(crate) fn install_device(&self, device: DeviceShutdown) -> wasmtime::Result<()> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let grants = state.grants_mut()?;
        wasmtime::ensure!(
            grants.devices.len() < crate::box_runtime::MAX_BOX_COMPONENTS,
            "box has too many device shutdown grants"
        );
        grants.devices.push(device);
        Ok(())
    }

    pub(crate) fn install_interrupts(&self, interrupts: Close) -> wasmtime::Result<()> {
        let mut state = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let grants = state.grants_mut()?;
        wasmtime::ensure!(
            grants.interrupts.is_none(),
            "interrupt teardown already installed"
        );
        grants.interrupts = Some(interrupts);
        Ok(())
    }

    fn task(&self) -> CleanupTask {
        let task = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .task();
        task.start();
        task
    }

    pub(crate) fn start(&self) {
        self.task();
    }

    pub(crate) fn has_work(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .has_work()
    }

    pub async fn wait_until(&self, deadline: Instant) -> Outcome {
        self.task().wait_until(deadline).await
    }

    pub(crate) async fn wait_until_finished(&self) -> Outcome {
        self.task().wait_until_finished().await
    }
}

impl Default for NativeTeardown {
    fn default() -> Self {
        Self::new()
    }
}

fn run_teardown(mut grants: TeardownGrants) -> Outcome {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            std::mem::forget(grants);
            return Err(format!("native teardown runtime: {error}"));
        }
    };
    runtime.block_on(async move {
        if let Some(machine) = &mut grants.machine
            && let Err(error) = machine.wait().await
        {
            std::mem::forget(grants);
            return Err(error.to_string());
        }
        grants.devices.sort_by_key(DeviceShutdown::order);
        let TeardownGrants {
            machine,
            devices,
            interrupts,
            ..
        } = grants;
        drop(machine);
        let mut first_error = None;
        for device in devices {
            if let Err(error) = device.close().await {
                first_error.get_or_insert(error);
            }
        }
        if let Some(interrupts) = interrupts
            && let Err(error) = interrupts.await
        {
            first_error.get_or_insert(error);
        }
        first_error.map_or(Ok(()), Err)
    })
}

pub struct DeviceShutdown {
    pub(super) kind: DeviceKind,
    close: Close,
}

impl DeviceShutdown {
    pub fn new(kind: DeviceKind, close: impl Future<Output = Outcome> + Send + 'static) -> Self {
        Self {
            kind,
            close: Box::pin(close),
        }
    }

    pub(crate) fn order(&self) -> u8 {
        match self.kind {
            DeviceKind::Memory => 0,
            DeviceKind::Fs => 1,
            DeviceKind::Net => 2,
            DeviceKind::Vsock => 3,
            DeviceKind::Block => 4,
        }
    }

    async fn close(self) -> Outcome {
        self.close.await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn running_cleanup_rejects_grants_and_shares_its_outcome() {
        let teardown = NativeTeardown::new();
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        teardown
            .install_device(DeviceShutdown::new(DeviceKind::Block, async move {
                entered.send(()).unwrap();
                blocked.recv_timeout(Duration::from_secs(5)).unwrap();
                Err("device close failed".to_owned())
            }))
            .unwrap();
        teardown.start();
        started.await.unwrap();
        assert!(
            teardown
                .install_device(DeviceShutdown::new(DeviceKind::Block, async {
                    panic!("late device grant executed")
                }))
                .is_err()
        );
        assert!(
            teardown
                .install_interrupts(Box::pin(async { panic!("late grant executed") }))
                .is_err()
        );
        release.send(()).unwrap();
        let (first, second) = tokio::join!(
            teardown.wait_until_finished(),
            teardown.wait_until_finished()
        );
        assert_eq!(first, Err("device close failed".to_owned()));
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn cancelled_recovery_retains_cleanup_order() {
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, released) = tokio::sync::oneshot::channel();
        let (finished, completed) = tokio::sync::oneshot::channel();
        let first_finished = Arc::new(AtomicBool::new(false));
        let first_observer = Arc::clone(&first_finished);
        let devices = vec![
            DeviceShutdown::new(DeviceKind::Memory, async move {
                entered.send(()).unwrap();
                released.await.unwrap();
                first_finished.store(true, Ordering::Release);
                Ok(())
            }),
            DeviceShutdown::new(DeviceKind::Block, async move {
                assert!(first_observer.load(Ordering::Acquire));
                finished.send(()).unwrap();
                Ok(())
            }),
        ];
        let teardown = NativeTeardown::new();
        for device in devices {
            teardown.install_device(device).unwrap();
        }
        {
            let recovering = teardown.wait_until_finished();
            tokio::pin!(recovering);
            tokio::select! {
                result = &mut recovering => panic!("recovery completed before release: {result:?}"),
                result = started => result.unwrap(),
            }
        }
        drop(teardown);
        release.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(2), completed)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn recovery_finishes_every_cleanup_in_order_and_keeps_the_first_error() {
        let completed = Arc::new(std::sync::Mutex::new(Vec::new()));
        let first = Arc::clone(&completed);
        let second = Arc::clone(&completed);
        let interrupts = Arc::clone(&completed);
        let teardown = NativeTeardown::new();
        teardown
            .install_device(DeviceShutdown::new(DeviceKind::Block, async move {
                let mut completed = second.lock().unwrap();
                assert_eq!(*completed, ["memory"]);
                completed.push("block");
                Err("second failure".to_owned())
            }))
            .unwrap();
        teardown
            .install_device(DeviceShutdown::new(DeviceKind::Memory, async move {
                first.lock().unwrap().push("memory");
                Err("first failure".to_owned())
            }))
            .unwrap();
        teardown
            .install_interrupts(Box::pin(async move {
                let mut completed = interrupts.lock().unwrap();
                assert_eq!(*completed, ["memory", "block"]);
                completed.push("interrupts");
                Err("interrupt failure".to_owned())
            }))
            .unwrap();
        assert_eq!(
            teardown.wait_until_finished().await.unwrap_err(),
            "first failure"
        );
        assert_eq!(
            *completed.lock().unwrap(),
            ["memory", "block", "interrupts"]
        );
    }

    #[test]
    fn only_the_last_owner_starts_drop_cleanup() {
        let teardown = NativeTeardown::new();
        let retained = teardown.clone();
        let (closed, completion) = std::sync::mpsc::channel();
        teardown
            .install_device(DeviceShutdown::new(DeviceKind::Block, async move {
                tokio::time::sleep(Duration::from_millis(1)).await;
                closed.send(()).unwrap();
                Ok(())
            }))
            .unwrap();
        drop(teardown);
        assert_eq!(
            completion.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        );
        drop(retained);
        completion
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
    }

    #[test]
    fn rejected_grants_do_not_start_cleanup() {
        let teardown = NativeTeardown::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let interrupt_calls = Arc::clone(&calls);
        teardown
            .install_interrupts(Box::pin(async move {
                interrupt_calls.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }))
            .unwrap();
        let rejected_calls = Arc::clone(&calls);
        assert!(
            teardown
                .install_interrupts(Box::pin(async move {
                    rejected_calls.fetch_add(1, Ordering::Relaxed);
                    Ok(())
                }))
                .is_err()
        );
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }
}
