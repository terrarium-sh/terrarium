//! Drive a Wasm device and forward its interrupt level to the host.

use std::sync::Arc;

use tokio::sync::Notify;
use wasmtime::component::{Accessor, Lift, TypedFunc};

use super::InterruptCallback;
use crate::box_runtime::DeviceWorker;
use crate::box_runtime::store::{StoreHost, StoreState};
use crate::component::context::DeviceHost;

pub(crate) struct DeviceLoop<E> {
    pub run: TypedFunc<(), (Result<(), E>,)>,
    pub interrupt: InterruptCallback,
}

impl<E: Lift + std::fmt::Debug + Send + Sync + 'static> DeviceLoop<E> {
    pub fn register<H: StoreHost + DeviceHost>(
        self,
        runtime: &mut DeviceWorker<H>,
        wake: Arc<Notify>,
        name: &'static str,
    ) -> wasmtime::Result<()> {
        runtime.register_loop(Box::new(move |accessor| {
            Box::pin(self.drive(accessor, wake, name))
        }))
    }

    pub(crate) async fn drive<H: StoreHost + DeviceHost>(
        self,
        accessor: &Accessor<StoreState<H>>,
        wake: Arc<Notify>,
        name: &'static str,
    ) -> wasmtime::Result<()> {
        let running = self.run.call_concurrent(accessor, ());
        tokio::pin!(running);
        loop {
            let finished = tokio::select! {
                result = &mut running => {
                    result?.0.map_err(|error| wasmtime::Error::msg(format!("{name} worker: {error:?}")))?;
                    true
                },
                () = wake.notified() => false,
            };
            let level = accessor.with(|mut store| {
                let host = store.data_mut().context();
                host.end_window();
                host.interrupt_level()
            });
            (self.interrupt)(level)?;
            if finished {
                return Ok(());
            }
        }
    }
}
