//! Drive a Wasm device and forward its interrupt level to the host.

use std::sync::Arc;

use tokio::sync::Notify;
use wasmtime::component::{Accessor, Lift, TypedFunc};

use super::Interrupt;
use crate::box_runtime::{BoxHost, BoxRuntime};

pub(crate) struct Worker<E> {
    pub run: TypedFunc<(), (Result<(), E>,)>,
    pub interrupt: Interrupt,
}

impl<E: Lift + std::fmt::Debug + Send + Sync + 'static> Worker<E> {
    pub fn register(
        self,
        runtime: &mut BoxRuntime,
        wake: Arc<Notify>,
        name: &'static str,
        read_interrupt: impl Fn(&mut BoxHost) -> wasmtime::Result<bool> + Send + Sync + 'static,
    ) -> wasmtime::Result<()> {
        runtime.register_loop(Box::new(move |accessor| {
            Box::pin(self.drive(accessor, wake, name, read_interrupt))
        }))
    }

    pub(crate) async fn drive(
        self,
        accessor: &Accessor<BoxHost>,
        wake: Arc<Notify>,
        name: &'static str,
        read_interrupt: impl Fn(&mut BoxHost) -> wasmtime::Result<bool> + Send + Sync,
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
            let level = accessor.with(|mut store| read_interrupt(store.data_mut()))?;
            (self.interrupt)(level)?;
            if finished {
                return Ok(());
            }
        }
    }
}
