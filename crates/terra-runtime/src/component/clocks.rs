//! Narrow WASI clock imports for device components.

use wasmtime::component::Linker;
use wasmtime_wasi::{
    clocks::{WasiClocks, WasiClocksView},
    p3::bindings::clocks::{monotonic_clock, system_clock, types},
};

pub fn add_monotonic_now<T: WasiClocksView + 'static>(
    linker: &mut Linker<T>,
) -> wasmtime::Result<()> {
    types::add_to_linker::<T, WasiClocks>(linker, T::clocks)?;
    linker
        .instance("wasi:clocks/monotonic-clock@0.3.0")?
        .func_wrap("now", |mut store, (): ()| {
            Ok((monotonic_clock::Host::now(&mut T::clocks(
                store.data_mut(),
            ))?,))
        })
}

pub fn add_monotonic_now_and_wait_for<T: WasiClocksView + 'static>(
    linker: &mut Linker<T>,
) -> wasmtime::Result<()> {
    add_monotonic_now(linker)?;
    add_wait_for(linker)
}

pub fn add_monotonic_wait_for<T: WasiClocksView + 'static>(
    linker: &mut Linker<T>,
) -> wasmtime::Result<()> {
    types::add_to_linker::<T, WasiClocks>(linker, T::clocks)?;
    add_wait_for(linker)
}

fn add_wait_for<T: WasiClocksView + 'static>(linker: &mut Linker<T>) -> wasmtime::Result<()> {
    linker
        .instance("wasi:clocks/monotonic-clock@0.3.0")?
        .func_wrap_concurrent("wait-for", |accessor, (duration,): (types::Duration,)| {
            Box::pin(async move {
                monotonic_clock::HostWithStore::wait_for(
                    &accessor.with_getter::<WasiClocks>(T::clocks),
                    duration,
                )
                .await
            })
        })
}

pub fn add_system_clock_now<T: WasiClocksView + 'static>(
    linker: &mut Linker<T>,
) -> wasmtime::Result<()> {
    linker
        .instance("wasi:clocks/system-clock@0.3.0")?
        .func_wrap("now", |mut store, (): ()| {
            Ok((system_clock::Host::now(&mut T::clocks(store.data_mut()))?,))
        })
}
