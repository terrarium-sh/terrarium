use wasmtime::component::{Access, Resource, StreamReader};
use wasmtime_wasi::{
    filesystem::{Descriptor, WasiFilesystem},
    p3::bindings::filesystem::types::{self, HostDescriptorWithStore},
};

macro_rules! descriptor_async {
    ($interface:expr, $filesystem:expr, $name:literal, $method:ident, ($($arg:ident: $type:ty),+ $(,)?)) => {
        $interface.func_wrap_concurrent($name, move |accessor, ($($arg,)+): ($($type,)+)| {
            Box::pin(async move {
                let wasi = accessor.with_getter::<WasiFilesystem>($filesystem);
                match <WasiFilesystem as HostDescriptorWithStore<T>>::$method(&wasi, $($arg),+).await {
                    Ok(value) => Ok((Ok(value),)),
                    Err(error) => Ok((Err(error.downcast()?),)),
                }
            })
        })?;
    };
}

pub(super) fn add<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    filesystem: for<'a> fn(&'a mut T) -> wasmtime_wasi::filesystem::WasiFilesystemCtxView<'a>,
) -> wasmtime::Result<()> {
    let mut interface = linker.instance("wasi:filesystem/types@0.3.0")?;
    interface.func_wrap(
        "[method]descriptor.read-via-stream",
        move |store, (descriptor, offset): (Resource<Descriptor>, types::Filesize)| {
            Ok((
                <WasiFilesystem as HostDescriptorWithStore<T>>::read_via_stream(
                    Access::<T, WasiFilesystem>::new(store, filesystem),
                    descriptor,
                    offset,
                )?,
            ))
        },
    )?;
    interface.func_wrap(
        "[method]descriptor.write-via-stream",
        move |store,
              (descriptor, data, offset): (
            Resource<Descriptor>,
            StreamReader<u8>,
            types::Filesize,
        )| {
            Ok((
                <WasiFilesystem as HostDescriptorWithStore<T>>::write_via_stream(
                    Access::<T, WasiFilesystem>::new(store, filesystem),
                    descriptor,
                    data,
                    offset,
                )?,
            ))
        },
    )?;
    descriptor_async!(interface, filesystem, "[method]descriptor.sync-data", sync_data, (descriptor: Resource<Descriptor>));
    descriptor_async!(interface, filesystem, "[method]descriptor.get-flags", get_flags, (descriptor: Resource<Descriptor>));
    descriptor_async!(interface, filesystem, "[method]descriptor.get-type", get_type, (descriptor: Resource<Descriptor>));
    descriptor_async!(interface, filesystem, "[method]descriptor.set-size", set_size, (descriptor: Resource<Descriptor>, size: types::Filesize));
    descriptor_async!(interface, filesystem, "[method]descriptor.set-times", set_times, (descriptor: Resource<Descriptor>, access_time: types::NewTimestamp, modification_time: types::NewTimestamp));
    interface.func_wrap(
        "[method]descriptor.read-directory",
        move |store, (descriptor,): (Resource<Descriptor>,)| {
            Ok((
                <WasiFilesystem as HostDescriptorWithStore<T>>::read_directory(
                    Access::<T, WasiFilesystem>::new(store, filesystem),
                    descriptor,
                )?,
            ))
        },
    )?;
    descriptor_async!(interface, filesystem, "[method]descriptor.sync", sync, (descriptor: Resource<Descriptor>));
    descriptor_async!(interface, filesystem, "[method]descriptor.create-directory-at", create_directory_at, (descriptor: Resource<Descriptor>, path: String));
    descriptor_async!(interface, filesystem, "[method]descriptor.stat", stat, (descriptor: Resource<Descriptor>));
    descriptor_async!(interface, filesystem, "[method]descriptor.stat-at", stat_at, (descriptor: Resource<Descriptor>, flags: types::PathFlags, path: String));
    descriptor_async!(interface, filesystem, "[method]descriptor.set-times-at", set_times_at, (descriptor: Resource<Descriptor>, flags: types::PathFlags, path: String, access_time: types::NewTimestamp, modification_time: types::NewTimestamp));
    descriptor_async!(interface, filesystem, "[method]descriptor.link-at", link_at, (descriptor: Resource<Descriptor>, old_flags: types::PathFlags, old_path: String, new_descriptor: Resource<Descriptor>, new_path: String));
    descriptor_async!(interface, filesystem, "[method]descriptor.readlink-at", readlink_at, (descriptor: Resource<Descriptor>, path: String));
    descriptor_async!(interface, filesystem, "[method]descriptor.remove-directory-at", remove_directory_at, (descriptor: Resource<Descriptor>, path: String));
    descriptor_async!(interface, filesystem, "[method]descriptor.rename-at", rename_at, (descriptor: Resource<Descriptor>, old_path: String, new_descriptor: Resource<Descriptor>, new_path: String));
    descriptor_async!(interface, filesystem, "[method]descriptor.symlink-at", symlink_at, (descriptor: Resource<Descriptor>, old_path: String, new_path: String));
    descriptor_async!(interface, filesystem, "[method]descriptor.unlink-file-at", unlink_file_at, (descriptor: Resource<Descriptor>, path: String));
    descriptor_async!(interface, filesystem, "[method]descriptor.metadata-hash", metadata_hash, (descriptor: Resource<Descriptor>));
    descriptor_async!(interface, filesystem, "[method]descriptor.metadata-hash-at", metadata_hash_at, (descriptor: Resource<Descriptor>, flags: types::PathFlags, path: String));
    Ok(())
}
