use super::ShareGrant;
use super::bindings::wit as terra;
use super::metadata::{get_mode, get_mode_at, open_metadata_file, set_mode, set_mode_at, statfs};

use wasmtime::component::{Access, HasSelf, Resource, StreamReader};
use wasmtime_wasi::{
    WasiView,
    filesystem::{Descriptor, Dir, OpenMode, WasiFilesystem},
    p3::bindings::filesystem::{preopens, types},
};

pub struct FsHost {
    pub device: crate::component::context::DeviceContext,
    grant: ShareGrant,
    events: Option<super::file_events::FileEvents>,
    descriptor_budget: std::sync::Arc<tokio::sync::Semaphore>,
    descriptor_permits: std::collections::HashMap<u32, tokio::sync::OwnedSemaphorePermit>,
    #[cfg(test)]
    pub(super) io_gate: Option<std::sync::Arc<super::stalled_io::IoGate>>,
}

impl crate::box_runtime::store::StoreHost for FsHost {
    fn retire(self) {
        let pending = std::sync::Arc::new(std::sync::Mutex::new(Some(self)));
        let worker = pending.clone();
        if std::thread::Builder::new()
            .name("terra-filesystem-drop".into())
            .spawn(move || {
                match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime.block_on(async {
                        let host = worker
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take();
                        drop(host);
                    }),
                    Err(_) => std::mem::forget(worker),
                }
            })
            .is_err()
        {
            // ponytail: retain filesystem resources if cleanup cannot start; retry if thread exhaustion becomes recoverable.
            std::mem::forget(pending);
        }
    }
}

impl FsHost {
    #[must_use]
    pub fn new(device: crate::component::context::DeviceContext, grant: ShareGrant) -> Self {
        Self::with_resource_capacity(device, grant, 16_384)
    }

    #[must_use]
    pub fn with_resource_capacity(
        mut device: crate::component::context::DeviceContext,
        grant: ShareGrant,
        resource_capacity: usize,
    ) -> Self {
        device.ctx().table.set_max_capacity(resource_capacity);
        Self {
            device,
            grant,
            events: None,
            descriptor_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(resource_capacity)),
            descriptor_permits: std::collections::HashMap::new(),
            #[cfg(test)]
            io_gate: None,
        }
    }

    pub(super) async fn initialize_events(&mut self) {
        self.events = Some(super::file_events::FileEvents::new(&self.grant).await);
    }

    fn preopen_directory(&self) -> Descriptor {
        Descriptor::Dir(self.grant.directory.clone())
    }

    fn grant_directory(&mut self) -> wasmtime::Result<Resource<Descriptor>> {
        let permit = self.descriptor_budget.clone().try_acquire_owned()?;
        let directory = self.preopen_directory();
        let resource = self.ctx().table.push(directory)?;
        self.descriptor_permits.insert(resource.rep(), permit);
        Ok(resource)
    }

    fn retire_descriptor(
        &mut self,
        representation: u32,
    ) -> wasmtime::Result<tokio::task::JoinHandle<()>> {
        let descriptor = self
            .ctx()
            .table
            .delete(Resource::<Descriptor>::new_own(representation))?;
        let permit = self.descriptor_permits.remove(&representation);
        #[cfg(test)]
        let gate = self.io_gate.clone();
        Ok(tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            if let Some(gate) = gate {
                gate.wait_on_descriptor_drop();
            }
            drop(descriptor);
            drop(permit);
        }))
    }

    fn clone_descriptor(
        &mut self,
        descriptor: &Resource<Descriptor>,
    ) -> Result<Descriptor, terra::fs::host::Error> {
        self.ctx()
            .table
            .get(descriptor)
            .cloned()
            .map_err(|_| terra::fs::host::Error::Access)
    }

    #[cfg(windows)]
    fn reopen_file_for_delete_sharing(
        &mut self,
        resource: &Resource<Descriptor>,
    ) -> Result<(), types::ErrorCode> {
        let descriptor = self
            .ctx()
            .table
            .get_mut(resource)
            .map_err(|_| types::ErrorCode::Io)?;
        let Descriptor::File(file) = descriptor else {
            return Ok(());
        };
        let access = terra_platform::filesystem::FileAccess {
            read: file.open_mode.contains(OpenMode::READ),
            write: file.open_mode.contains(OpenMode::WRITE),
        };
        let reopened =
            terra_platform::filesystem::reopen_file_with_delete_sharing(&file.file, access)
                .map_err(|_| types::ErrorCode::Io)?;
        file.file = std::sync::Arc::new(reopened);
        Ok(())
    }

    #[cfg(windows)]
    pub(super) fn directory(
        &mut self,
        resource: &Resource<Descriptor>,
    ) -> Result<Dir, types::ErrorCode> {
        let descriptor = self
            .ctx()
            .table
            .get(resource)
            .map_err(|_| types::ErrorCode::BadDescriptor)?;
        let Descriptor::Dir(directory) = descriptor else {
            return Err(types::ErrorCode::NotDirectory);
        };
        Ok(directory.clone())
    }

    #[cfg(windows)]
    fn writable_directory(
        &mut self,
        resource: &Resource<Descriptor>,
    ) -> Result<Dir, types::ErrorCode> {
        let directory = self.directory(resource)?;
        if directory.perms.write_not_permitted() {
            return Err(types::ErrorCode::NotPermitted);
        }
        Ok(directory)
    }
}

impl WasiView for FsHost {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        self.device.ctx()
    }
}

impl<T: Send + 'static> terra::fs::host::HostWithStore<T> for HasSelf<FsHost> {
    async fn release_descriptor(
        accessor: &wasmtime::component::Accessor<T, Self>,
        descriptor: Resource<Descriptor>,
    ) -> Result<(), terra::fs::host::Error> {
        accessor
            .with(|mut access| access.get().retire_descriptor(descriptor.rep()))
            .map_err(|_| terra::fs::host::Error::Io)?
            .await
            .map_err(|_| terra::fs::host::Error::Io)
    }

    async fn open_metadata_at(
        accessor: &wasmtime::component::Accessor<T, Self>,
        parent: Resource<Descriptor>,
        name: String,
    ) -> Result<Resource<Descriptor>, terra::fs::host::Error> {
        use terra::fs::host::Error;
        let (directory, permit) = accessor.with(|mut access| {
            let host = access.get();
            let Descriptor::Dir(directory) = host.clone_descriptor(&parent)? else {
                return Err(Error::Access);
            };
            let permit = host
                .descriptor_budget
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::Io)?;
            Ok((directory, permit))
        })?;
        let (descriptor, permit) = tokio::task::spawn_blocking(move || {
            let file = open_metadata_file(&directory.dir, &name)?;
            let descriptor = if file.metadata().map_err(|_| Error::Io)?.is_dir() {
                Descriptor::Dir(Dir::new(file, directory.perms, OpenMode::empty(), false))
            } else {
                Descriptor::File(wasmtime_wasi::filesystem::File::new(
                    file,
                    directory.perms,
                    OpenMode::empty(),
                    false,
                ))
            };
            Ok::<_, Error>((descriptor, permit))
        })
        .await
        .map_err(|_| Error::Io)??;
        accessor.with(|mut access| {
            let host = access.get();
            let resource = host.ctx().table.push(descriptor).map_err(|_| Error::Io)?;
            host.descriptor_permits.insert(resource.rep(), permit);
            Ok(resource)
        })
    }

    fn statfs(
        accessor: &wasmtime::component::Accessor<T, Self>,
        descriptor: Resource<Descriptor>,
    ) -> impl Future<Output = Result<terra::fs::host::FilesystemStat, terra::fs::host::Error>> + Send
    {
        let descriptor = accessor.with(|mut access| access.get().clone_descriptor(&descriptor));
        async move {
            let descriptor = descriptor?;
            tokio::task::spawn_blocking(move || statfs(&descriptor))
                .await
                .map_err(|_| terra::fs::host::Error::Io)?
        }
    }

    fn get_mode(
        accessor: &wasmtime::component::Accessor<T, Self>,
        descriptor: Resource<Descriptor>,
    ) -> impl Future<Output = Result<Option<u32>, terra::fs::host::Error>> + Send {
        #[cfg(test)]
        let gate = accessor.with(|mut access| access.get().io_gate.clone());
        let descriptor = accessor.with(|mut access| access.get().clone_descriptor(&descriptor));
        async move {
            let descriptor = descriptor?;
            tokio::task::spawn_blocking(move || {
                #[cfg(test)]
                if let Some(gate) = gate {
                    gate.wait_on_host_thread();
                }
                get_mode(&descriptor)
            })
            .await
            .map_err(|_| terra::fs::host::Error::Io)?
        }
    }

    fn set_mode(
        accessor: &wasmtime::component::Accessor<T, Self>,
        descriptor: Resource<Descriptor>,
        mode: u32,
    ) -> impl Future<Output = Result<(), terra::fs::host::Error>> + Send {
        let descriptor = accessor.with(|mut access| {
            let host = access.get();
            if host.grant.readonly {
                return Err(terra::fs::host::Error::Access);
            }
            host.clone_descriptor(&descriptor)
        });
        async move {
            let descriptor = descriptor?;
            tokio::task::spawn_blocking(move || set_mode(&descriptor, mode))
                .await
                .map_err(|_| terra::fs::host::Error::Io)?
        }
    }

    async fn get_mode_at(
        accessor: &wasmtime::component::Accessor<T, Self>,
        parent: Resource<Descriptor>,
        name: String,
    ) -> Result<Option<u32>, terra::fs::host::Error> {
        let parent = accessor.with(|mut access| access.get().clone_descriptor(&parent))?;
        tokio::task::spawn_blocking(move || get_mode_at(&parent, &name))
            .await
            .map_err(|_| terra::fs::host::Error::Io)?
    }

    async fn set_mode_at(
        accessor: &wasmtime::component::Accessor<T, Self>,
        parent: Resource<Descriptor>,
        name: String,
        mode: u32,
    ) -> Result<(), terra::fs::host::Error> {
        let parent = accessor.with(|mut access| {
            let host = access.get();
            if host.grant.readonly {
                return Err(terra::fs::host::Error::Access);
            }
            host.clone_descriptor(&parent)
        })?;
        tokio::task::spawn_blocking(move || set_mode_at(&parent, &name, mode))
            .await
            .map_err(|_| terra::fs::host::Error::Io)?
    }

    fn file_events(
        mut access: Access<'_, T, Self>,
    ) -> wasmtime::Result<StreamReader<terra::fs::host::FileEvent>> {
        let host = access.get();
        let events = host.events.take().unwrap_or_default();
        StreamReader::new(&mut access, events)
    }
}

impl terra::fs::host::Host for FsHost {}

impl preopens::Host for FsHost {
    fn get_directories(&mut self) -> wasmtime::Result<Vec<(Resource<Descriptor>, String)>> {
        Ok(vec![(self.grant_directory()?, "/".into())])
    }
}

impl crate::component::context::DeviceHost for FsHost {
    fn context(&mut self) -> &mut crate::component::context::DeviceContext {
        &mut self.device
    }
}
impl AsMut<FsHost> for FsHost {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

pub fn fs_component_linker<T: WasiView + AsMut<FsHost> + 'static>(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<T>> {
    use wasmtime_wasi::filesystem::WasiFilesystemView;
    let mut linker = wasmtime::component::Linker::new(engine);
    crate::component::clocks::add_monotonic_wait_for(&mut linker)?;
    add_descriptor_lifecycle(&mut linker, T::filesystem, AsMut::as_mut)?;
    super::resource_linker::add(&mut linker, T::filesystem)?;
    terra::fs::host::add_to_linker::<T, HasSelf<FsHost>>(&mut linker, AsMut::as_mut)?;
    preopens::add_to_linker::<T, HasSelf<FsHost>>(&mut linker, AsMut::as_mut)?;
    crate::component::context::add_device_imports(&mut linker, |host: &mut T| {
        &mut host.as_mut().device
    })?;
    Ok(linker)
}

fn add_descriptor_lifecycle<T: Send + 'static>(
    linker: &mut wasmtime::component::Linker<T>,
    filesystem: for<'a> fn(&'a mut T) -> wasmtime_wasi::filesystem::WasiFilesystemCtxView<'a>,
    host: for<'a> fn(&'a mut T) -> &'a mut FsHost,
) -> wasmtime::Result<()> {
    use types::HostDescriptorWithStore;
    linker.allow_shadowing(true);
    let mut interface = linker.instance("wasi:filesystem/types@0.3.0")?;
    interface.resource(
        "descriptor",
        wasmtime::component::ResourceType::host::<Descriptor>(),
        move |mut store, representation| {
            host(store.data_mut())
                .retire_descriptor(representation)
                .map(drop)
        },
    )?;
    interface.func_wrap_concurrent(
        "[method]descriptor.open-at",
        move |accessor,
              (descriptor, path_flags, path, open_flags, flags): (
            Resource<Descriptor>,
            types::PathFlags,
            String,
            types::OpenFlags,
            types::DescriptorFlags,
        )| {
            let permit = accessor.with(|mut access| {
                host(access.data_mut())
                    .descriptor_budget
                    .clone()
                    .try_acquire_owned()
            });
            Box::pin(async move {
                let Ok(permit) = permit else {
                    return Ok((Err(types::ErrorCode::InsufficientMemory),));
                };
                let wasi = accessor.with_getter::<WasiFilesystem>(filesystem);
                match WasiFilesystem::open_at(
                    &wasi, descriptor, path_flags, path, open_flags, flags,
                )
                .await
                {
                    Ok(resource) => {
                        let opened: Result<Resource<Descriptor>, types::ErrorCode> =
                            accessor.with(|mut access| {
                                let host = host(access.data_mut());
                                #[cfg(windows)]
                                if let Err(error) = host.reopen_file_for_delete_sharing(&resource) {
                                    host.ctx()
                                        .table
                                        .delete(resource)
                                        .map_err(|_| types::ErrorCode::Io)?;
                                    return Err(error);
                                }
                                host.descriptor_permits.insert(resource.rep(), permit);
                                Ok(resource)
                            });
                        Ok((opened,))
                    }
                    Err(error) => Ok((Err(error.downcast()?),)),
                }
            })
        },
    )?;
    #[cfg(windows)]
    super::read_directory::add_windows_read_directory(&mut interface, host)?;
    #[cfg(windows)]
    add_windows_mutations(&mut interface, host)?;
    linker.allow_shadowing(false);
    Ok(())
}

#[cfg(windows)]
fn add_windows_mutations<T: Send + 'static>(
    interface: &mut wasmtime::component::LinkerInstance<'_, T>,
    host: for<'a> fn(&'a mut T) -> &'a mut FsHost,
) -> wasmtime::Result<()> {
    interface.func_wrap_concurrent(
        "[method]descriptor.create-directory-at",
        move |accessor, (descriptor, path): (Resource<Descriptor>, String)| {
            let directory =
                accessor.with(|mut access| host(access.data_mut()).writable_directory(&descriptor));
            Box::pin(async move {
                let result = match directory {
                    Ok(directory) => tokio::task::spawn_blocking(move || {
                        terra_platform::filesystem::create_directory_at(
                            &directory.dir,
                            path.as_ref(),
                        )
                    })
                    .await
                    .map_err(|_| types::ErrorCode::Io)
                    .and_then(|result| result.map_err(Into::into)),
                    Err(error) => Err(error),
                };
                Ok((result,))
            })
        },
    )?;
    interface.func_wrap_concurrent(
        "[method]descriptor.link-at",
        move |accessor,
              (descriptor, old_flags, old_path, new_descriptor, new_path): (
            Resource<Descriptor>,
            types::PathFlags,
            String,
            Resource<Descriptor>,
            String,
        )| {
            let directories = accessor.with(|mut access| {
                let host = host(access.data_mut());
                let old = host.writable_directory(&descriptor)?;
                let new = host.writable_directory(&new_descriptor)?;
                if old_flags.contains(types::PathFlags::SYMLINK_FOLLOW) {
                    return Err(types::ErrorCode::Invalid);
                }
                if old.perms != new.perms {
                    return Err(types::ErrorCode::NotPermitted);
                }
                Ok((old, new))
            });
            Box::pin(async move {
                let result = match directories {
                    Ok((old, new)) => tokio::task::spawn_blocking(move || {
                        terra_platform::filesystem::hard_link_at(
                            &old.dir,
                            old_path.as_ref(),
                            &new.dir,
                            new_path.as_ref(),
                        )
                    })
                    .await
                    .map_err(|_| types::ErrorCode::Io)
                    .and_then(|result| result.map_err(Into::into)),
                    Err(error) => Err(error),
                };
                Ok((result,))
            })
        },
    )?;
    add_windows_rename_and_delete(interface, host)
}

#[cfg(windows)]
fn add_windows_rename_and_delete<T: Send + 'static>(
    interface: &mut wasmtime::component::LinkerInstance<'_, T>,
    host: for<'a> fn(&'a mut T) -> &'a mut FsHost,
) -> wasmtime::Result<()> {
    interface.func_wrap_concurrent(
        "[method]descriptor.rename-at",
        move |accessor,
              (descriptor, old_path, new_descriptor, new_path): (
            Resource<Descriptor>,
            String,
            Resource<Descriptor>,
            String,
        )| {
            let directories = accessor.with(|mut access| {
                let host = host(access.data_mut());
                let old = host.writable_directory(&descriptor)?;
                let new = host.writable_directory(&new_descriptor)?;
                if old.perms != new.perms {
                    return Err(types::ErrorCode::NotPermitted);
                }
                Ok((old, new))
            });
            Box::pin(async move {
                let result = match directories {
                    Ok((old, new)) => tokio::task::spawn_blocking(move || {
                        terra_platform::filesystem::rename_at(
                            &old.dir,
                            old_path.as_ref(),
                            &new.dir,
                            new_path.as_ref(),
                        )
                    })
                    .await
                    .map_err(|_| types::ErrorCode::Io)
                    .and_then(|result| result.map_err(Into::into)),
                    Err(error) => Err(error),
                };
                Ok((result,))
            })
        },
    )?;
    interface.func_wrap_concurrent(
        "[method]descriptor.remove-directory-at",
        move |accessor, (descriptor, path): (Resource<Descriptor>, String)| {
            let directory =
                accessor.with(|mut access| host(access.data_mut()).writable_directory(&descriptor));
            Box::pin(async move {
                let result = match directory {
                    Ok(directory) => tokio::task::spawn_blocking(move || {
                        terra_platform::filesystem::remove_directory_at(
                            &directory.dir,
                            path.as_ref(),
                        )
                    })
                    .await
                    .map_err(|_| types::ErrorCode::Io)
                    .and_then(|result| result.map_err(Into::into)),
                    Err(error) => Err(error),
                };
                Ok((result,))
            })
        },
    )?;
    interface.func_wrap_concurrent(
        "[method]descriptor.unlink-file-at",
        move |accessor, (descriptor, path): (Resource<Descriptor>, String)| {
            let directory =
                accessor.with(|mut access| host(access.data_mut()).writable_directory(&descriptor));
            Box::pin(async move {
                let result = match directory {
                    Ok(directory) => tokio::task::spawn_blocking(move || {
                        terra_platform::filesystem::unlink_file_at(&directory.dir, path.as_ref())
                    })
                    .await
                    .map_err(|_| types::ErrorCode::Io)
                    .and_then(|result| result.map_err(Into::into)),
                    Err(error) => Err(error),
                };
                Ok((result,))
            })
        },
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_metadata_open_keeps_its_permit_until_the_blocking_job_finishes() {
        use terra::fs::host::HostWithStore;
        use wasmtime_wasi::p3::bindings::filesystem::preopens::Host;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join("file"), b"metadata").unwrap();
            let grant = ShareGrant::new(&root.path().canonicalize().unwrap(), true).unwrap();
            let mut host = FsHost::with_resource_capacity(
                crate::component::context::DeviceContext::new(4096).unwrap(),
                grant,
                2,
            );
            let parent = host.get_directories().unwrap().remove(0).0;
            let budget = host.descriptor_budget.clone();
            let engine = crate::engine::device_engine().unwrap();
            let mut store = wasmtime::Store::new(&engine, host);
            let (entered, started) = tokio::sync::oneshot::channel();
            let (release, blocked) = std::sync::mpsc::channel();
            let occupied_pool = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                let _ = blocked.recv_timeout(std::time::Duration::from_secs(5));
            });
            started.await.unwrap();
            store
                .run_concurrent(async |accessor| {
                    let accessor = accessor.with_getter::<HasSelf<FsHost>>(|host| host);
                    {
                        let open = HasSelf::<FsHost>::open_metadata_at(
                            &accessor,
                            Resource::new_borrow(parent.rep()),
                            "file".into(),
                        );
                        tokio::pin!(open);
                        assert!(futures_util::poll!(&mut open).is_pending());
                    }
                    assert_eq!(budget.available_permits(), 0);
                    release.send(()).unwrap();
                    occupied_pool.await.unwrap();
                    drop(
                        tokio::time::timeout(std::time::Duration::from_secs(5), budget.acquire())
                            .await
                            .unwrap()
                            .unwrap(),
                    );
                    let opened = HasSelf::<FsHost>::open_metadata_at(
                        &accessor,
                        Resource::new_borrow(parent.rep()),
                        "file".into(),
                    )
                    .await;
                    #[cfg(target_os = "macos")]
                    {
                        use std::assert_matches;
                        assert_matches!(opened, Err(terra::fs::host::Error::Unsupported));
                        assert_eq!(budget.available_permits(), 1);
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        let descriptor = opened.unwrap();
                        assert_eq!(budget.available_permits(), 0);
                        HasSelf::<FsHost>::release_descriptor(&accessor, descriptor)
                            .await
                            .unwrap();
                    }
                })
                .await
                .unwrap();
            drop(
                tokio::time::timeout(std::time::Duration::from_secs(5), budget.acquire())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        });
    }
}
