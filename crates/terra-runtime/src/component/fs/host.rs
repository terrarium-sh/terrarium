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

    fn retire_descriptor(&mut self, representation: u32) -> wasmtime::Result<()> {
        let descriptor = self
            .ctx()
            .table
            .delete(Resource::<Descriptor>::new_own(representation))?;
        let permit = self.descriptor_permits.remove(&representation);
        #[cfg(test)]
        let gate = self.io_gate.clone();
        tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            if let Some(gate) = gate {
                gate.wait_on_descriptor_drop();
            }
            drop(descriptor);
            drop(permit);
        });
        Ok(())
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

    pub fn set_mode_for_descriptor(
        &mut self,
        descriptor: &Resource<Descriptor>,
        mode: u32,
    ) -> Result<(), terra::fs::host::Error> {
        if self.grant.readonly {
            return Err(terra::fs::host::Error::Access);
        }
        set_mode(&self.clone_descriptor(descriptor)?, mode)
    }

    pub fn mode_for_descriptor(
        &mut self,
        descriptor: &Resource<Descriptor>,
    ) -> Result<Option<u32>, terra::fs::host::Error> {
        get_mode(&self.clone_descriptor(descriptor)?)
    }

    pub fn statfs_for_descriptor(
        &mut self,
        descriptor: &Resource<Descriptor>,
    ) -> Result<terra::fs::host::FilesystemStat, terra::fs::host::Error> {
        statfs(&self.clone_descriptor(descriptor)?)
    }
}

impl WasiView for FsHost {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        self.device.ctx()
    }
}

impl<T: Send + 'static> terra::fs::host::HostWithStore<T> for HasSelf<FsHost> {
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
        move |mut store, representation| host(store.data_mut()).retire_descriptor(representation),
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
                        accessor.with(|mut access| {
                            host(access.data_mut())
                                .descriptor_permits
                                .insert(resource.rep(), permit);
                        });
                        Ok((Ok(resource),))
                    }
                    Err(error) => Ok((Err(error.downcast()?),)),
                }
            })
        },
    )?;
    linker.allow_shadowing(false);
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
                        assert!(matches!(opened, Err(terra::fs::host::Error::Unsupported)));
                        assert_eq!(budget.available_permits(), 1);
                    }
                    #[cfg(not(target_os = "macos"))]
                    {
                        let descriptor = opened.unwrap();
                        assert_eq!(budget.available_permits(), 0);
                        accessor.with(|mut access| {
                            access.get().retire_descriptor(descriptor.rep()).unwrap();
                        });
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
