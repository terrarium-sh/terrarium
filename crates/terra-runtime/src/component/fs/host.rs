#[cfg(unix)]
use std::path::Component;
use std::{io, path::Path};

#[cfg(windows)]
mod windows;

use wasmtime::component::{Access, HasSelf, Resource, StreamReader};
use wasmtime_wasi::{
    WasiView,
    filesystem::{Descriptor, Dir, FsPerms, OpenMode, WasiFilesystem},
    p3::bindings::filesystem::{preopens, types},
};

wasmtime::component::bindgen!({
    world: "device",
    path: "../../components/fs/wit",
    exports: { default: async },
    imports: {
 "terra:fs/host.file-events": store | trappable,
 "terra:fs/host.open-metadata-at": async | store,
 "terra:fs/host.set-mode": async | store,
 "terra:fs/host.get-mode": async | store,
 "terra:fs/host.statfs": async | store,
 },
    with: {
        "terra:host/memory@0.1.0": crate::engine::terra::host::memory,
        "terra:host/interrupt@0.1.0": crate::engine::terra::host::interrupt,
        "terra:mmio/types@0.1.0": crate::component::vmm::mmio::terra::mmio::types,
        "wasi:filesystem/types.descriptor": wasmtime_wasi::filesystem::Descriptor,
    },
});

pub(crate) use Device as FsComponent;
pub use terra::mmio::types::DeviceError as FsDeviceError;

#[derive(Clone)]
pub struct ShareGrant {
    pub readonly: bool,
    pub(crate) root: std::path::PathBuf,
    directory: Dir,
    pub(super) watch_budget: std::sync::Arc<tokio::sync::Semaphore>,
    pub(super) event_budget: std::sync::Arc<tokio::sync::Semaphore>,
    #[cfg(test)]
    pub(super) watch_registration: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

impl ShareGrant {
    pub fn new(root: &Path, readonly: bool) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self::from_directory(
                open_directory_without_symlinks(root)?,
                readonly,
                root,
            ))
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS);
            let directory = options.open(root)?;
            if !directory.metadata()?.is_dir() {
                return Err(io::Error::other("mount source must be a directory"));
            }
            if read_final_path(&directory)? != root {
                return Err(io::Error::other("mount source changed while opening it"));
            }
            Ok(Self::from_directory(directory, readonly, root))
        }
    }

    fn from_directory(directory: std::fs::File, readonly: bool, root: &Path) -> Self {
        let directory = Dir::new(
            directory,
            if readonly {
                FsPerms::ReadOnly
            } else {
                FsPerms::ReadWrite
            },
            if readonly {
                OpenMode::READ
            } else {
                OpenMode::READ | OpenMode::WRITE
            },
            false,
        );
        Self {
            readonly,
            root: root.to_path_buf(),
            watch_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(
                super::file_events::MAX_NATIVE_WATCHES,
            )),
            event_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(
                super::file_events::MAX_PENDING_FILE_EVENTS - 2,
            )),
            directory,
            #[cfg(test)]
            watch_registration: None,
        }
    }
}

pub fn share_notification_budgets(shares: &mut [ShareGrant]) {
    // Reserve the stream transfer and worker slots for each share.
    let queued =
        super::file_events::MAX_PENDING_FILE_EVENTS.saturating_sub(shares.len().saturating_mul(2));
    let budget = std::sync::Arc::new(tokio::sync::Semaphore::new(queued));
    let watches = std::sync::Arc::new(tokio::sync::Semaphore::new(
        super::file_events::MAX_NATIVE_WATCHES,
    ));
    for share in shares {
        share.watch_budget = watches.clone();
        share.event_budget = budget.clone();
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn read_final_path(file: &std::fs::File) -> io::Result<std::path::PathBuf> {
    use std::os::{windows::ffi::OsStringExt as _, windows::io::AsRawHandle as _};
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;

    const PATH_CAPACITY: u32 = 32_768;
    let mut path = vec![0; PATH_CAPACITY as usize];
    // SAFETY: `path` is writable for its stated length and `file` stays open.
    let len = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle().cast(),
            path.as_mut_ptr(),
            PATH_CAPACITY,
            0,
        )
    };
    if len == 0 || len >= PATH_CAPACITY {
        return Err(io::Error::last_os_error());
    }
    Ok(std::ffi::OsString::from_wide(&path[..len as usize]).into())
}

#[cfg(unix)]
fn open_directory_without_symlinks(root: &Path) -> io::Result<std::fs::File> {
    use rustix::fs::{Mode, OFlags, openat};

    if !root.is_absolute() {
        return Err(io::Error::other("mount source is not an absolute path"));
    }
    let mut directory = std::fs::File::open("/")?;
    for component in root.components() {
        let Component::Normal(name) = component else {
            if component != Component::RootDir {
                return Err(io::Error::other("mount source is not an absolute path"));
            }
            continue;
        };
        directory = openat(
            &directory,
            name,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(io::Error::from)?
        .into();
    }
    Ok(directory)
}

#[must_use]
pub fn share_tag(index: usize) -> String {
    format!("terra-share-{index}")
}

pub struct FsHost {
    pub device: crate::engine::DeviceContext,
    grant: ShareGrant,
    events: Option<super::file_events::FileEvents>,
    descriptor_budget: std::sync::Arc<tokio::sync::Semaphore>,
    descriptor_permits: std::collections::HashMap<u32, tokio::sync::OwnedSemaphorePermit>,
    #[cfg(test)]
    pub(super) io_gate: Option<std::sync::Arc<super::stalled_io::IoGate>>,
}

impl crate::box_runtime::StoreHost for FsHost {
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
    pub fn new(device: crate::engine::DeviceContext, grant: ShareGrant) -> Self {
        Self::with_resource_capacity(device, grant, 16_384)
    }

    #[must_use]
    pub fn with_resource_capacity(
        mut device: crate::engine::DeviceContext,
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

    fn file_events(
        mut access: Access<'_, T, Self>,
    ) -> wasmtime::Result<StreamReader<terra::fs::host::FileEvent>> {
        let host = access.get();
        let events = host.events.take().unwrap_or_default();
        StreamReader::new(&mut access, events)
    }
}

impl terra::fs::host::Host for FsHost {}

fn open_metadata_file(
    directory: &std::fs::File,
    name: &str,
) -> Result<std::fs::File, terra::fs::host::Error> {
    use terra::fs::host::Error;
    // Only one child may be resolved; separators and stream syntax could escape the granted directory.
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\0']) {
        return Err(Error::Access);
    }
    #[cfg(windows)]
    if name.contains(['\\', ':']) {
        return Err(Error::Access);
    }
    #[cfg(unix)]
    let file = {
        use rustix::fs::{Mode, OFlags, openat};
        #[cfg(target_os = "linux")]
        let flags = OFlags::PATH;
        #[cfg(target_os = "macos")]
        let flags = OFlags::from_bits_retain(libc::O_EVTONLY.cast_unsigned());
        std::fs::File::from(
            openat(
                directory,
                name,
                flags | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::Access)?,
        )
    };
    #[cfg(windows)]
    let file = windows::open_metadata_file(directory, name)?;
    let metadata = file.metadata().map_err(|_| Error::Io)?;
    if !metadata.is_file() && !metadata.is_dir() {
        return Err(Error::Access);
    }
    Ok(file)
}

fn statfs(
    descriptor: &Descriptor,
) -> Result<terra::fs::host::FilesystemStat, terra::fs::host::Error> {
    #[cfg(unix)]
    {
        let stat = match descriptor {
            Descriptor::File(file) => rustix::fs::fstatvfs(&file.file),
            Descriptor::Dir(directory) => rustix::fs::fstatvfs(&directory.dir),
        }
        .map_err(|_| terra::fs::host::Error::Io)?;
        let block_size = if stat.f_frsize == 0 {
            stat.f_bsize
        } else {
            stat.f_frsize
        };
        if block_size == 0 {
            return Err(terra::fs::host::Error::Io);
        }
        Ok(terra::fs::host::FilesystemStat {
            blocks: stat.f_blocks,
            blocks_free: stat.f_bfree,
            blocks_available: stat.f_bavail,
            files: stat.f_files,
            files_free: stat.f_ffree,
            block_size: u32::try_from(block_size).map_err(|_| terra::fs::host::Error::Io)?,
            name_max: u32::try_from(stat.f_namemax).map_err(|_| terra::fs::host::Error::Io)?,
        })
    }
    #[cfg(windows)]
    {
        let file = match descriptor {
            Descriptor::File(file) => &file.file,
            Descriptor::Dir(directory) => &directory.dir,
        };
        windows::statfs(file)
    }
}

fn get_mode(descriptor: &Descriptor) -> Result<Option<u32>, terra::fs::host::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let file = match descriptor {
            Descriptor::File(file) => &file.file,
            Descriptor::Dir(directory) => &directory.dir,
        };
        file.metadata()
            .map(|metadata| Some(metadata.mode()))
            .map_err(|_| terra::fs::host::Error::Io)
    }
    #[cfg(windows)]
    {
        match descriptor {
            Descriptor::Dir(_) => Ok(Some(0o040_755)),
            Descriptor::File(file) => file
                .file
                .metadata()
                .map(|metadata| {
                    Some(if metadata.permissions().readonly() {
                        0o100_555
                    } else {
                        0o100_755
                    })
                })
                .map_err(|_| terra::fs::host::Error::Io),
        }
    }
}

fn set_mode(descriptor: &Descriptor, mode: u32) -> Result<(), terra::fs::host::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let file = match descriptor {
            Descriptor::File(file) => &file.file,
            Descriptor::Dir(directory) => &directory.dir,
        };
        let permissions = std::fs::Permissions::from_mode(mode & 0o0777);
        let result = file.set_permissions(permissions.clone());
        #[cfg(target_os = "linux")]
        if result
            .as_ref()
            .is_err_and(|error| error.raw_os_error() == Some(libc::EBADF))
        {
            use std::os::fd::AsRawFd;
            match rustix::fs::chmodat(
                file,
                "",
                rustix::fs::Mode::from_raw_mode(mode & 0o777),
                rustix::fs::AtFlags::EMPTY_PATH,
            ) {
                Ok(()) => return Ok(()),
                Err(
                    rustix::io::Errno::NOSYS
                    | rustix::io::Errno::INVAL
                    | rustix::io::Errno::OPNOTSUPP,
                ) => {}
                Err(_) => return Err(terra::fs::host::Error::Io),
            }
            // Older Linux kernels need procfs to chmod the retained O_PATH inode, including after unlink.
            return std::fs::set_permissions(
                format!("/proc/self/fd/{}", file.as_raw_fd()),
                permissions,
            )
            .map_err(|_| terra::fs::host::Error::Io);
        }
        result.map_err(|_| terra::fs::host::Error::Io)
    }
    #[cfg(windows)]
    {
        match descriptor {
            Descriptor::File(file) => windows::set_readonly(&file.file, mode & 0o222 == 0),
            Descriptor::Dir(_) if mode & 0o777 == 0o755 => Ok(()),
            Descriptor::Dir(_) => Err(terra::fs::host::Error::Unsupported),
        }
    }
}

impl preopens::Host for FsHost {
    fn get_directories(&mut self) -> wasmtime::Result<Vec<(Resource<Descriptor>, String)>> {
        Ok(vec![(self.grant_directory()?, "/".into())])
    }
}

impl crate::engine::DeviceHost for FsHost {
    fn context(&mut self) -> &mut crate::engine::DeviceContext {
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
    let mut linker = crate::engine::device_component_linker(engine)?;
    types::add_to_linker::<T, WasiFilesystem>(&mut linker, T::filesystem)?;
    add_descriptor_lifecycle(&mut linker, T::filesystem, AsMut::as_mut)?;
    terra::fs::host::add_to_linker::<T, HasSelf<FsHost>>(&mut linker, AsMut::as_mut)?;
    preopens::add_to_linker::<T, HasSelf<FsHost>>(&mut linker, AsMut::as_mut)?;
    crate::engine::add_device_imports(&mut linker, |host: &mut T| &mut host.as_mut().device)?;
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
mod metadata_tests {
    use super::*;
    use std::io::Read;

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
                crate::engine::DeviceContext::new(4096).unwrap(),
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
                    let descriptor = HasSelf::<FsHost>::open_metadata_at(
                        &accessor,
                        Resource::new_borrow(parent.rep()),
                        "file".into(),
                    )
                    .await
                    .unwrap();
                    assert_eq!(budget.available_permits(), 0);
                    accessor.with(|mut access| {
                        access.get().retire_descriptor(descriptor.rep()).unwrap();
                    });
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

    #[test]
    fn metadata_handle_keeps_the_inode_without_granting_content_access() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("original");
        std::fs::write(&original, b"original").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&original, std::fs::Permissions::from_mode(0o000)).unwrap();
        }
        let grant = ShareGrant::new(&root.path().canonicalize().unwrap(), false).unwrap();
        let mut metadata = open_metadata_file(&grant.directory.dir, "original").unwrap();
        assert_eq!(metadata.metadata().unwrap().len(), 8);
        assert!(metadata.read(&mut [0; 1]).is_err());
        let moved = root.path().join("moved");
        std::fs::rename(&original, &moved).unwrap();
        std::fs::write(&original, b"replacement").unwrap();
        let descriptor = Descriptor::File(wasmtime_wasi::filesystem::File::new(
            metadata,
            FsPerms::ReadWrite,
            OpenMode::empty(),
            false,
        ));
        set_mode(&descriptor, 0o600).unwrap();
        assert_eq!(std::fs::read(&moved).unwrap(), b"original");
        assert_eq!(std::fs::read(&original).unwrap(), b"replacement");
        for name in ["", ".", "..", "../original", "original/child", "original\0"] {
            assert!(open_metadata_file(&grant.directory.dir, name).is_err());
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&original, root.path().join("link")).unwrap();
            assert!(open_metadata_file(&grant.directory.dir, "link").is_err());
        }
        #[cfg(windows)]
        for name in ["..\\original", "original:stream"] {
            assert!(open_metadata_file(&grant.directory.dir, name).is_err());
        }
    }
}
