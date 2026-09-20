#[cfg(unix)]
use std::path::Component;
use std::{io, path::Path};

#[cfg(windows)]
mod windows;

use wasmtime::component::{Access, HasData, HasSelf, Resource, StreamReader};
use wasmtime_wasi::{
    WasiView,
    filesystem::{Descriptor, Dir, FsPerms, OpenMode, WasiFilesystem, WasiFilesystemView},
    p3::bindings::filesystem::{preopens, types},
};

wasmtime::component::bindgen!({
    world: "device",
    path: "../../components/fs/wit",
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
        "wasi:filesystem/types.descriptor": wasmtime_wasi::filesystem::Descriptor,
    },
});

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
            event_budget: std::sync::Arc::new(tokio::sync::Semaphore::new(4096 - 2)),
            directory,
            #[cfg(test)]
            watch_registration: None,
        }
    }
}

pub fn share_notification_budgets(shares: &mut [ShareGrant]) {
    // Reserve the stream transfer and worker slots for each share.
    let queued = 4096_usize.saturating_sub(shares.len().saturating_mul(2));
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
    pub device: crate::engine::DeviceHost,
    grant: ShareGrant,
    events: Option<super::file_events::FileEvents>,
    descriptor_budget: std::sync::Arc<tokio::sync::Semaphore>,
    descriptor_permits: std::collections::HashMap<u32, tokio::sync::OwnedSemaphorePermit>,
    #[cfg(test)]
    pub(super) io_gate: Option<std::sync::Arc<super::stalled_io::IoGate>>,
}

impl FsHost {
    #[must_use]
    pub fn new(device: crate::engine::DeviceHost, grant: ShareGrant) -> Self {
        Self::with_resource_capacity(device, grant, 16_384)
    }

    #[must_use]
    pub fn with_resource_capacity(
        mut device: crate::engine::DeviceHost,
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
        let descriptor = tokio::task::spawn_blocking(move || {
            let file = open_metadata_file(&directory.dir, &name)?;
            if file.metadata().map_err(|_| Error::Io)?.is_dir() {
                Ok(Descriptor::Dir(Dir::new(
                    file,
                    directory.perms,
                    OpenMode::empty(),
                    false,
                )))
            } else {
                Ok(Descriptor::File(wasmtime_wasi::filesystem::File::new(
                    file,
                    directory.perms,
                    OpenMode::empty(),
                    false,
                )))
            }
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

struct MountPreopens;

impl HasData for MountPreopens {
    type Data<'a> = &'a mut FsHost;
}

impl preopens::Host for FsHost {
    fn get_directories(&mut self) -> wasmtime::Result<Vec<(Resource<Descriptor>, String)>> {
        Ok(vec![(self.grant_directory()?, "/".into())])
    }
}

pub fn fs_component_linker(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<FsHost>> {
    let mut linker = crate::engine::device_component_linker(engine)?;
    types::add_to_linker::<_, WasiFilesystem>(&mut linker, FsHost::filesystem)?;
    add_descriptor_lifecycle(&mut linker, FsHost::filesystem, |host| host)?;
    terra::fs::host::add_to_linker::<FsHost, HasSelf<FsHost>>(&mut linker, |host| host)?;
    preopens::add_to_linker::<_, MountPreopens>(&mut linker, |host| host)?;
    crate::engine::terra::host::memory::add_to_linker::<FsHost, crate::engine::TerraHost>(
        &mut linker,
        |host| &mut host.device,
    )?;
    crate::engine::terra::host::interrupt::add_to_linker::<FsHost, crate::engine::TerraHost>(
        &mut linker,
        |host| &mut host.device,
    )?;
    Ok(linker)
}

pub fn fs_component_linker_with<T>(
    engine: &wasmtime::Engine,
    wasi: crate::engine::DeviceWasiGetters<T>,
    filesystem: for<'a> fn(&'a mut T) -> wasmtime_wasi::filesystem::WasiFilesystemCtxView<'a>,
    host: for<'a> fn(&'a mut T) -> &'a mut FsHost,
) -> wasmtime::Result<wasmtime::component::Linker<T>>
where
    T: Send + 'static,
{
    let mut linker = crate::engine::device_component_linker_with_wasi(engine, wasi)?;
    types::add_to_linker::<T, WasiFilesystem>(&mut linker, filesystem)?;
    add_descriptor_lifecycle(&mut linker, filesystem, host)?;
    terra::fs::host::add_to_linker::<T, HasSelf<FsHost>>(&mut linker, host)?;
    linker
        .instance("wasi:filesystem/preopens@0.3.1")?
        .func_wrap("get-directories", move |mut store, (): ()| {
            Ok((vec![(
                host(store.data_mut()).grant_directory()?,
                String::from("/"),
            )],))
        })?;
    crate::engine::add_device_imports(&mut linker, move |store| &mut host(store).device)?;
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
