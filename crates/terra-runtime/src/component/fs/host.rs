#[cfg(unix)]
use std::path::Component;
use std::{io, path::Path};

#[cfg(windows)]
mod windows;

use wasmtime::component::{HasData, HasSelf, Resource};
use wasmtime_wasi::{
    WasiView,
    filesystem::{Descriptor, Dir, FsPerms, OpenMode, WasiFilesystem, WasiFilesystemView},
    p3::bindings::filesystem::{preopens, types},
};

wasmtime::component::bindgen!({
    world: "device",
    path: "../../components/fs/wit",
    with: {
        "terra:host/memory@0.1.0": crate::engine::terra::host::memory,
        "terra:host/interrupt@0.1.0": crate::engine::terra::host::interrupt,
        "wasi:filesystem/types.descriptor": wasmtime_wasi::filesystem::Descriptor,
    },
});

#[derive(Clone)]
pub struct ShareGrant {
    pub readonly: bool,
    directory: Dir,
}

impl ShareGrant {
    pub fn new(root: &Path, readonly: bool) -> io::Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self::from_directory(
                open_directory_without_symlinks(root)?,
                readonly,
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
            Ok(Self::from_directory(directory, readonly))
        }
    }

    fn from_directory(directory: std::fs::File, readonly: bool) -> Self {
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
            directory,
        }
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
        Self { device, grant }
    }

    fn preopen_directory(&self) -> Descriptor {
        Descriptor::Dir(self.grant.directory.clone())
    }

    pub fn set_mode_for_descriptor(
        &mut self,
        descriptor: Resource<Descriptor>,
        mode: u32,
    ) -> Result<(), terra::fs::host::Error> {
        terra::fs::host::Host::set_mode(self, descriptor, mode)
    }

    pub fn mode_for_descriptor(
        &mut self,
        descriptor: Resource<Descriptor>,
    ) -> Result<Option<u32>, terra::fs::host::Error> {
        terra::fs::host::Host::get_mode(self, descriptor)
    }

    pub fn statfs_for_descriptor(
        &mut self,
        descriptor: Resource<Descriptor>,
    ) -> Result<terra::fs::host::FilesystemStat, terra::fs::host::Error> {
        terra::fs::host::Host::statfs(self, descriptor)
    }
}

impl WasiView for FsHost {
    fn ctx(&mut self) -> wasmtime_wasi::WasiCtxView<'_> {
        self.device.ctx()
    }
}

impl terra::fs::host::Host for FsHost {
    fn statfs(
        &mut self,
        descriptor: Resource<types::Descriptor>,
    ) -> Result<terra::fs::host::FilesystemStat, terra::fs::host::Error> {
        #[cfg(unix)]
        {
            let descriptor = self
                .ctx()
                .table
                .get(&descriptor)
                .map_err(|_| terra::fs::host::Error::Access)?;
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
            let descriptor = self
                .ctx()
                .table
                .get(&descriptor)
                .map_err(|_| terra::fs::host::Error::Access)?;
            let file = match descriptor {
                Descriptor::File(file) => &file.file,
                Descriptor::Dir(directory) => &directory.dir,
            };
            windows::statfs(file)
        }
    }

    fn get_mode(
        &mut self,
        descriptor: Resource<types::Descriptor>,
    ) -> Result<Option<u32>, terra::fs::host::Error> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let descriptor = self
                .ctx()
                .table
                .get(&descriptor)
                .map_err(|_| terra::fs::host::Error::Access)?;
            let file = match descriptor {
                Descriptor::File(file) => &file.file,
                Descriptor::Dir(directory) => &directory.dir,
            };
            file.metadata()
                .map(|metadata| Some(metadata.mode()))
                .map_err(|_| terra::fs::host::Error::Io)
        }
        #[cfg(not(unix))]
        {
            let _ = descriptor;
            Ok(None)
        }
    }

    fn set_mode(
        &mut self,
        descriptor: Resource<types::Descriptor>,
        mode: u32,
    ) -> Result<(), terra::fs::host::Error> {
        if self.grant.readonly {
            return Err(terra::fs::host::Error::Access);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let descriptor = self
                .ctx()
                .table
                .get(&descriptor)
                .map_err(|_| terra::fs::host::Error::Access)?;
            let file = match descriptor {
                Descriptor::File(file) => &file.file,
                Descriptor::Dir(directory) => &directory.dir,
            };
            file.set_permissions(std::fs::Permissions::from_mode(mode & 0o0777))
                .map_err(|_| terra::fs::host::Error::Io)
        }
        #[cfg(not(unix))]
        {
            let _ = (descriptor, mode);
            Err(terra::fs::host::Error::Unsupported)
        }
    }
}

struct MountPreopens;

impl HasData for MountPreopens {
    type Data<'a> = &'a mut FsHost;
}

impl preopens::Host for FsHost {
    fn get_directories(&mut self) -> wasmtime::Result<Vec<(Resource<Descriptor>, String)>> {
        let directory = self.preopen_directory();
        Ok(vec![(self.ctx().table.push(directory)?, "/".into())])
    }
}

pub fn fs_component_linker(
    engine: &wasmtime::Engine,
) -> wasmtime::Result<wasmtime::component::Linker<FsHost>> {
    let mut linker = crate::engine::device_component_linker(engine)?;
    types::add_to_linker::<_, WasiFilesystem>(&mut linker, FsHost::filesystem)?;
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
    terra::fs::host::add_to_linker::<T, HasSelf<FsHost>>(&mut linker, host)?;
    linker
        .instance("wasi:filesystem/preopens@0.3.1")?
        .func_wrap("get-directories", move |mut store, (): ()| {
            let directory = host(store.data_mut()).preopen_directory();
            Ok((vec![(
                filesystem(store.data_mut()).table.push(directory)?,
                String::from("/"),
            )],))
        })?;
    crate::engine::add_device_imports(&mut linker, move |store| &mut host(store).device)?;
    Ok(linker)
}
