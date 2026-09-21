use wasmtime_wasi::filesystem::Descriptor;

use super::bindings::wit as terra;

fn map_error(error: terra_platform::filesystem::Error) -> terra::fs::host::Error {
    match error {
        terra_platform::filesystem::Error::Access => terra::fs::host::Error::Access,
        terra_platform::filesystem::Error::Unsupported => terra::fs::host::Error::Unsupported,
        terra_platform::filesystem::Error::Io => terra::fs::host::Error::Io,
    }
}

struct DescriptorFile<'a> {
    file: &'a std::fs::File,
    is_directory: bool,
}

fn descriptor_file(descriptor: &Descriptor) -> DescriptorFile<'_> {
    match descriptor {
        Descriptor::File(file) => DescriptorFile {
            file: &file.file,
            is_directory: false,
        },
        Descriptor::Dir(directory) => DescriptorFile {
            file: &directory.dir,
            is_directory: true,
        },
    }
}

pub(super) fn get_mode_at(
    parent: &Descriptor,
    name: &str,
) -> Result<Option<u32>, terra::fs::host::Error> {
    let Descriptor::Dir(directory) = parent else {
        return Err(terra::fs::host::Error::Access);
    };
    terra_platform::filesystem::mode_at(&directory.dir, name).map_err(map_error)
}

pub(super) fn set_mode_at(
    parent: &Descriptor,
    name: &str,
    mode: u32,
) -> Result<(), terra::fs::host::Error> {
    let Descriptor::Dir(directory) = parent else {
        return Err(terra::fs::host::Error::Access);
    };
    if directory.perms.write_not_permitted() {
        return Err(terra::fs::host::Error::Access);
    }
    terra_platform::filesystem::set_mode_at(&directory.dir, name, mode).map_err(map_error)
}

pub(super) fn open_metadata_file(
    directory: &std::fs::File,
    name: &str,
) -> Result<std::fs::File, terra::fs::host::Error> {
    terra_platform::filesystem::open_metadata_file(directory, name).map_err(map_error)
}

pub(super) fn statfs(
    descriptor: &Descriptor,
) -> Result<terra::fs::host::FilesystemStat, terra::fs::host::Error> {
    let DescriptorFile { file, .. } = descriptor_file(descriptor);
    let terra_platform::filesystem::FilesystemStat {
        blocks,
        blocks_free,
        blocks_available,
        files,
        files_free,
        block_size,
        name_max,
    } = terra_platform::filesystem::stat(file).map_err(map_error)?;
    Ok(terra::fs::host::FilesystemStat {
        blocks,
        blocks_free,
        blocks_available,
        files,
        files_free,
        block_size,
        name_max,
    })
}

pub(super) fn get_mode(descriptor: &Descriptor) -> Result<Option<u32>, terra::fs::host::Error> {
    let DescriptorFile { file, is_directory } = descriptor_file(descriptor);
    terra_platform::filesystem::mode(file, is_directory).map_err(map_error)
}

pub(super) fn set_mode(descriptor: &Descriptor, mode: u32) -> Result<(), terra::fs::host::Error> {
    let DescriptorFile { file, is_directory } = descriptor_file(descriptor);
    terra_platform::filesystem::set_mode(file, is_directory, mode).map_err(map_error)
}
