use std::fs::File;
use std::os::windows::io::AsRawHandle as _;
use std::ptr::null_mut;

use windows_sys::Wdk::Storage::FileSystem::{
    FileFsFullSizeInformation, NtQueryVolumeInformationFile,
};
use windows_sys::Wdk::System::SystemServices::FILE_FS_FULL_SIZE_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::terra::fs::host::{Error, FilesystemStat};

#[allow(unsafe_code)]
pub(super) fn statfs(file: &File) -> Result<FilesystemStat, Error> {
    let mut status = IO_STATUS_BLOCK::default();
    let mut size = FILE_FS_FULL_SIZE_INFORMATION::default();
    // SAFETY: WASI opens synchronous handles; both output buffers stay live for the query.
    let result = unsafe {
        NtQueryVolumeInformationFile(
            file.as_raw_handle(),
            &raw mut status,
            (&raw mut size).cast(),
            u32::try_from(size_of_val(&size)).map_err(|_| Error::Io)?,
            FileFsFullSizeInformation,
        )
    };
    if result != 0 || status.Information < size_of_val(&size) {
        return Err(Error::Io);
    }
    let mut name_max = 0;
    // SAFETY: the handle stays open, name_max is writable, and the unused outputs are optional.
    let result = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            &raw mut name_max,
            null_mut(),
            null_mut(),
            0,
        )
    };
    if result == 0 {
        return Err(Error::Io);
    }
    let block_size = size
        .SectorsPerAllocationUnit
        .checked_mul(size.BytesPerSector)
        .filter(|bytes| *bytes != 0)
        .ok_or(Error::Io)?;
    Ok(FilesystemStat {
        blocks: u64::try_from(size.TotalAllocationUnits).map_err(|_| Error::Io)?,
        blocks_free: u64::try_from(size.ActualAvailableAllocationUnits).map_err(|_| Error::Io)?,
        blocks_available: u64::try_from(size.CallerAvailableAllocationUnits)
            .map_err(|_| Error::Io)?,
        // Windows does not report inode capacity; zero denotes undefined statfs fields.
        files: 0,
        files_free: 0,
        block_size,
        name_max,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

    #[test]
    fn file_and_directory_handles_report_the_same_volume_after_rename() {
        let root = tempfile::tempdir().unwrap();
        let file_path = root.path().join("before");
        let file = File::create(&file_path).unwrap();
        std::fs::rename(&file_path, root.path().join("after")).unwrap();
        let directory = File::options()
            .read(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(root.path())
            .unwrap();
        let stat = statfs(&file).unwrap();
        let directory_stat = statfs(&directory).unwrap();
        assert_ne!(stat.blocks, 0);
        assert_ne!(stat.block_size, 0);
        assert_ne!(stat.name_max, 0);
        assert_eq!(stat.blocks, directory_stat.blocks);
        assert_eq!(stat.block_size, directory_stat.block_size);
        assert_eq!(stat.name_max, directory_stat.name_max);
        assert!(stat.blocks_available <= stat.blocks_free);
        assert!(stat.blocks_free <= stat.blocks);
        assert_eq!((stat.files, stat.files_free), (0, 0));
    }
}
