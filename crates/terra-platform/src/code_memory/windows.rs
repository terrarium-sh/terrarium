#![allow(unsafe_code)]

use std::io;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use windows_sys::Win32::Foundation::{GENERIC_EXECUTE, GENERIC_READ, HMODULE};
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};
use windows_sys::Win32::System::Diagnostics::Debug::{IMAGE_FILE_HEADER, IMAGE_SECTION_HEADER};
use windows_sys::Win32::System::LibraryLoader::{
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    GetModuleFileNameW, GetModuleHandleExW,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_EXECUTE, FILE_MAP_READ, MapViewOfFile, PAGE_EXECUTE_READ,
    PAGE_PROTECTION_FLAGS, PAGE_READONLY, UnmapViewOfFile, VirtualProtect,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::SystemServices::IMAGE_DOS_HEADER;

fn system_info() -> SYSTEM_INFO {
    // SAFETY: GetSystemInfo fills every field of the out parameter.
    unsafe {
        let mut info = std::mem::zeroed();
        GetSystemInfo(&raw mut info);
        info
    }
}

#[must_use]
pub fn page_size() -> usize {
    system_info().dwPageSize as usize
}

/// `bytes`, which lie in a loaded module, as a read-only view of that module's file whose pages
/// [`protect_executable`] can make executable; see `file_backed_code_runs_under_control_flow_guard`.
pub fn map_file_backed_code(bytes: &'static [u8]) -> io::Result<&'static [u8]> {
    let module = find_module(bytes.as_ptr())?;
    let offset = find_file_offset(module, bytes)?;
    if !offset.is_multiple_of(page_size() as u64) {
        return Err(io::Error::other(
            "the module's file alignment is below the page size",
        ));
    }
    let file = std::fs::OpenOptions::new()
        .access_mode(GENERIC_READ | GENERIC_EXECUTE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE)
        .open(read_module_path(module)?)?;
    // SAFETY: the file handle is live; null attributes and name create an anonymous mapping.
    let mapping = unsafe {
        CreateFileMappingW(
            file.as_raw_handle(),
            std::ptr::null(),
            PAGE_EXECUTE_READ,
            0,
            0,
            std::ptr::null(),
        )
    };
    if mapping.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileMappingW returned a new owned handle; a view keeps the section alive.
    let mapping = unsafe { OwnedHandle::from_raw_handle(mapping) };
    let view_offset = offset - offset % u64::from(system_info().dwAllocationGranularity);
    let lead = usize::try_from(offset - view_offset).map_err(io::Error::other)?;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "MapViewOfFile takes the offset as two halves"
    )]
    let (offset_high, offset_low) = ((view_offset >> 32) as u32, view_offset as u32);
    // SAFETY: the mapping handle is live and the range lies within the module's file.
    let view = unsafe {
        MapViewOfFile(
            mapping.as_raw_handle(),
            FILE_MAP_READ | FILE_MAP_EXECUTE,
            offset_high,
            offset_low,
            lead + bytes.len(),
        )
    };
    if view.Value.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the view maps `lead + bytes.len()` readable bytes and stays mapped on success.
    let code =
        unsafe { std::slice::from_raw_parts(view.Value.cast::<u8>().add(lead), bytes.len()) };
    // SAFETY: the view is page-aligned memory mapped just above, from which no code runs yet.
    let protected = unsafe { protect(view.Value.cast(), lead + bytes.len(), PAGE_READONLY) };
    // A running image cannot be written, but its file may have been renamed and replaced since.
    let verified = protected.and_then(|()| {
        if code == bytes {
            Ok(code)
        } else {
            Err(io::Error::other(
                "the module's file no longer holds its running code",
            ))
        }
    });
    if verified.is_err() {
        // SAFETY: the view was mapped above and `code`, its only borrow, is discarded.
        unsafe { UnmapViewOfFile(view) };
    }
    verified
}

fn find_module(address: *const u8) -> io::Result<HMODULE> {
    let mut module = std::ptr::null_mut();
    // SAFETY: FROM_ADDRESS treats `address` as a location, and UNCHANGED_REFCOUNT returns a
    // handle that needs no release.
    let found = unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            address.cast(),
            &raw mut module,
        )
    };
    if found == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(module)
    }
}

/// The offset in `module`'s file of the raw section data the loader mapped at `bytes`.
fn find_file_offset(module: HMODULE, bytes: &[u8]) -> io::Result<u64> {
    let base = module.cast::<u8>().cast_const();
    // SAFETY: a loaded module's headers stay mapped at its base while it is loaded.
    let sections = unsafe {
        let dos = base.cast::<IMAGE_DOS_HEADER>().read_unaligned();
        // The file header follows the 4-byte "PE\0\0" signature.
        let file_header = base.offset(dos.e_lfanew as isize + 4);
        let header = file_header.cast::<IMAGE_FILE_HEADER>().read_unaligned();
        let first = file_header
            .add(size_of::<IMAGE_FILE_HEADER>() + usize::from(header.SizeOfOptionalHeader));
        (0..usize::from(header.NumberOfSections))
            .map(|index| {
                first
                    .add(index * size_of::<IMAGE_SECTION_HEADER>())
                    .cast::<IMAGE_SECTION_HEADER>()
                    .read_unaligned()
            })
            .collect::<Vec<_>>()
    };
    let rva = bytes.as_ptr().addr() - base.addr();
    sections
        .iter()
        .find_map(|section| {
            let start = section.VirtualAddress as usize;
            (rva >= start && rva + bytes.len() <= start + section.SizeOfRawData as usize)
                .then(|| (rva - start + section.PointerToRawData as usize) as u64)
        })
        .ok_or_else(|| io::Error::other("the bytes are not raw data of their module"))
}

fn read_module_path(module: HMODULE) -> io::Result<std::path::PathBuf> {
    use std::os::windows::ffi::OsStringExt as _;

    let mut path = vec![0_u16; 32_768];
    let capacity = u32::try_from(path.len()).map_err(io::Error::other)?;
    // SAFETY: the module handle is live and the buffer is writable for its full length.
    let length = unsafe { GetModuleFileNameW(module, path.as_mut_ptr(), capacity) } as usize;
    if length == 0 || length >= path.len() {
        return Err(io::Error::last_os_error());
    }
    Ok(std::ffi::OsString::from_wide(&path[..length]).into())
}

/// # Safety
///
/// `ptr..ptr + len` must be page-aligned committed memory that nothing writes
/// while it is executable.
pub unsafe fn protect_executable(ptr: *const u8, len: usize) -> io::Result<()> {
    // SAFETY: the caller upholds the alignment and no-writer contract.
    unsafe { protect(ptr, len, PAGE_EXECUTE_READ) }
}

/// # Safety
///
/// `ptr..ptr + len` must be page-aligned committed memory from which no code runs.
pub unsafe fn protect_read_only(ptr: *const u8, len: usize) -> io::Result<()> {
    // SAFETY: the caller guarantees nothing executes from the range.
    unsafe { protect(ptr, len, PAGE_READONLY) }
}

unsafe fn protect(ptr: *const u8, len: usize, protection: PAGE_PROTECTION_FLAGS) -> io::Result<()> {
    let mut previous = 0;
    // SAFETY: the callers' contracts make the range a valid VirtualProtect target.
    if unsafe { VirtualProtect(ptr.cast(), len, protection, &raw mut previous) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_memory::PageAligned;

    static RETURN_42: PageAligned<[u8; 4096]> = PageAligned({
        let instructions: &[u8] = if cfg!(target_arch = "aarch64") {
            // mov w0, #42; ret
            &[0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6]
        } else {
            // mov eax, 42; ret
            &[0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3]
        };
        let mut page = [0; 4096];
        let mut index = 0;
        while index < instructions.len() {
            page[index] = instructions[index];
            index += 1;
        }
        page
    });

    /// Windows builds enforce Control Flow Guard, which kills the process on a
    /// call into its own image pages made executable at runtime: those keep the
    /// image's guard table. The same bytes mapped from the module's file run, so
    /// embedded code can still share the file's page-cache pages across processes.
    #[test]
    fn file_backed_code_runs_under_control_flow_guard() {
        use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let code = map_file_backed_code(&RETURN_42.0).unwrap();
        assert_eq!(code, &RETURN_42.0[..]);
        assert_ne!(code.as_ptr(), RETURN_42.0.as_ptr());
        // SAFETY: the view is page-aligned, nothing writes it, and it holds a whole function.
        let returned = unsafe {
            protect_executable(code.as_ptr(), code.len()).unwrap();
            FlushInstructionCache(GetCurrentProcess(), code.as_ptr().cast(), code.len());
            let run: extern "C" fn() -> i32 = std::mem::transmute(code.as_ptr());
            std::hint::black_box(run)()
        };
        assert_eq!(returned, 42);
    }
}
