use super::api::{self, LocalAllocation, Profile};
use anyhow::{Context, Result, ensure};
use std::fs::File;
use std::io::ErrorKind;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use windows_sys::Win32::Foundation::{WAIT_ABANDONED_0, WAIT_OBJECT_0};
use windows_sys::Win32::Security::Authorization::{
    BuildTrusteeWithSidW, ConvertSidToStringSidW, DENY_ACCESS, EXPLICIT_ACCESS_W, GRANT_ACCESS,
    GetSecurityInfo, SE_FILE_OBJECT, SetEntriesInAclW,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, DeleteAce, EqualSid, GetAce,
    GetAclInformation, GetSecurityDescriptorControl, INHERITED_ACE, InitializeSecurityDescriptor,
    OBJECT_INHERIT_ACE, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED, SE_DACL_PROTECTED,
    SECURITY_DESCRIPTOR, SetKernelObjectSecurity, SetSecurityDescriptorControl,
    SetSecurityDescriptorDacl, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_APPEND_DATA, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_EXECUTE,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA, FILE_WRITE_EA, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SECURITY_DESCRIPTOR_REVISION,
    SID_MAX_SUB_AUTHORITIES, SID_REVISION,
};
use windows_sys::Win32::System::Threading::{CreateMutexW, ReleaseMutex, WaitForSingleObject};

pub(super) const MAX_GRANTED_OBJECTS: usize = 16_384;
const READONLY_DENY: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER;

pub(super) struct Grants<'a> {
    profile: &'a Profile,
    objects: Vec<GrantedObject>,
    roots: Vec<PathBuf>,
}

struct GrantedObject {
    file: File,
    restore_dacl_protection: Option<bool>,
    inherited_aces: Vec<Vec<u8>>,
}

impl<'a> Grants<'a> {
    pub(super) const fn new(profile: &'a Profile) -> Self {
        Self {
            profile,
            objects: Vec::new(),
            roots: Vec::new(),
        }
    }

    pub(super) fn add(&mut self, path: &Path, writable: bool) -> Result<()> {
        let path = std::fs::canonicalize(path)
            .with_context(|| format!("resolving Windows sandbox grant {}", path.display()))?;
        self.roots.push(path.clone());
        let _lock = AclLock::acquire()?;
        for path in walk_objects(&path, false)? {
            ensure!(
                self.objects.len() < MAX_GRANTED_OBJECTS,
                "Windows sandbox exceeds {MAX_GRANTED_OBJECTS} filesystem grants"
            );
            let object = open_security_object(&path)?;
            let directory = object.metadata()?.is_dir();
            let inheritance = if directory {
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
            } else {
                0
            };
            let mut allow = EXPLICIT_ACCESS_W {
                grfAccessPermissions: FILE_GENERIC_READ
                    | FILE_GENERIC_EXECUTE
                    | if writable {
                        FILE_GENERIC_WRITE | DELETE
                    } else {
                        0
                    },
                grfAccessMode: GRANT_ACCESS,
                grfInheritance: inheritance,
                ..EXPLICIT_ACCESS_W::default()
            };
            // SAFETY: profile SID remains live for all grant and cleanup operations.
            unsafe {
                BuildTrusteeWithSidW(&raw mut allow.Trustee, self.profile.sid);
            }
            let mut entries = vec![allow];
            if !writable {
                entries.push(EXPLICIT_ACCESS_W {
                    grfAccessPermissions: READONLY_DENY,
                    grfAccessMode: DENY_ACCESS,
                    grfInheritance: inheritance,
                    Trustee: allow.Trustee,
                });
            }
            let (acl, descriptor) = read_acl(&object)?;
            let was_dacl_protected = is_dacl_protected(&descriptor)?;
            remove_profile_aces_from_acl(acl, self.profile)?;
            let inherited_aces = if !writable && !was_dacl_protected {
                collect_inherited_aces(acl)?
            } else {
                Vec::new()
            };
            let mut updated = std::ptr::null_mut();
            // SAFETY: old ACL, SID, and entry array stay live; updated receives the owned ACL allocation.
            win_error(unsafe {
                SetEntriesInAclW(
                    u32::try_from(entries.len())?,
                    entries.as_ptr(),
                    acl,
                    &raw mut updated,
                )
            })?;
            let updated_owner = LocalAllocation(updated.cast());
            write_acl(
                &object,
                updated,
                &descriptor,
                !writable || was_dacl_protected,
            )?;
            drop(updated_owner);
            self.objects.push(GrantedObject {
                file: object,
                restore_dacl_protection: (!writable && !was_dacl_protected).then_some(false),
                inherited_aces,
            });
        }
        Ok(())
    }

    pub(super) fn clear(&mut self) -> Result<()> {
        let _lock = AclLock::acquire()?;
        let mut first_error = None;
        for object in self.objects.drain(..).rev() {
            if let Err(error) = remove_profile_aces(
                &object.file,
                self.profile,
                object.restore_dacl_protection,
                &object.inherited_aces,
            ) {
                first_error.get_or_insert(error);
            }
        }
        for root in self.roots.drain(..) {
            let result = walk_objects(&root, true)
                .and_then(|paths| remove_grants_from_paths(&paths, self.profile));
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for Grants<'_> {
    fn drop(&mut self) {
        if (!self.objects.is_empty() || !self.roots.is_empty())
            && let Err(error) = self.clear()
        {
            log::warn!("removing Windows sandbox file grants failed: {error:#}");
        }
    }
}

/// Cleanup skips deleted entries when `skip_missing` is true.
fn walk_objects(root: &Path, skip_missing: bool) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if skip_missing && error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            continue;
        }
        ensure!(
            paths.len() + pending.len() < MAX_GRANTED_OBJECTS,
            "Windows sandbox filesystem grant exceeds {MAX_GRANTED_OBJECTS} objects"
        );
        if metadata.is_dir() {
            let entries = match std::fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(error) if skip_missing && error.kind() == ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            };
            for entry in entries {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(error) if skip_missing && error.kind() == ErrorKind::NotFound => {
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };
                ensure!(
                    paths.len() + pending.len() < MAX_GRANTED_OBJECTS,
                    "Windows sandbox filesystem grant exceeds {MAX_GRANTED_OBJECTS} objects"
                );
                pending.push(entry.path());
            }
        }
        paths.push(path);
    }
    Ok(paths)
}

fn remove_grants_from_paths(paths: &[PathBuf], profile: &Profile) -> Result<()> {
    for path in paths {
        let object = match open_security_object(path) {
            Ok(object) => object,
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|error| error.kind() == ErrorKind::NotFound) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        remove_profile_aces(&object, profile, None, &[])?;
    }
    Ok(())
}

fn open_security_object(path: &Path) -> Result<File> {
    let object = std::fs::OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .with_context(|| format!("opening Windows sandbox grant {}", path.display()))?;
    ensure!(
        object.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "Windows sandbox grant cannot target a reparse point: {}",
        path.display()
    );
    Ok(object)
}

fn read_acl(object: &File) -> Result<(*mut ACL, LocalAllocation)> {
    let mut acl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: the handle is live and the initialized DACL is retained through the returned descriptor owner.
    win_error(unsafe {
        GetSecurityInfo(
            object.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut acl,
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    })?;
    let descriptor = LocalAllocation(descriptor);
    ensure!(
        !acl.is_null(),
        "Windows sandbox filesystem grants require a non-null DACL"
    );
    Ok((acl, descriptor))
}

fn read_descriptor_control(descriptor: &LocalAllocation) -> Result<u16> {
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: read_acl returns a live security descriptor owned by descriptor.
    api::win_ok(unsafe {
        GetSecurityDescriptorControl(descriptor.0, &raw mut control, &raw mut revision)
    })?;
    Ok(control)
}

fn is_dacl_protected(descriptor: &LocalAllocation) -> Result<bool> {
    Ok(read_descriptor_control(descriptor)? & SE_DACL_PROTECTED != 0)
}

fn write_acl(
    object: &File,
    acl: *mut ACL,
    original_descriptor: &LocalAllocation,
    dacl_protected: bool,
) -> Result<()> {
    let original_control = read_descriptor_control(original_descriptor)?;
    let auto_inherited = original_control & SE_DACL_AUTO_INHERITED;
    let mut descriptor = SECURITY_DESCRIPTOR::default();
    let descriptor_pointer = (&raw mut descriptor).cast();
    // SAFETY: descriptor is correctly sized; acl remains owned by the caller throughout the write.
    unsafe {
        api::win_ok(InitializeSecurityDescriptor(
            descriptor_pointer,
            SECURITY_DESCRIPTOR_REVISION,
        ))?;
        api::win_ok(SetSecurityDescriptorDacl(descriptor_pointer, 1, acl, 0))?;
        api::win_ok(SetSecurityDescriptorControl(
            descriptor_pointer,
            SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED | SE_DACL_AUTO_INHERIT_REQ,
            auto_inherited
                | if auto_inherited != 0 {
                    SE_DACL_AUTO_INHERIT_REQ
                } else {
                    0
                }
                | if dacl_protected { SE_DACL_PROTECTED } else { 0 },
        ))?;
        // SetSecurityInfo rewrites inheritance and can propagate through guest-created reparse points.
        // Our explicit walk owns propagation; this write changes only the retained object.
        if !dacl_protected && original_control & SE_DACL_PROTECTED == 0 {
            // An unprotected-to-unprotected update would retain inherited ACEs we removed.
            api::win_ok(SetSecurityDescriptorControl(
                descriptor_pointer,
                SE_DACL_PROTECTED,
                SE_DACL_PROTECTED,
            ))?;
            api::win_ok(SetKernelObjectSecurity(
                object.as_raw_handle(),
                DACL_SECURITY_INFORMATION,
                descriptor_pointer,
            ))?;
            api::win_ok(SetSecurityDescriptorControl(
                descriptor_pointer,
                SE_DACL_PROTECTED,
                0,
            ))?;
        }
        api::win_ok(SetKernelObjectSecurity(
            object.as_raw_handle(),
            DACL_SECURITY_INFORMATION,
            descriptor_pointer,
        ))
    }
}

fn count_acl_entries(acl: *const ACL) -> Result<u32> {
    Ok(read_acl_information(acl)?.AceCount)
}

fn read_acl_information(acl: *const ACL) -> Result<ACL_SIZE_INFORMATION> {
    ensure!(!acl.is_null(), "Windows returned a null ACL");
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: callers retain the descriptor returned by read_acl; information matches the requested class and size.
    api::win_ok(unsafe {
        GetAclInformation(
            acl,
            (&raw mut information).cast(),
            u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>())?,
            AclSizeInformation,
        )
    })?;
    Ok(information)
}

fn read_acl_entry(acl: *mut ACL, index: u32) -> Result<(usize, Vec<u8>)> {
    let information = read_acl_information(acl)?;
    ensure!(
        index < information.AceCount,
        "Windows ACL entry index is out of bounds"
    );
    let used_bytes = usize::try_from(information.AclBytesInUse)?;
    ensure!(
        (std::mem::size_of::<ACL>()..=usize::from(u16::MAX)).contains(&used_bytes),
        "Windows returned an invalid ACL byte length"
    );
    let mut entry = std::ptr::null_mut();
    // SAFETY: the checked index belongs to the live ACL retained by the caller.
    api::win_ok(unsafe { GetAce(acl, index, &raw mut entry) })?;
    ensure!(!entry.is_null(), "Windows returned a null ACL entry");
    let offset = entry
        .addr()
        .checked_sub(acl.addr())
        .context("Windows returned an ACL entry outside its ACL")?;
    // SAFETY: GetAclInformation supplies the initialized length of the caller's live ACL allocation.
    let acl_bytes = unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), used_bytes) };
    let range = validate_acl_entry_range(acl_bytes, offset)?;
    Ok((offset, acl_bytes[range].to_vec()))
}

fn validate_acl_entry_range(acl_bytes: &[u8], offset: usize) -> Result<std::ops::Range<usize>> {
    ensure!(
        offset >= std::mem::size_of::<ACL>()
            && offset.is_multiple_of(std::mem::align_of::<ACCESS_ALLOWED_ACE>()),
        "Windows returned an invalid ACL entry offset"
    );
    let header = acl_bytes
        .get(offset..)
        .and_then(|bytes| bytes.get(..std::mem::size_of::<ACE_HEADER>()))
        .context("Windows returned a truncated ACL entry header")?;
    let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
    ensure!(
        size >= header.len(),
        "Windows returned a truncated ACL entry"
    );
    let end = offset
        .checked_add(size)
        .context("Windows ACL entry length overflowed")?;
    ensure!(
        end <= acl_bytes.len(),
        "Windows returned an ACL entry outside its ACL"
    );
    Ok(offset..end)
}

fn remove_profile_aces(
    object: &File,
    profile: &Profile,
    dacl_protected: Option<bool>,
    inherited_aces: &[Vec<u8>],
) -> Result<()> {
    let (acl, descriptor) = read_acl(object)?;
    let changed = remove_profile_aces_from_acl(acl, profile)?;
    if dacl_protected == Some(false) {
        restore_converted_inherited_aces(acl, inherited_aces)?;
    }
    if changed || dacl_protected.is_some() {
        write_acl(
            object,
            acl,
            &descriptor,
            dacl_protected.unwrap_or(is_dacl_protected(&descriptor)?),
        )?;
    }
    Ok(())
}

fn remove_profile_aces_from_acl(acl: *mut ACL, profile: &Profile) -> Result<bool> {
    let count = count_acl_entries(acl)?;
    let mut changed = false;
    for index in (0..count).rev() {
        let (offset, bytes) = read_acl_entry(acl, index)?;
        if [ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE].contains(&u32::from(bytes[0])) {
            let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
            let sid_bytes = bytes
                .get(sid_offset..)
                .filter(|sid| sid.len() >= 8)
                .context("Windows returned a truncated ACL entry SID")?;
            ensure!(
                u32::from(sid_bytes[0]) == SID_REVISION
                    && u32::from(sid_bytes[1]) <= SID_MAX_SUB_AUTHORITIES
                    && sid_bytes.len() >= 8 + 4 * usize::from(sid_bytes[1]),
                "Windows returned an invalid ACL entry SID"
            );
            // SAFETY: the checked ACL offset contains a complete aligned SID; the profile SID remains live.
            if unsafe {
                EqualSid(
                    acl.cast::<u8>().add(offset + sid_offset).cast(),
                    profile.sid,
                )
            } != 0
            {
                // SAFETY: the current ACE index is valid and ACL memory is mutable API-owned storage.
                api::win_ok(unsafe { DeleteAce(acl, index) })?;
                changed = true;
            }
        }
    }
    Ok(changed)
}

fn collect_inherited_aces(acl: *mut ACL) -> Result<Vec<Vec<u8>>> {
    let mut inherited = Vec::new();
    for index in 0..count_acl_entries(acl)? {
        let (_offset, mut bytes) = read_acl_entry(acl, index)?;
        if u32::from(bytes[1]) & INHERITED_ACE != 0 {
            bytes[1] &= !u8::try_from(INHERITED_ACE)?;
            inherited.push(bytes);
        }
    }
    Ok(inherited)
}

fn restore_converted_inherited_aces(acl: *mut ACL, inherited_aces: &[Vec<u8>]) -> Result<()> {
    for inherited_ace in inherited_aces {
        for index in (0..count_acl_entries(acl)?).rev() {
            let (offset, bytes) = read_acl_entry(acl, index)?;
            if u32::from(bytes[1]) & INHERITED_ACE == 0 && bytes == *inherited_ace {
                // SAFETY: the validated entry range includes its flags byte in mutable live ACL storage.
                unsafe {
                    acl.cast::<u8>()
                        .add(offset + 1)
                        .write(bytes[1] | u8::try_from(INHERITED_ACE)?);
                }
                break;
            }
        }
    }
    Ok(())
}

struct AclLock(OwnedHandle);

impl AclLock {
    fn acquire() -> Result<Self> {
        let token = api::open_current_token(TOKEN_QUERY)?;
        let information = api::token_information(&token, TokenUser)?;
        // SAFETY: TokenUser initialized this pointer-aligned structure and its embedded SID.
        let sid = unsafe { (*information.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let mut text = std::ptr::null_mut();
        // SAFETY: the user SID remains live and text receives a LocalFree-owned NUL-terminated string.
        api::win_ok(unsafe { ConvertSidToStringSidW(sid, &raw mut text) })?;
        let text_owner = LocalAllocation(text.cast());
        let mut name: Vec<u16> = "Local\\terra-sandbox-acl-".encode_utf16().collect();
        let mut offset = 0;
        loop {
            // SAFETY: ConvertSidToStringSidW returned a NUL-terminated allocation retained above.
            let character = unsafe { *text.add(offset) };
            if character == 0 {
                break;
            }
            name.push(character);
            offset += 1;
        }
        name.push(0);
        drop(text_owner);
        // SAFETY: the user-specific name is NUL-terminated; default security prevents workers acquiring the lock.
        let handle = api::own_handle(unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) })?;
        // SAFETY: handle names a live mutex; the finite wait bounds launch and cleanup delays.
        let status = unsafe { WaitForSingleObject(handle.as_raw_handle(), 10_000) };
        ensure!(
            [WAIT_OBJECT_0, WAIT_ABANDONED_0].contains(&status),
            "waiting for Windows sandbox ACL lock failed or timed out"
        );
        Ok(Self(handle))
    }
}

impl Drop for AclLock {
    fn drop(&mut self) {
        // SAFETY: the successful wait acquired this mutex on the current thread.
        unsafe {
            ReleaseMutex(self.0.as_raw_handle());
        }
    }
}

fn win_error(error: u32) -> Result<()> {
    ensure!(
        error == 0,
        "{}",
        std::io::Error::from_raw_os_error(i32::try_from(error)?)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Role;

    #[test]
    fn only_cleanup_walks_skip_deleted_paths() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let missing = directory.path().join("deleted");
        assert_eq!(
            walk_objects(&missing, false)
                .unwrap_err()
                .downcast_ref::<std::io::Error>()
                .unwrap()
                .kind(),
            ErrorKind::NotFound
        );
        assert!(walk_objects(&missing, true)?.is_empty());
        Ok(())
    }

    fn count_file_acl_entries(path: &Path) -> Result<u32> {
        let object = open_security_object(path)?;
        let (acl, _descriptor) = read_acl(&object)?;
        count_acl_entries(acl)
    }

    fn file_dacl_protected(path: &Path) -> Result<bool> {
        let object = open_security_object(path)?;
        let (_acl, descriptor) = read_acl(&object)?;
        is_dacl_protected(&descriptor)
    }

    fn read_file_dacl_control(path: &Path) -> Result<u16> {
        let object = open_security_object(path)?;
        let (_acl, descriptor) = read_acl(&object)?;
        Ok(read_descriptor_control(&descriptor)? & (SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED))
    }

    fn read_file_acl_entries(path: &Path) -> Result<Vec<Vec<u8>>> {
        let object = open_security_object(path)?;
        let (acl, _descriptor) = read_acl(&object)?;
        let mut entries = Vec::new();
        for index in 0..count_acl_entries(acl)? {
            let (_offset, bytes) = read_acl_entry(acl, index)?;
            entries.push(bytes);
        }
        entries.sort_unstable();
        Ok(entries)
    }

    #[test]
    fn acl_entry_ranges_reject_truncated_and_out_of_bounds_bytes() -> Result<()> {
        let mut bytes = [0_u8; 12];
        bytes[10..12].copy_from_slice(&4_u16.to_le_bytes());
        assert_eq!(validate_acl_entry_range(&bytes, 8)?, 8..12);
        assert!(validate_acl_entry_range(&bytes[..11], 8).is_err());
        assert!(validate_acl_entry_range(&bytes, 0).is_err());
        assert!(validate_acl_entry_range(&bytes, 9).is_err());
        assert!(validate_acl_entry_range(&bytes, usize::MAX).is_err());
        for size in [3_u16, 8] {
            bytes[10..12].copy_from_slice(&size.to_le_bytes());
            assert!(validate_acl_entry_range(&bytes, 8).is_err());
        }
        Ok(())
    }

    /// Writable grants preserve existing ACEs and inheritance modes through handle and path cleanup.
    #[test]
    fn writable_grants_restore_inherited_and_protected_dacls() -> Result<()> {
        for cleanup_by_paths in [false, true] {
            let directory = tempfile::tempdir()?;
            let inherited = directory.path().join("inherited");
            let protected = directory.path().join("protected");
            std::fs::write(&inherited, b"inherited")?;
            std::fs::write(&protected, b"protected")?;
            let protected_object = open_security_object(&protected)?;
            let (acl, descriptor) = read_acl(&protected_object)?;
            write_acl(&protected_object, acl, &descriptor, true)?;
            let paths = [directory.path(), inherited.as_path(), protected.as_path()];
            let original_acls = paths
                .iter()
                .map(|path| Ok((read_file_acl_entries(path)?, read_file_dacl_control(path)?)))
                .collect::<Result<Vec<_>>>()?;

            let profile = Profile::create(Role::Vm)?;
            let mut grants = Grants::new(&profile);
            grants.add(directory.path(), true)?;
            for (path, (_, original_control)) in paths.iter().zip(&original_acls) {
                assert_eq!(
                    read_file_dacl_control(path)?,
                    *original_control,
                    "{}",
                    path.display()
                );
            }
            if cleanup_by_paths {
                grants.objects.clear();
            }
            grants.clear()?;

            for (path, (original_entries, original_control)) in paths.iter().zip(original_acls) {
                assert_eq!(
                    read_file_acl_entries(path)?,
                    original_entries,
                    "{}",
                    path.display()
                );
                assert_eq!(read_file_dacl_control(path)?, original_control);
            }
        }
        Ok(())
    }

    /// Parent writes leave children untouched; the cleanup walk also revokes newly inherited grants.
    #[test]
    fn cleanup_explicitly_revokes_grants_inherited_after_launch() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let baseline = directory.path().join("baseline");
        std::fs::write(&baseline, b"baseline")?;
        let original_entries = read_file_acl_entries(&baseline)?;
        let profile = Profile::create(Role::Vm)?;
        let mut grants = Grants::new(&profile);
        grants.add(directory.path(), true)?;
        let child = directory.path().join("created-by-worker");
        std::fs::write(&child, b"child")?;
        let granted_entries = read_file_acl_entries(&child)?;
        assert!(granted_entries.len() > original_entries.len());

        let root = open_security_object(directory.path())?;
        remove_profile_aces(&root, &profile, None, &[])?;
        assert_eq!(read_file_acl_entries(&child)?, granted_entries);
        grants.clear()?;
        assert_eq!(read_file_acl_entries(&child)?, original_entries);
        Ok(())
    }

    #[test]
    fn readonly_child_grants_restore_inherited_and_protected_dacls() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let inherited = directory.path().join("inherited");
        let protected = directory.path().join("protected");
        std::fs::write(&inherited, b"inherited")?;
        std::fs::write(&protected, b"protected")?;
        let inherited_object = open_security_object(&inherited)?;
        let protected_object = open_security_object(&protected)?;
        let (inherited_acl, descriptor) = read_acl(&inherited_object)?;
        write_acl(&inherited_object, inherited_acl, &descriptor, false)?;
        let (protected_acl, descriptor) = read_acl(&protected_object)?;
        write_acl(&protected_object, protected_acl, &descriptor, true)?;
        let inherited_entries = read_file_acl_entries(&inherited)?;
        let protected_entries = read_file_acl_entries(&protected)?;

        let profile = Profile::create(Role::Vm)?;
        let mut grants = Grants::new(&profile);
        grants.add(directory.path(), true)?;
        grants.add(&inherited, false)?;
        grants.add(&protected, false)?;
        assert!(file_dacl_protected(&inherited)?);
        assert!(file_dacl_protected(&protected)?);

        grants.clear()?;
        assert!(!file_dacl_protected(&inherited)?);
        assert!(file_dacl_protected(&protected)?);
        assert_eq!(read_file_acl_entries(&inherited)?, inherited_entries);
        assert_eq!(read_file_acl_entries(&protected)?, protected_entries);
        Ok(())
    }

    /// Overlapping workers must not restore another worker's temporary protection on a shared executable.
    #[test]
    fn overlapping_readonly_grants_restore_inheritance_in_either_exit_order() -> Result<()> {
        for first_exits_first in [true, false] {
            let file = tempfile::NamedTempFile::new()?;
            let object = open_security_object(file.path())?;
            let (acl, descriptor) = read_acl(&object)?;
            write_acl(&object, acl, &descriptor, false)?;
            let original_entries = read_file_acl_entries(file.path())?;
            let first_profile = Profile::create(Role::Vm)?;
            let second_profile = Profile::create(Role::Vm)?;
            let mut first_grants = Grants::new(&first_profile);
            let mut second_grants = Grants::new(&second_profile);
            first_grants.add(file.path(), false)?;
            second_grants.add(file.path(), false)?;
            if first_exits_first {
                first_grants.clear()?;
                second_grants.clear()?;
            } else {
                second_grants.clear()?;
                first_grants.clear()?;
            }
            assert!(!file_dacl_protected(file.path())?);
            assert_eq!(read_file_acl_entries(file.path())?, original_entries);
        }
        Ok(())
    }

    /// A file can disappear after the cleanup walk; its surviving siblings still lose their grants.
    #[test]
    fn cleanup_skips_deleted_paths_and_revokes_surviving_grants() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let deleted = directory.path().join("deleted");
        let surviving = directory.path().join("surviving");
        std::fs::write(&deleted, b"deleted")?;
        std::fs::write(&surviving, b"surviving")?;
        let original_entries = count_file_acl_entries(&surviving)?;
        let profile = Profile::create(Role::Vm)?;
        let mut grants = Grants::new(&profile);
        grants.add(directory.path(), true)?;
        assert!(count_file_acl_entries(&surviving)? > original_entries);

        let paths = walk_objects(directory.path(), false)?;
        grants.objects.clear();
        std::fs::remove_file(&deleted)?;
        remove_grants_from_paths(&paths, &profile)?;
        assert_eq!(count_file_acl_entries(&surviving)?, original_entries);
        grants.clear()?;
        Ok(())
    }

    #[test]
    fn cleanup_removes_allow_and_deny_entries_only_for_its_profile() -> Result<()> {
        let file = tempfile::NamedTempFile::new()?;
        let original_entries = count_file_acl_entries(file.path())?;
        let readonly_profile = Profile::create(Role::Vm)?;
        let writable_profile = Profile::create(Role::Vm)?;
        let mut readonly_grants = Grants::new(&readonly_profile);
        let mut writable_grants = Grants::new(&writable_profile);
        readonly_grants.add(file.path(), false)?;
        assert_eq!(count_file_acl_entries(file.path())?, original_entries + 2);
        writable_grants.add(file.path(), true)?;
        assert_eq!(count_file_acl_entries(file.path())?, original_entries + 3);

        readonly_grants.clear()?;
        assert_eq!(count_file_acl_entries(file.path())?, original_entries + 1);
        writable_grants.clear()?;
        assert_eq!(count_file_acl_entries(file.path())?, original_entries);
        Ok(())
    }

    #[test]
    fn cleanup_accepts_deleted_granted_files() -> Result<()> {
        let directory = tempfile::tempdir()?;
        let deleted = directory.path().join("deleted");
        std::fs::write(&deleted, b"deleted")?;
        let profile = Profile::create(Role::Vm)?;
        let mut grants = Grants::new(&profile);
        grants.add(&deleted, true)?;
        std::fs::remove_file(&deleted)?;
        grants.clear()?;
        Ok(())
    }
}
