use crate::wasi::filesystem::{preopens, types};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}

#[derive(Clone, Copy)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub blocks: u64,
    pub atime: Timestamp,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
}

#[derive(Clone, Copy)]
pub enum Error {
    Access,
    Exist,
    Invalid,
    IllegalByteSequence,
    Io,
    IsDirectory,
    Loop,
    NoEntry,
    NotDirectory,
    NotEmpty,
    ReadOnly,
    Unsupported,
    Exhausted,
    NoSpace,
    Quota,
    TooLarge,
}

#[derive(Clone, Copy)]
pub enum RenameMode {
    Replace,
    NoReplace,
    Exchange,
}

pub struct Statfs {
    pub blocks: u64,
    pub blocks_free: u64,
    pub blocks_available: u64,
    pub files: u64,
    pub files_free: u64,
    pub block_size: u32,
    pub name_max: u32,
}

const FIXED_OWNER: u32 = 1000;

fn fixed_owner(uid: Option<u32>, gid: Option<u32>) -> bool {
    uid.is_none_or(|value| value == FIXED_OWNER) && gid.is_none_or(|value| value == FIXED_OWNER)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OpenFlags(u32);

impl OpenFlags {
    pub const READ: Self = Self(1);
    pub const WRITE: Self = Self(2);
    pub const TRUNCATE: Self = Self(4);
}

impl core::ops::BitOr for OpenFlags {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
impl core::ops::BitOrAssign for OpenFlags {
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateFlags(u32);

impl CreateFlags {
    pub const NONE: Self = Self(0);
    pub const EXCLUSIVE: Self = Self(4);
    pub const TRUNCATE: Self = Self(8);
}
impl core::ops::BitOr for CreateFlags {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}
impl core::ops::BitOrAssign for CreateFlags {
    fn bitor_assign(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

type Descriptor = std::sync::Arc<types::Descriptor>;

const MAX_DIRECTORY_CACHE_BYTES: usize = 4 << 20;
static DIRECTORY_CACHE_BYTES: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone)]
pub struct Node {
    descriptor: Option<Descriptor>,
    path: Option<(Descriptor, String)>,
    path_identity: Option<types::MetadataHashValue>,
}

pub struct Directory {
    descriptor: Descriptor,
    entries: Option<CachedEntries>,
}

struct CachedEntries {
    entries: Vec<types::DirectoryEntry>,
    _reservation: CacheReservation<'static>,
}

struct CacheReservation<'a> {
    used: &'a AtomicUsize,
    limit: usize,
    bytes: usize,
}

impl<'a> CacheReservation<'a> {
    fn new(used: &'a AtomicUsize, limit: usize) -> Self {
        Self {
            used,
            limit,
            bytes: 0,
        }
    }

    fn grow(&mut self, bytes: usize) -> Result<(), Error> {
        if self
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= self.limit)
            })
            .is_err()
        {
            return Err(Error::Exhausted);
        }
        self.bytes += bytes;
        Ok(())
    }
}

impl Drop for CacheReservation<'_> {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::Release);
    }
}

pub struct DirectoryEntry {
    pub name: Vec<u8>,
    pub stat: Stat,
    pub next: u64,
}

fn text(bytes: &[u8]) -> Result<&str, Error> {
    if bytes.is_empty()
        || bytes.contains(&0)
        || bytes.contains(&b'/')
        || matches!(bytes, b"." | b"..")
    {
        return Err(Error::Invalid);
    }
    core::str::from_utf8(bytes).map_err(|_| Error::IllegalByteSequence)
}

#[allow(clippy::needless_pass_by_value)]
fn error(code: types::ErrorCode) -> Error {
    use types::ErrorCode;
    match code {
        ErrorCode::Access | ErrorCode::NotPermitted => Error::Access,
        ErrorCode::Exist | ErrorCode::Already => Error::Exist,
        ErrorCode::Invalid => Error::Invalid,
        ErrorCode::IllegalByteSequence => Error::IllegalByteSequence,
        ErrorCode::NoEntry => Error::NoEntry,
        ErrorCode::NotDirectory => Error::NotDirectory,
        ErrorCode::IsDirectory => Error::IsDirectory,
        ErrorCode::Loop => Error::Loop,
        ErrorCode::NotEmpty => Error::NotEmpty,
        ErrorCode::ReadOnly => Error::ReadOnly,
        ErrorCode::InsufficientMemory => Error::Exhausted,
        ErrorCode::InsufficientSpace => Error::NoSpace,
        ErrorCode::Quota => Error::Quota,
        ErrorCode::FileTooLarge
        | ErrorCode::MessageSize
        | ErrorCode::NameTooLong
        | ErrorCode::Overflow => Error::TooLarge,
        ErrorCode::Unsupported => Error::Unsupported,
        ErrorCode::BadDescriptor
        | ErrorCode::Busy
        | ErrorCode::Deadlock
        | ErrorCode::InProgress
        | ErrorCode::Interrupted
        | ErrorCode::Io
        | ErrorCode::TooManyLinks
        | ErrorCode::NoDevice
        | ErrorCode::NoLock
        | ErrorCode::NotRecoverable
        | ErrorCode::NoTty
        | ErrorCode::NoSuchDevice
        | ErrorCode::Pipe
        | ErrorCode::InvalidSeek
        | ErrorCode::TextFileBusy
        | ErrorCode::CrossDevice
        | ErrorCode::Other(_) => Error::Io,
    }
}

fn timestamp(value: Option<crate::wasi::clocks::system_clock::Instant>) -> Timestamp {
    value.map_or(
        Timestamp {
            seconds: 0,
            nanoseconds: 0,
        },
        |value| Timestamp {
            seconds: value.seconds,
            nanoseconds: value.nanoseconds,
        },
    )
}

#[allow(clippy::needless_pass_by_value)]
fn stat(value: types::DescriptorStat, identity: types::MetadataHashValue) -> Stat {
    let mode = match value.type_ {
        types::DescriptorType::Directory => 0o040_755,
        types::DescriptorType::SymbolicLink => 0o120_777,
        types::DescriptorType::RegularFile => 0o100_755,
        types::DescriptorType::BlockDevice => 0o060_000,
        types::DescriptorType::CharacterDevice => 0o020_000,
        types::DescriptorType::Fifo => 0o010_000,
        types::DescriptorType::Socket => 0o140_000,
        types::DescriptorType::Other(_) => 0,
    };
    Stat {
        dev: identity.upper,
        ino: identity.lower,
        mode,
        nlink: value.link_count,
        uid: 1000,
        gid: 1000,
        size: value.size,
        blocks: value.size.div_ceil(512),
        atime: timestamp(value.data_access_timestamp),
        mtime: timestamp(value.data_modification_timestamp),
        ctime: timestamp(value.status_change_timestamp),
    }
}

async fn path_stat(directory: &types::Descriptor, name: &str) -> Result<Stat, Error> {
    Ok(stat(
        directory
            .stat_at(types::PathFlags::empty(), name.to_owned())
            .await
            .map_err(error)?,
        directory
            .metadata_hash_at(types::PathFlags::empty(), name.to_owned())
            .await
            .map_err(error)?,
    ))
}

impl Node {
    pub fn repoint(&mut self, parent: &Descriptor, name: &[u8]) {
        if let Ok(name) = text(name) {
            self.path = Some((parent.clone(), name.to_owned()));
        }
    }

    pub fn clear_path(&mut self) {
        self.path = None;
    }

    async fn checked_path(&self) -> Result<&(Descriptor, String), Error> {
        let path = self.path.as_ref().ok_or(Error::NoEntry)?;
        if let Some(expected) = &self.path_identity {
            let actual = path
                .0
                .metadata_hash_at(types::PathFlags::empty(), path.1.clone())
                .await
                .map_err(error)?;
            if (expected.upper, expected.lower) != (actual.upper, actual.lower) {
                return Err(Error::NoEntry);
            }
        }
        Ok(path)
    }

    pub async fn resolve_descriptor(&self) -> Result<Descriptor, Error> {
        if let Some(descriptor) = &self.descriptor {
            return Ok(descriptor.clone());
        }
        self.open_path(types::OpenFlags::DIRECTORY, types::DescriptorFlags::READ)
            .await
    }

    async fn open_path(
        &self,
        flags: types::OpenFlags,
        access: types::DescriptorFlags,
    ) -> Result<Descriptor, Error> {
        let (parent, name) = if self.descriptor.is_some() {
            self.path.as_ref().ok_or(Error::Access)?
        } else {
            self.checked_path().await?
        };
        let opened = parent
            .open_at(types::PathFlags::empty(), name.clone(), flags, access)
            .await
            .map_err(error)?;
        let expected = if let Some(descriptor) = &self.descriptor {
            Some(descriptor.metadata_hash().await.map_err(error)?)
        } else {
            self.path_identity
        };
        if let Some(expected) = expected {
            let actual = opened.metadata_hash().await.map_err(error)?;
            if (expected.upper, expected.lower) != (actual.upper, actual.lower) {
                return Err(Error::NoEntry);
            }
        }
        Ok(std::sync::Arc::new(opened))
    }

    pub async fn child_identity(&self, name: &str) -> Result<types::MetadataHashValue, Error> {
        self.resolve_descriptor()
            .await?
            .metadata_hash_at(types::PathFlags::empty(), name.to_owned())
            .await
            .map_err(error)
    }

    pub async fn stat(&self) -> Result<Stat, Error> {
        let (mut stat, mode) = if let Some(descriptor) = &self.descriptor {
            (
                stat(
                    descriptor.stat().await.map_err(error)?,
                    descriptor.metadata_hash().await.map_err(error)?,
                ),
                crate::terra::fs::host::get_mode(descriptor).await,
            )
        } else {
            let (parent, name) = self.checked_path().await?;
            (
                path_stat(parent, name).await?,
                crate::terra::fs::host::get_mode_at(parent, name.clone()).await,
            )
        };
        if let Some(mode) = mode.map_err(host_error)? {
            stat.mode = mode;
        }
        Ok(stat)
    }

    pub async fn open(&self, flags: OpenFlags) -> Result<Descriptor, Error> {
        let mut access = types::DescriptorFlags::empty();
        if flags.0 & OpenFlags::READ.0 != 0 {
            access |= types::DescriptorFlags::READ;
        }
        if flags.0 & OpenFlags::WRITE.0 != 0 {
            access |= types::DescriptorFlags::WRITE;
        }

        let mut descriptor = if let Some(descriptor) = &self.descriptor {
            descriptor.clone()
        } else {
            self.open_path(types::OpenFlags::empty(), access).await?
        };
        if !matches!(
            descriptor.get_type().await.map_err(error)?,
            types::DescriptorType::RegularFile
        ) {
            return Err(Error::Unsupported);
        }
        if !descriptor
            .get_flags()
            .await
            .map_err(error)?
            .contains(access)
        {
            descriptor = self.open_path(types::OpenFlags::empty(), access).await?;
        }
        if flags.0 & OpenFlags::TRUNCATE.0 != 0 {
            descriptor.set_size(0).await.map_err(error)?;
        }
        Ok(descriptor)
    }

    pub async fn setattr(
        &self,
        mode: Option<u32>,
        size: Option<u64>,
        atime: Option<Timestamp>,
        mtime: Option<Timestamp>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), Error> {
        if !fixed_owner(uid, gid) {
            return Err(Error::Unsupported);
        }
        if let Some(mode) = mode {
            if let Some(descriptor) = &self.descriptor {
                crate::terra::fs::host::set_mode(descriptor, mode)
                    .await
                    .map_err(host_error)?;
            } else {
                let (parent, name) = self.checked_path().await?;
                crate::terra::fs::host::set_mode_at(parent, name.clone(), mode)
                    .await
                    .map_err(host_error)?;
            }
        }
        if let Some(size) = size {
            self.open(OpenFlags::WRITE)
                .await?
                .set_size(size)
                .await
                .map_err(error)?;
        }
        if atime.is_some() || mtime.is_some() {
            let convert = |value: Option<Timestamp>| match value {
                Some(value) => {
                    types::NewTimestamp::Timestamp(crate::wasi::clocks::system_clock::Instant {
                        seconds: value.seconds,
                        nanoseconds: value.nanoseconds,
                    })
                }
                None => types::NewTimestamp::NoChange,
            };
            if let Some(descriptor) = &self.descriptor {
                descriptor
                    .set_times(convert(atime), convert(mtime))
                    .await
                    .map_err(error)?;
            } else {
                let (parent, name) = self.checked_path().await?;
                parent
                    .set_times_at(
                        types::PathFlags::empty(),
                        name.clone(),
                        convert(atime),
                        convert(mtime),
                    )
                    .await
                    .map_err(error)?;
            }
        }
        Ok(())
    }

    pub async fn readlink(&self) -> Result<Vec<u8>, Error> {
        let (parent, name) = self.path.as_ref().ok_or(Error::Unsupported)?;
        parent
            .readlink_at(name.clone())
            .await
            .map(std::string::String::into_bytes)
            .map_err(error)
    }

    pub async fn open_directory(&self) -> Result<(Directory, Option<Descriptor>), Error> {
        let descriptor = self.resolve_descriptor().await?;
        if !matches!(
            descriptor.get_type().await.map_err(error)?,
            types::DescriptorType::Directory
        ) {
            return Err(Error::NotDirectory);
        }
        Ok((
            Directory {
                descriptor: descriptor.clone(),
                entries: None,
            },
            Some(descriptor),
        ))
    }

    pub async fn statfs(&self) -> Result<Statfs, Error> {
        let stat = crate::terra::fs::host::statfs(self.resolve_descriptor().await?.as_ref())
            .await
            .map_err(host_error)?;
        Ok(Statfs {
            blocks: stat.blocks,
            blocks_free: stat.blocks_free,
            blocks_available: stat.blocks_available,
            files: stat.files,
            files_free: stat.files_free,
            block_size: stat.block_size,
            name_max: stat.name_max,
        })
    }
}

impl Directory {
    pub async fn readdir(
        &mut self,
        cookie: u64,
        max_entries: u32,
        max_bytes: u32,
    ) -> Result<Vec<DirectoryEntry>, Error> {
        if cookie == 0 {
            self.entries = None;
        }
        if self.entries.is_none() {
            let (mut stream, completion) = self.descriptor.read_directory();
            let mut entries = Vec::new();
            let mut name_bytes = 0usize;
            let mut reservation =
                CacheReservation::new(&DIRECTORY_CACHE_BYTES, MAX_DIRECTORY_CACHE_BYTES);
            loop {
                let (stream_result, batch) = stream.read(Vec::with_capacity(64)).await;
                let (batch_name_bytes, cache_bytes) = batch
                    .iter()
                    .try_fold((0usize, 0usize), |(name_bytes, cache_bytes), entry| {
                        Some((
                            name_bytes.checked_add(entry.name.len())?,
                            cache_bytes
                                .checked_add(entry.name.capacity())?
                                .checked_add(2 * std::mem::size_of_val(entry))?,
                        ))
                    })
                    .ok_or(Error::Exhausted)?;
                name_bytes = name_bytes
                    .checked_add(batch_name_bytes)
                    .ok_or(Error::Exhausted)?;
                reservation.grow(cache_bytes)?;
                if entries.len() + batch.len() > 65_536 || name_bytes > 8 << 20 {
                    return Err(Error::Exhausted);
                }
                entries.extend(batch);
                if !matches!(
                    stream_result,
                    wit_bindgen::rt::async_support::StreamResult::Complete(_)
                ) {
                    break;
                }
            }
            drop(stream);
            completion.await.map_err(error)?;
            self.entries = Some(CachedEntries {
                entries,
                _reservation: reservation,
            });
        }
        let entry_offset = usize::try_from(cookie).map_err(|_| Error::Invalid)?;
        let mut result = Vec::new();
        let mut bytes = 0usize;
        for (index, entry) in self
            .entries
            .as_ref()
            .ok_or(Error::Io)?
            .entries
            .iter()
            .enumerate()
            .skip(entry_offset)
        {
            if result.len() == max_entries.min(64) as usize {
                break;
            }
            let size = (24_usize + entry.name.len()).next_multiple_of(8);
            if bytes + size > max_bytes as usize {
                break;
            }
            let entry_stat = match path_stat(&self.descriptor, &entry.name).await {
                Ok(entry_stat) => entry_stat,
                Err(Error::NoEntry) => continue,
                Err(error) => return Err(error),
            };
            result.push(DirectoryEntry {
                name: entry.name.as_bytes().to_vec(),
                stat: entry_stat,
                next: (index + 1) as u64,
            });
            bytes += size;
        }
        Ok(result)
    }
}

pub fn root() -> Result<Node, Error> {
    let mut directories = preopens::get_directories();
    if directories.len() != 1 {
        return Err(Error::Access);
    }
    let (descriptor, _) = directories.pop().ok_or(Error::NoEntry)?;
    Ok(Node {
        descriptor: Some(std::sync::Arc::new(descriptor)),
        path: None,
        path_identity: None,
    })
}

pub async fn lookup(parent: &Node, name: Vec<u8>) -> Result<Node, Error> {
    let name = text(&name)?.to_owned();
    let directory = parent.resolve_descriptor().await?;
    let metadata = directory
        .stat_at(types::PathFlags::empty(), name.clone())
        .await
        .map_err(error)?;
    let flags = match metadata.type_ {
        types::DescriptorType::RegularFile => {
            Some(types::DescriptorFlags::READ | types::DescriptorFlags::WRITE)
        }
        types::DescriptorType::Directory => {
            Some(types::DescriptorFlags::READ | types::DescriptorFlags::MUTATE_DIRECTORY)
        }
        types::DescriptorType::SymbolicLink
        | types::DescriptorType::BlockDevice
        | types::DescriptorType::CharacterDevice
        | types::DescriptorType::Fifo
        | types::DescriptorType::Socket
        | types::DescriptorType::Other(_) => None,
    };
    let descriptor = if let Some(flags) = flags {
        let mut opened = None;
        for access in [flags, types::DescriptorFlags::READ] {
            match directory
                .open_at(
                    types::PathFlags::empty(),
                    name.clone(),
                    types::OpenFlags::empty(),
                    access,
                )
                .await
            {
                Ok(descriptor) => {
                    opened = Some(descriptor);
                    break;
                }
                Err(
                    types::ErrorCode::ReadOnly
                    | types::ErrorCode::NotPermitted
                    | types::ErrorCode::Access,
                ) => {}
                Err(code) => return Err(error(code)),
            }
        }
        if opened.is_none() {
            opened = match crate::terra::fs::host::open_metadata_at(&directory, name.clone()).await
            {
                Ok(descriptor) => Some(descriptor),
                Err(crate::terra::fs::host::Error::Unsupported) => None,
                Err(error) => return Err(host_error(error)),
            };
        }
        opened.map(std::sync::Arc::new)
    } else {
        None
    };
    let path_identity = if descriptor.is_none() {
        Some(
            directory
                .metadata_hash_at(types::PathFlags::empty(), name.clone())
                .await
                .map_err(error)?,
        )
    } else {
        None
    };
    Ok(Node {
        descriptor,
        path: Some((directory.clone(), name)),
        path_identity,
    })
}

pub async fn create(
    parent: &Node,
    name: Vec<u8>,
    flags: CreateFlags,
    mode: u32,
) -> Result<(Node, Descriptor), Error> {
    let name = text(&name)?.to_owned();
    let mut open = types::OpenFlags::CREATE;
    if flags.0 & CreateFlags::EXCLUSIVE.0 != 0 {
        open |= types::OpenFlags::EXCLUSIVE;
    }
    if flags.0 & CreateFlags::TRUNCATE.0 != 0 {
        open |= types::OpenFlags::TRUNCATE;
    }
    let directory = parent.resolve_descriptor().await?;
    let created = match directory
        .stat_at(types::PathFlags::empty(), name.clone())
        .await
    {
        Ok(metadata) if !matches!(metadata.type_, types::DescriptorType::RegularFile) => {
            return Err(Error::Unsupported);
        }
        Ok(_) => false,
        Err(types::ErrorCode::NoEntry) => true,
        Err(code) => return Err(error(code)),
    };
    let descriptor = std::sync::Arc::new(
        directory
            .open_at(
                types::PathFlags::empty(),
                name.clone(),
                open,
                types::DescriptorFlags::READ | types::DescriptorFlags::WRITE,
            )
            .await
            .map_err(error)?,
    );
    if created {
        apply_create_mode(&descriptor, mode).await?;
    }
    Ok((
        Node {
            descriptor: Some(descriptor.clone()),
            path: Some((directory.clone(), name)),
            path_identity: None,
        },
        descriptor,
    ))
}

pub async fn mkdir(parent: &Node, name: Vec<u8>, mode: u32) -> Result<Node, Error> {
    parent
        .resolve_descriptor()
        .await?
        .create_directory_at(text(&name)?.to_owned())
        .await
        .map_err(error)?;
    let node = lookup(parent, name).await?;
    apply_create_mode(&node.resolve_descriptor().await?, mode).await?;
    Ok(node)
}

async fn apply_create_mode(descriptor: &Descriptor, mode: u32) -> Result<(), Error> {
    match crate::terra::fs::host::set_mode(descriptor, mode).await {
        Ok(()) | Err(crate::terra::fs::host::Error::Unsupported) => Ok(()),
        Err(error) => Err(host_error(error)),
    }
}

fn host_error(error: crate::terra::fs::host::Error) -> Error {
    match error {
        crate::terra::fs::host::Error::Access => Error::Access,
        crate::terra::fs::host::Error::Io => Error::Io,
        crate::terra::fs::host::Error::Unsupported => Error::Unsupported,
    }
}

pub async fn unlink(parent: &Node, name: Vec<u8>, directory: bool) -> Result<(), Error> {
    if directory {
        parent
            .resolve_descriptor()
            .await?
            .remove_directory_at(text(&name)?.to_owned())
            .await
            .map_err(error)
    } else {
        parent
            .resolve_descriptor()
            .await?
            .unlink_file_at(text(&name)?.to_owned())
            .await
            .map_err(error)
    }
}

pub async fn rename(
    old_parent: &Node,
    old_name: Vec<u8>,
    new_parent: &Node,
    new_name: Vec<u8>,
    mode: RenameMode,
) -> Result<(), Error> {
    if !matches!(mode, RenameMode::Replace) {
        return Err(Error::Unsupported);
    }
    old_parent
        .resolve_descriptor()
        .await?
        .rename_at(
            text(&old_name)?.to_owned(),
            new_parent.resolve_descriptor().await?.as_ref(),
            text(&new_name)?.to_owned(),
        )
        .await
        .map_err(error)
}

pub async fn link(old: &Node, parent: &Node, name: Vec<u8>) -> Result<(), Error> {
    let (source, source_name) = old.checked_path().await?;
    source
        .link_at(
            types::PathFlags::empty(),
            source_name.clone(),
            parent.resolve_descriptor().await?.as_ref(),
            text(&name)?.to_owned(),
        )
        .await
        .map_err(error)
}

pub async fn symlink(parent: &Node, name: Vec<u8>, target: Vec<u8>) -> Result<Node, Error> {
    parent
        .resolve_descriptor()
        .await?
        .symlink_at(
            core::str::from_utf8(&target)
                .map_err(|_| Error::IllegalByteSequence)?
                .to_owned(),
            text(&name)?.to_owned(),
        )
        .await
        .map_err(error)?;
    lookup(parent, name).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_owner_requests_do_not_need_host_mutation() {
        assert!(fixed_owner(Some(FIXED_OWNER), Some(FIXED_OWNER)));
        assert!(fixed_owner(None, Some(FIXED_OWNER)));
        assert!(fixed_owner(Some(FIXED_OWNER), None));
        assert!(!fixed_owner(Some(0), Some(FIXED_OWNER)));
        assert!(!fixed_owner(Some(FIXED_OWNER), Some(0)));
    }

    #[test]
    fn directory_cache_budget_is_shared() {
        let used = AtomicUsize::new(0);
        let mut first = CacheReservation::new(&used, 4);
        assert!(first.grow(3).is_ok());
        let mut second = CacheReservation::new(&used, 4);
        assert!(matches!(second.grow(2), Err(Error::Exhausted)));
        drop(first);
        assert!(second.grow(1).is_ok());
        assert_eq!(used.load(Ordering::Relaxed), 1);
    }
}
