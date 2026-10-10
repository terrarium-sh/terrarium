use crate::terra::fs::host::FilesystemStat;
use crate::transport::wasi_error;
use crate::wasi::clocks::system_clock::Instant;
use crate::wasi::filesystem::{preopens, types};
use crate::wire;
use std::sync::atomic::{AtomicUsize, Ordering};

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
    pub atime: Instant,
    pub mtime: Instant,
    pub ctime: Instant,
}

const FIXED_OWNER: u32 = 1000;

fn fixed_owner(uid: Option<u32>, gid: Option<u32>) -> bool {
    uid.is_none_or(|value| value == FIXED_OWNER) && gid.is_none_or(|value| value == FIXED_OWNER)
}

pub(crate) type Descriptor = std::sync::Arc<types::Descriptor>;

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

    fn grow(&mut self, bytes: usize) -> Result<(), i32> {
        if self
            .used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= self.limit)
            })
            .is_err()
        {
            return Err(wire::EMFILE);
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
    pub inode: u64,
    pub type_: types::DescriptorType,
    pub next: u64,
}

fn text(bytes: &[u8]) -> Result<&str, i32> {
    if bytes.is_empty()
        || bytes.contains(&0)
        || bytes.contains(&b'/')
        || matches!(bytes, b"." | b"..")
    {
        return Err(wire::EINVAL);
    }
    core::str::from_utf8(bytes).map_err(|_| wire::EILSEQ)
}

fn instant_or_epoch(value: Option<Instant>) -> Instant {
    value.unwrap_or(Instant {
        seconds: 0,
        nanoseconds: 0,
    })
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
        uid: FIXED_OWNER,
        gid: FIXED_OWNER,
        size: value.size,
        blocks: value.size.div_ceil(512),
        atime: instant_or_epoch(value.data_access_timestamp),
        mtime: instant_or_epoch(value.data_modification_timestamp),
        ctime: instant_or_epoch(value.status_change_timestamp),
    }
}

async fn path_stat(directory: &types::Descriptor, name: &str) -> Result<Stat, i32> {
    let (metadata, identity) = futures::try_join!(
        async {
            directory
                .stat_at(types::PathFlags::empty(), name.to_owned())
                .await
                .map_err(wasi_error)
        },
        async {
            directory
                .metadata_hash_at(types::PathFlags::empty(), name.to_owned())
                .await
                .map_err(wasi_error)
        },
    )?;
    Ok(stat(metadata, identity))
}

fn verify_identity(
    expected: types::MetadataHashValue,
    actual: types::MetadataHashValue,
) -> Result<(), i32> {
    if (expected.upper, expected.lower) != (actual.upper, actual.lower) {
        return Err(wire::ENOENT);
    }
    Ok(())
}

impl Node {
    pub fn release_cached_directory(
        &mut self,
        parent: &Descriptor,
        name: &str,
        identity: types::MetadataHashValue,
    ) -> Option<types::Descriptor> {
        let descriptor = match std::sync::Arc::try_unwrap(self.descriptor.take()?) {
            Ok(descriptor) => descriptor,
            Err(descriptor) => {
                self.descriptor = Some(descriptor);
                return None;
            }
        };
        self.path = Some((parent.clone(), name.to_owned()));
        self.path_identity = Some(identity);
        Some(descriptor)
    }

    pub fn repoint(&mut self, parent: &Descriptor, name: &[u8]) {
        if let Ok(name) = text(name) {
            self.path = Some((parent.clone(), name.to_owned()));
        }
    }

    async fn expected_identity(&self) -> Result<Option<types::MetadataHashValue>, i32> {
        if let Some(descriptor) = &self.descriptor {
            Ok(Some(descriptor.metadata_hash().await.map_err(wasi_error)?))
        } else {
            Ok(self.path_identity)
        }
    }

    async fn checked_path(&self) -> Result<&(Descriptor, String), i32> {
        let path = self.path.as_ref().ok_or(wire::ENOENT)?;
        if let Some(expected) = self.expected_identity().await? {
            let actual = path
                .0
                .metadata_hash_at(types::PathFlags::empty(), path.1.clone())
                .await
                .map_err(wasi_error)?;
            verify_identity(expected, actual)?;
        }
        Ok(path)
    }

    pub async fn resolve_descriptor(&self) -> Result<Descriptor, i32> {
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
    ) -> Result<Descriptor, i32> {
        let (parent, name) = if self.descriptor.is_some() {
            self.path.as_ref().ok_or(wire::EACCES)?
        } else {
            self.checked_path().await?
        };
        let opened = parent
            .open_at(types::PathFlags::empty(), name.clone(), flags, access)
            .await
            .map_err(wasi_error)?;
        if let Some(expected) = self.expected_identity().await? {
            let actual = opened.metadata_hash().await.map_err(wasi_error)?;
            verify_identity(expected, actual)?;
        }
        Ok(std::sync::Arc::new(opened))
    }

    pub async fn child_identity(&self, name: &str) -> Result<types::MetadataHashValue, i32> {
        self.resolve_descriptor()
            .await?
            .metadata_hash_at(types::PathFlags::empty(), name.to_owned())
            .await
            .map_err(wasi_error)
    }

    pub async fn stat(&self) -> Result<Stat, i32> {
        let (mut stat, mode) = if let Some(descriptor) = &self.descriptor {
            let (metadata, identity, mode) = futures::try_join!(
                async { descriptor.stat().await.map_err(wasi_error) },
                async { descriptor.metadata_hash().await.map_err(wasi_error) },
                async {
                    crate::terra::fs::host::get_mode(descriptor)
                        .await
                        .map_err(extension_error)
                },
            )?;
            (stat(metadata, identity), mode)
        } else {
            let (parent, name) = self.checked_path().await?;
            futures::try_join!(path_stat(parent, name), async {
                crate::terra::fs::host::get_mode_at(parent, name.clone())
                    .await
                    .map_err(extension_error)
            },)?
        };
        if let Some(mode) = mode {
            stat.mode = mode;
        }
        Ok(stat)
    }

    pub async fn open(
        &self,
        access: types::DescriptorFlags,
        truncate: bool,
    ) -> Result<Descriptor, i32> {
        let mut descriptor = if let Some(descriptor) = &self.descriptor {
            descriptor.clone()
        } else {
            self.open_path(types::OpenFlags::empty(), access).await?
        };
        if !matches!(
            descriptor.get_type().await.map_err(wasi_error)?,
            types::DescriptorType::RegularFile
        ) {
            return Err(wire::EOPNOTSUPP);
        }
        if !descriptor
            .get_flags()
            .await
            .map_err(wasi_error)?
            .contains(access)
        {
            descriptor = self.open_path(types::OpenFlags::empty(), access).await?;
        }
        if truncate {
            descriptor.set_size(0).await.map_err(wasi_error)?;
        }
        Ok(descriptor)
    }

    pub async fn setattr(
        &self,
        mode: Option<u32>,
        size: Option<u64>,
        atime: Option<Instant>,
        mtime: Option<Instant>,
        uid: Option<u32>,
        gid: Option<u32>,
    ) -> Result<(), i32> {
        if !fixed_owner(uid, gid) {
            return Err(wire::EOPNOTSUPP);
        }
        if let Some(mode) = mode {
            if let Some(descriptor) = &self.descriptor {
                crate::terra::fs::host::set_mode(descriptor, mode)
                    .await
                    .map_err(extension_error)?;
            } else {
                let (parent, name) = self.checked_path().await?;
                crate::terra::fs::host::set_mode_at(parent, name.clone(), mode)
                    .await
                    .map_err(extension_error)?;
            }
        }
        if let Some(size) = size {
            self.open(types::DescriptorFlags::WRITE, false)
                .await?
                .set_size(size)
                .await
                .map_err(wasi_error)?;
        }
        if atime.is_some() || mtime.is_some() {
            let convert = |value: Option<Instant>| {
                value.map_or(
                    types::NewTimestamp::NoChange,
                    types::NewTimestamp::Timestamp,
                )
            };
            if let Some(descriptor) = &self.descriptor {
                descriptor
                    .set_times(convert(atime), convert(mtime))
                    .await
                    .map_err(wasi_error)?;
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
                    .map_err(wasi_error)?;
            }
        }
        Ok(())
    }

    pub async fn readlink(&self) -> Result<Vec<u8>, i32> {
        let (parent, name) = self.checked_path().await?;
        parent
            .readlink_at(name.clone())
            .await
            .map(std::string::String::into_bytes)
            .map_err(wasi_error)
    }

    pub async fn open_directory(&self) -> Result<(Directory, Descriptor), i32> {
        let descriptor = self.resolve_descriptor().await?;
        if !matches!(
            descriptor.get_type().await.map_err(wasi_error)?,
            types::DescriptorType::Directory
        ) {
            return Err(wire::ENOTDIR);
        }
        Ok((
            Directory {
                descriptor: descriptor.clone(),
                entries: None,
            },
            descriptor,
        ))
    }

    pub async fn statfs(&self) -> Result<FilesystemStat, i32> {
        crate::terra::fs::host::statfs(self.resolve_descriptor().await?.as_ref())
            .await
            .map_err(extension_error)
    }
}

pub async fn release_descriptor(descriptor: types::Descriptor) -> Result<(), i32> {
    crate::terra::fs::host::release_descriptor(descriptor)
        .await
        .map_err(extension_error)
}

impl Directory {
    async fn cache_entries(&mut self) -> Result<(), i32> {
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
                .ok_or(wire::EMFILE)?;
            name_bytes = name_bytes
                .checked_add(batch_name_bytes)
                .ok_or(wire::EMFILE)?;
            reservation.grow(cache_bytes)?;
            if entries.len() + batch.len() > 65_536 || name_bytes > 8 << 20 {
                return Err(wire::EMFILE);
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
        completion.await.map_err(wasi_error)?;
        self.entries = Some(CachedEntries {
            entries,
            _reservation: reservation,
        });
        Ok(())
    }

    pub async fn readdir(
        &mut self,
        cookie: u64,
        max_entries: u32,
        max_bytes: u32,
    ) -> Result<Vec<DirectoryEntry>, i32> {
        if cookie == 0 {
            self.entries = None;
        }
        if self.entries.is_none() {
            self.cache_entries().await?;
        }
        let entry_offset = usize::try_from(cookie).map_err(|_| wire::EINVAL)?;
        let descriptor = &self.descriptor;
        let limit = max_entries.min(64) as usize;
        let mut entries = self
            .entries
            .as_ref()
            .ok_or(wire::EIO)?
            .entries
            .iter()
            .enumerate()
            .skip(entry_offset)
            .peekable();
        let mut result = Vec::new();
        let mut bytes = 0usize;
        while result.len() < limit {
            let mut candidates = Vec::new();
            let mut candidate_bytes = bytes;
            while candidates.len() + result.len() < limit {
                let Some((_, entry)) = entries.peek() else {
                    break;
                };
                let size = (24_usize + entry.name.len()).next_multiple_of(8);
                if candidate_bytes + size > max_bytes as usize {
                    break;
                }
                let Some((index, entry)) = entries.next() else {
                    break;
                };
                candidates.push(async move {
                    let identity = descriptor
                        .metadata_hash_at(types::PathFlags::empty(), entry.name.clone())
                        .await
                        .map_err(wasi_error)?;
                    Ok((
                        DirectoryEntry {
                            name: entry.name.as_bytes().to_vec(),
                            inode: identity.lower,
                            type_: entry.type_.clone(),
                            next: (index + 1) as u64,
                        },
                        size,
                    ))
                });
                candidate_bytes += size;
            }
            if candidates.is_empty() {
                break;
            }
            for entry in futures::future::join_all(candidates).await {
                match entry {
                    Ok((entry, size)) => {
                        result.push(entry);
                        bytes += size;
                    }
                    Err(wire::ENOENT) => {}
                    Err(errno) => return Err(errno),
                }
            }
        }

        Ok(result)
    }
}

pub fn root() -> Result<Node, i32> {
    let mut directories = preopens::get_directories();
    if directories.len() != 1 {
        return Err(wire::EACCES);
    }
    let (descriptor, _) = directories.pop().ok_or(wire::ENOENT)?;
    Ok(Node {
        descriptor: Some(std::sync::Arc::new(descriptor)),
        path: None,
        path_identity: None,
    })
}

pub async fn lookup(parent: &Node, name: Vec<u8>) -> Result<Node, i32> {
    let name = text(&name)?.to_owned();
    let directory = parent.resolve_descriptor().await?;
    let metadata = directory
        .stat_at(types::PathFlags::empty(), name.clone())
        .await
        .map_err(wasi_error)?;
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
                Err(code) => return Err(wasi_error(code)),
            }
        }
        if opened.is_none() {
            opened = match crate::terra::fs::host::open_metadata_at(&directory, name.clone()).await
            {
                Ok(descriptor) => Some(descriptor),
                Err(crate::terra::fs::host::Error::Unsupported) => None,
                Err(error) => return Err(extension_error(error)),
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
                .map_err(wasi_error)?,
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
    open: types::OpenFlags,
    mode: u32,
) -> Result<(Node, Descriptor), i32> {
    let name = text(&name)?.to_owned();
    let directory = parent.resolve_descriptor().await?;
    let created = match directory
        .stat_at(types::PathFlags::empty(), name.clone())
        .await
    {
        Ok(metadata) if !matches!(metadata.type_, types::DescriptorType::RegularFile) => {
            return Err(wire::EOPNOTSUPP);
        }
        Ok(_) => false,
        Err(types::ErrorCode::NoEntry) => true,
        Err(code) => return Err(wasi_error(code)),
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
            .map_err(wasi_error)?,
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

pub async fn mkdir(parent: &Node, name: Vec<u8>, mode: u32) -> Result<Node, i32> {
    parent
        .resolve_descriptor()
        .await?
        .create_directory_at(text(&name)?.to_owned())
        .await
        .map_err(wasi_error)?;
    let node = lookup(parent, name).await?;
    apply_create_mode(&node.resolve_descriptor().await?, mode).await?;
    Ok(node)
}

async fn apply_create_mode(descriptor: &Descriptor, mode: u32) -> Result<(), i32> {
    match crate::terra::fs::host::set_mode(descriptor, mode).await {
        Ok(()) | Err(crate::terra::fs::host::Error::Unsupported) => Ok(()),
        Err(error) => Err(extension_error(error)),
    }
}

fn extension_error(error: crate::terra::fs::host::Error) -> i32 {
    match error {
        crate::terra::fs::host::Error::Access => wire::EACCES,
        crate::terra::fs::host::Error::Io => wire::EIO,
        crate::terra::fs::host::Error::Unsupported => wire::EOPNOTSUPP,
    }
}

pub async fn unlink(parent: &Node, name: Vec<u8>, directory: bool) -> Result<(), i32> {
    let parent = parent.resolve_descriptor().await?;
    let name = text(&name)?.to_owned();
    let result = if directory {
        parent.remove_directory_at(name).await
    } else {
        parent.unlink_file_at(name).await
    };
    result.map_err(wasi_error)
}

pub async fn rename(
    old_parent: &Node,
    old_name: Vec<u8>,
    new_parent: &Node,
    new_name: Vec<u8>,
) -> Result<(), i32> {
    old_parent
        .resolve_descriptor()
        .await?
        .rename_at(
            text(&old_name)?.to_owned(),
            new_parent.resolve_descriptor().await?.as_ref(),
            text(&new_name)?.to_owned(),
        )
        .await
        .map_err(wasi_error)
}

pub async fn link(old: &Node, parent: &Node, name: Vec<u8>) -> Result<(), i32> {
    let (source, source_name) = old.checked_path().await?;
    source
        .link_at(
            types::PathFlags::empty(),
            source_name.clone(),
            parent.resolve_descriptor().await?.as_ref(),
            text(&name)?.to_owned(),
        )
        .await
        .map_err(wasi_error)
}

pub async fn symlink(parent: &Node, name: Vec<u8>, target: Vec<u8>) -> Result<Node, i32> {
    parent
        .resolve_descriptor()
        .await?
        .symlink_at(
            core::str::from_utf8(&target)
                .map_err(|_| wire::EILSEQ)?
                .to_owned(),
            text(&name)?.to_owned(),
        )
        .await
        .map_err(wasi_error)?;
    lookup(parent, name).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

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
        assert_matches!(second.grow(2), Err(wire::EMFILE));
        drop(first);
        assert!(second.grow(1).is_ok());
        assert_eq!(used.load(Ordering::Relaxed), 1);
    }
}
