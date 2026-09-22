mod io;
mod requests;

use std::sync::{
    LazyLock, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};

use futures::{FutureExt, StreamExt, future::poll_fn};

use terra_device_transport::{
    INT_USED_BUFFER, MmioError, MmioTransport, SPLIT_RING_DESC_F_NEXT, SplitRingDescriptor,
    complete_split_ring_entry, read_split_ring_available_head, split_ring_chain,
};

use crate::host;
use crate::terra::host::{interrupt, memory};
use crate::terra::mmio::types::DeviceError;
use crate::wire;

const HIPRIO_QUEUE: usize = 0;
const REQUEST_QUEUE: usize = 1;
const STATUS: u64 = 0x70;
const QUEUE_SIZE: u16 = 256;
const DEVICE_ID: u32 = 26;
const VIRTIO_F_VERSION_1: u64 = 1 << 32;
const WRITE: u16 = 2;
const MAX_CHAIN: usize = 32;
const MAX_REQUEST: usize = 128 * 1024;
const MAX_READ: usize = 64 * 1024;
#[allow(clippy::cast_possible_truncation)]
const MAX_COPY: usize = terra_limits::MAX_SINGLE_GUEST_COPY_BYTES as usize;
const MAX_NODES: usize = 8192;
const MAX_HANDLES: usize = 2048;
const MAX_DIRECTORIES: usize = 2048;
const CLOSE_FLUSH_TIMEOUT: u64 = 1_000_000_000;

struct NodeRecord {
    id: u64,
    dev: u64,
    ino: u64,
    lookups: u64,
    node: host::Node,
}

struct OpenHandle {
    id: u64,
    node: u64,
    writable: bool,
    descriptor: std::sync::Arc<crate::wasi::filesystem::types::Descriptor>,
}

struct OpenDirectory {
    node: u64,
    directory: std::sync::Arc<futures::lock::Mutex<host::Directory>>,
    descriptor: Option<std::sync::Arc<crate::wasi::filesystem::types::Descriptor>>,
}

struct PendingReply {
    queue: usize,
    head: u16,
    output: Vec<Descriptor>,
    unique: u64,
    generation: u64,
}

struct State {
    event_request: Option<PendingReply>,
    event_entries: std::collections::BTreeMap<(u64, Vec<u8>), u64>,
    events_enabled: bool,
    max_nodes: usize,
    nodes: std::collections::BTreeMap<u64, NodeRecord>,
    node_id_by_identity: std::collections::BTreeMap<(u64, u64), u64>,
    unused_nodes: std::collections::BTreeSet<u64>,
    handles: Vec<OpenHandle>,
    directories: Vec<(u64, OpenDirectory)>,
    next_handle: u64,
    next_node: u64,
}

struct Transport {
    mmio: MmioTransport,
    next: [u16; 2],
    generation: u64,
}

type Descriptor = SplitRingDescriptor;

static STATE: LazyLock<Mutex<Option<State>>> = LazyLock::new(|| Mutex::new(None));
static TRANSPORT: LazyLock<Mutex<Option<Transport>>> = LazyLock::new(|| Mutex::new(None));
static COMPLETION_GATE: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
static RUNNING: AtomicBool = AtomicBool::new(false);
static WORK: LazyLock<Mutex<Work>> = LazyLock::new(|| Mutex::new(Work::default()));
static WORK_WAKER: futures::task::AtomicWaker = futures::task::AtomicWaker::new();

#[derive(Default)]
struct Work {
    pending: [bool; 2],
    next: usize,
}

fn error(error: MmioError) -> DeviceError {
    terra_device_transport::device_error!(error, DeviceError)
}

fn publish_interrupt_level(level: bool) {
    if cfg!(target_arch = "wasm32") {
        crate::terra::host::interrupt::set_level(level);
    }
}

fn transport<T>(
    f: impl FnOnce(&mut Transport) -> Result<T, DeviceError>,
) -> Result<T, DeviceError> {
    let mut transport = TRANSPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let transport = transport.as_mut().ok_or(DeviceError::NotReady)?;
    let result = f(transport);
    if let Some(level) = transport.mmio.take_irq() {
        publish_interrupt_level(level);
    }
    result
}

fn generation() -> Result<u64, DeviceError> {
    transport(|transport| Ok(transport.generation))
}

fn queue_work(queue: usize) {
    if !matches!(queue, HIPRIO_QUEUE | REQUEST_QUEUE) {
        return;
    }
    let mut work = WORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    work.pending[queue] = true;
    WORK_WAKER.wake();
}

fn queue_work_if_current(queue: usize, expected_generation: u64) -> Result<(), DeviceError> {
    let _completion = COMPLETION_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if generation()? == expected_generation {
        queue_work(queue);
    }
    Ok(())
}

fn take_work() -> Option<usize> {
    let mut work = WORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for offset in 0..work.pending.len() {
        let queue = (work.next + offset) % work.pending.len();
        if work.pending[queue] {
            work.pending[queue] = false;
            work.next = (queue + 1) % work.pending.len();
            return Some(queue);
        }
    }
    None
}

fn clear_work() {
    *WORK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Work::default();
}

fn node(state: &State, inode: u64) -> Result<&host::Node, DeviceError> {
    state
        .nodes
        .get(&inode)
        .map(|record| &record.node)
        .ok_or(DeviceError::Io)
}

fn node_id(state: &mut State, node: host::Node, stat: &host::Stat) -> Result<u64, i32> {
    if let Some(&id) = state.node_id_by_identity.get(&(stat.dev, stat.ino)) {
        let record = state.nodes.get_mut(&id).ok_or(5)?;
        record.node = node;
        record.lookups = record.lookups.saturating_add(1);
        state.unused_nodes.remove(&id);
        return Ok(record.id);
    }
    if state.nodes.len() == state.max_nodes {
        evict_unused_node(state);
    }
    if state.nodes.len() == state.max_nodes {
        return Err(24);
    }
    let id = state.next_node;
    state.next_node = state.next_node.wrapping_add(1).max(2);
    state.nodes.insert(
        id,
        NodeRecord {
            id,
            dev: stat.dev,
            ino: stat.ino,
            lookups: 1,
            node,
        },
    );
    state.node_id_by_identity.insert((stat.dev, stat.ino), id);
    Ok(id)
}

fn forget(state: &mut State, id: u64, count: u64) {
    if id == 1 {
        return;
    }
    if let Some(record) = state.nodes.get_mut(&id) {
        record.lookups = record.lookups.saturating_sub(count);
    }
    mark_unused_if_unheld(state, id);
}

fn node_is_held(state: &State, id: u64) -> bool {
    state
        .handles
        .iter()
        .map(|handle| handle.node)
        .chain(
            state
                .directories
                .iter()
                .map(|(_, directory)| directory.node),
        )
        .any(|held| held == id)
}

fn mark_unused_if_unheld(state: &mut State, id: u64) {
    if id != 1
        && state
            .nodes
            .get(&id)
            .is_some_and(|record| record.lookups == 0)
        && !node_is_held(state, id)
    {
        state.unused_nodes.insert(id);
    }
}

fn evict_unused_node(state: &mut State) {
    if let Some(id) = state.unused_nodes.pop_first()
        && let Some(record) = state.nodes.remove(&id)
    {
        state.node_id_by_identity.remove(&(record.dev, record.ino));
    }
}

#[allow(clippy::needless_pass_by_value)]
fn repoint_node(
    state: &mut State,
    stat: &host::Stat,
    parent: std::sync::Arc<crate::wasi::filesystem::types::Descriptor>,
    name: Vec<u8>,
) {
    if let Some(&id) = state.node_id_by_identity.get(&(stat.dev, stat.ino))
        && let Some(record) = state.nodes.get_mut(&id)
    {
        record.node.repoint(&parent, &name);
    }
}

fn clear_node_path(state: &mut State, stat: &host::Stat) {
    if let Some(&id) = state.node_id_by_identity.get(&(stat.dev, stat.ino))
        && let Some(record) = state.nodes.get_mut(&id)
    {
        record.node.clear_path();
    }
}

fn increment_lookup(state: &mut State, id: u64) {
    if let Some(record) = state.nodes.get_mut(&id) {
        record.lookups = record.lookups.saturating_add(1);
        state.unused_nodes.remove(&id);
    }
}

fn directory(state: &State, handle: u64) -> Result<&OpenDirectory, DeviceError> {
    state
        .directories
        .iter()
        .find_map(|(known, directory)| (*known == handle).then_some(directory))
        .ok_or(DeviceError::Io)
}

fn handle(state: &State, id: u64) -> Result<&OpenHandle, DeviceError> {
    state
        .handles
        .iter()
        .find(|handle| handle.id == id)
        .ok_or(DeviceError::Io)
}

fn name(bytes: &[u8]) -> Result<Vec<u8>, i32> {
    let name = bytes.split(|byte| *byte == 0).next().ok_or(wire::EINVAL)?;
    if name.is_empty() || name.len() == bytes.len() || name.contains(&b'/') {
        return Err(wire::EINVAL);
    }
    Ok(name.to_vec())
}

fn names(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let split = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(wire::EINVAL)?;
    Ok((name(&bytes[..=split])?, name(&bytes[split + 1..])?))
}

fn symlink_parts(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), i32> {
    let split = bytes
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(wire::EINVAL)?;
    let target = bytes.get(split + 1..).ok_or(wire::EINVAL)?;
    let target = target.strip_suffix(&[0]).ok_or(wire::EINVAL)?;
    if target.contains(&0) {
        return Err(wire::EINVAL);
    }
    Ok((name(&bytes[..=split])?, target.to_vec()))
}

fn host_error(error: host::Error) -> i32 {
    match error {
        host::Error::Access => 13,
        host::Error::Exist => 17,
        host::Error::Invalid => wire::EINVAL,
        host::Error::IllegalByteSequence => 84,
        host::Error::Io => 5,
        host::Error::IsDirectory => 21,
        host::Error::Loop => 40,
        host::Error::NoEntry => 2,
        host::Error::NotDirectory => 20,
        host::Error::NotEmpty => 39,
        host::Error::ReadOnly => 30,
        host::Error::Unsupported => 95,
        host::Error::Exhausted => 24,
        host::Error::NoSpace => 28,
        host::Error::Quota => 122,
        host::Error::TooLarge => 27,
    }
}

#[allow(clippy::needless_pass_by_value)]
fn wasi_error(error: crate::wasi::filesystem::types::ErrorCode) -> i32 {
    use crate::wasi::filesystem::types::ErrorCode;
    match error {
        ErrorCode::Access => 13,
        ErrorCode::Already => 114,
        ErrorCode::BadDescriptor => 9,
        ErrorCode::Busy => 16,
        ErrorCode::Deadlock => 35,
        ErrorCode::Quota => 122,
        ErrorCode::Exist => 17,
        ErrorCode::FileTooLarge => 27,
        ErrorCode::IllegalByteSequence => 84,
        ErrorCode::InProgress => 115,
        ErrorCode::Interrupted => 4,
        ErrorCode::Invalid => wire::EINVAL,
        ErrorCode::Io | ErrorCode::Other(_) => 5,
        ErrorCode::IsDirectory => 21,
        ErrorCode::Loop => 40,
        ErrorCode::TooManyLinks => 31,
        ErrorCode::MessageSize => 90,
        ErrorCode::NameTooLong => 36,
        ErrorCode::NoDevice => 19,
        ErrorCode::NoEntry => 2,
        ErrorCode::NoLock => 37,
        ErrorCode::InsufficientMemory => 12,
        ErrorCode::InsufficientSpace => 28,
        ErrorCode::NotDirectory => 20,
        ErrorCode::NotEmpty => 39,
        ErrorCode::NotRecoverable => 131,
        ErrorCode::Unsupported => 95,
        ErrorCode::NoTty => 25,
        ErrorCode::NoSuchDevice => 6,
        ErrorCode::Overflow => 75,
        ErrorCode::NotPermitted => 1,
        ErrorCode::Pipe => 32,
        ErrorCode::ReadOnly => 30,
        ErrorCode::InvalidSeek => 29,
        ErrorCode::TextFileBusy => 26,
        ErrorCode::CrossDevice => 18,
    }
}

fn stable_inode(stat: &host::Stat) -> u64 {
    stat.ino
}

fn flush_body(body: &[u8]) -> Result<(), i32> {
    (body.len() == 24).then_some(()).ok_or(wire::EINVAL)
}

fn attr(stat: &host::Stat) -> Vec<u8> {
    let mut out = vec![0; 88];
    out[0..8].copy_from_slice(&stable_inode(stat).to_le_bytes());
    out[8..16].copy_from_slice(&stat.size.to_le_bytes());
    out[16..24].copy_from_slice(&stat.blocks.to_le_bytes());
    out[24..32].copy_from_slice(
        &u64::try_from(stat.atime.seconds)
            .unwrap_or_default()
            .to_le_bytes(),
    );
    out[32..40].copy_from_slice(
        &u64::try_from(stat.mtime.seconds)
            .unwrap_or_default()
            .to_le_bytes(),
    );
    out[40..48].copy_from_slice(
        &u64::try_from(stat.ctime.seconds)
            .unwrap_or_default()
            .to_le_bytes(),
    );
    out[48..52].copy_from_slice(&stat.atime.nanoseconds.to_le_bytes());
    out[52..56].copy_from_slice(&stat.mtime.nanoseconds.to_le_bytes());
    out[56..60].copy_from_slice(&stat.ctime.nanoseconds.to_le_bytes());
    out[60..64].copy_from_slice(&stat.mode.to_le_bytes());
    out[64..68].copy_from_slice(&u32::try_from(stat.nlink).unwrap_or(u32::MAX).to_le_bytes());
    out[68..72].copy_from_slice(&stat.uid.to_le_bytes());
    out[72..76].copy_from_slice(&stat.gid.to_le_bytes());
    out
}

fn attr_out(stat: &host::Stat) -> Vec<u8> {
    let mut out = vec![0; 16];
    out.extend_from_slice(&attr(stat));
    out
}

fn entry(stat: &host::Stat, node: u64) -> Vec<u8> {
    let mut out = vec![0; 128];
    out[..8].copy_from_slice(&node.to_le_bytes());
    out[40..].copy_from_slice(&attr(stat));
    out
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, i32> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(wire::EINVAL)?
            .try_into()
            .map_err(|_| wire::EINVAL)?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, i32> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(wire::EINVAL)?
            .try_into()
            .map_err(|_| wire::EINVAL)?,
    ))
}

fn dirent_type(mode: u32) -> u32 {
    match mode & 0o170_000 {
        0o040_000 => 4,
        0o120_000 => 10,
        _ => 8,
    }
}

fn timestamp(seconds: u64, nanoseconds: u32) -> host::Timestamp {
    host::Timestamp {
        seconds: i64::try_from(seconds).unwrap_or(i64::MAX),
        nanoseconds,
    }
}

fn dirents(entries: Vec<host::DirectoryEntry>, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        let size = 24_usize.saturating_add(entry.name.len());
        let padded = (size + 7) & !7;
        if padded > max.saturating_sub(out.len()) {
            break;
        }
        out.extend_from_slice(&stable_inode(&entry.stat).to_le_bytes());
        out.extend_from_slice(&entry.next.to_le_bytes());
        out.extend_from_slice(
            &u32::try_from(entry.name.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        out.extend_from_slice(&dirent_type(entry.stat.mode).to_le_bytes());
        out.extend_from_slice(&entry.name);
        out.resize(out.len() + padded - size, 0);
    }
    out
}

fn open(inode: u64) -> Vec<u8> {
    let mut out = vec![0; 16];
    out[..8].copy_from_slice(&inode.to_le_bytes());
    out
}

fn sized_out(size: u32) -> Vec<u8> {
    let mut out = vec![0; 8];
    out[..4].copy_from_slice(&size.to_le_bytes());
    out
}

fn create_flags(flags: u32) -> Result<host::CreateFlags, i32> {
    const O_CREAT: u32 = 0o100;
    const O_NONBLOCK: u32 = 0o4000;
    const O_LARGEFILE: u32 = 0o100_000;
    const O_DIRECTORY: u32 = 0o200_000;
    const O_NOFOLLOW: u32 = 0o400_000;
    const O_CLOEXEC: u32 = 0o2_000_000;
    const FMODE_EXEC: u32 = 0x20;
    if flags
        & !(3
            | O_CREAT
            | 0o200
            | 0o1000
            | 0o2000
            | O_NONBLOCK
            | O_LARGEFILE
            | O_DIRECTORY
            | O_NOFOLLOW
            | O_CLOEXEC
            | FMODE_EXEC)
        != 0
        || flags & O_DIRECTORY != 0
    {
        return Err(wire::EINVAL);
    }
    match flags & 3 {
        0..=2 => {}
        _ => return Err(wire::EINVAL),
    }
    let mut result = host::CreateFlags::NONE;
    if flags & 0o1000 != 0 {
        result |= host::CreateFlags::TRUNCATE;
    }
    if flags & 0o200 != 0 {
        result |= host::CreateFlags::EXCLUSIVE;
    }
    Ok(result)
}

fn open_flags(flags: u32) -> Result<(host::OpenFlags, bool), i32> {
    const O_NONBLOCK: u32 = 0o4000;
    const O_LARGEFILE: u32 = 0o100_000;
    const O_DIRECTORY: u32 = 0o200_000;
    const O_NOFOLLOW: u32 = 0o400_000;
    const O_CLOEXEC: u32 = 0o2_000_000;
    const FMODE_EXEC: u32 = 0x20;
    if flags
        & !(3
            | 0o1000
            | 0o2000
            | O_NONBLOCK
            | O_LARGEFILE
            | O_DIRECTORY
            | O_NOFOLLOW
            | O_CLOEXEC
            | FMODE_EXEC)
        != 0
    {
        return Err(wire::EINVAL);
    }
    if flags & O_DIRECTORY != 0 {
        return Err(wire::EINVAL);
    }
    let (mut access, writable) = match flags & 3 {
        0 => (host::OpenFlags::READ, false),
        1 => (host::OpenFlags::WRITE, true),
        2 => (host::OpenFlags::READ | host::OpenFlags::WRITE, true),
        _ => return Err(wire::EINVAL),
    };
    if flags & 0o1000 != 0 {
        access |= host::OpenFlags::TRUNCATE;
    }
    Ok((access, writable))
}

fn store_handle(
    state: &mut State,
    node: u64,
    descriptor: std::sync::Arc<crate::wasi::filesystem::types::Descriptor>,
    writable: bool,
) -> Result<u64, i32> {
    if state.handles.len() == MAX_HANDLES {
        return Err(24);
    }
    let id = state.next_handle;
    state.next_handle = state.next_handle.wrapping_add(1).max(2);
    state.handles.push(OpenHandle {
        id,
        node,
        writable,
        descriptor,
    });
    state.unused_nodes.remove(&node);
    Ok(id)
}

fn statfs(stat: &host::Statfs) -> Vec<u8> {
    let mut out = vec![0; 80];
    out[0..8].copy_from_slice(&stat.blocks.to_le_bytes());
    out[8..16].copy_from_slice(&stat.blocks_free.to_le_bytes());
    out[16..24].copy_from_slice(&stat.blocks_available.to_le_bytes());
    out[24..32].copy_from_slice(&stat.files.to_le_bytes());
    out[32..40].copy_from_slice(&stat.files_free.to_le_bytes());
    out[40..44].copy_from_slice(&stat.block_size.to_le_bytes());
    out[44..48].copy_from_slice(&stat.name_max.to_le_bytes());
    out[48..52].copy_from_slice(&stat.block_size.to_le_bytes());
    out
}

fn rename_mode(flags: u32) -> Result<host::RenameMode, i32> {
    match flags {
        0 => Ok(host::RenameMode::Replace),
        1 => Ok(host::RenameMode::NoReplace),
        2 => Ok(host::RenameMode::Exchange),
        _ => Err(wire::ENOSYS),
    }
}

async fn read_file(
    descriptor: &crate::wasi::filesystem::types::Descriptor,
    offset: u64,
    size: usize,
) -> Result<Vec<u8>, i32> {
    let (mut stream, completion) = descriptor.read_via_stream(offset);
    let mut bytes = Vec::with_capacity(size);
    while bytes.len() < size {
        let before = bytes.len();
        let (result, next) = stream.read(bytes).await;
        bytes = next;
        match result {
            wit_bindgen::rt::async_support::StreamResult::Complete(read) => {
                if !read_progressed(before, bytes.len(), read)? {
                    break;
                }
            }
            wit_bindgen::rt::async_support::StreamResult::Dropped => break,
            wit_bindgen::rt::async_support::StreamResult::Cancelled => return Err(5),
        }
    }
    drop(stream);
    match completion.await {
        Ok(()) => Ok(bytes),
        Err(_) => Err(5),
    }
}

fn read_progressed(before: usize, after: usize, read: usize) -> Result<bool, i32> {
    if read == 0 {
        return Ok(false);
    }
    (after.checked_sub(before) == Some(read))
        .then_some(true)
        .ok_or(5)
}

async fn write_file(
    descriptor: &crate::wasi::filesystem::types::Descriptor,
    offset: u64,
    bytes: Vec<u8>,
) -> Result<(), i32> {
    let (mut writer, reader) = crate::wit_stream::new::<u8>();
    let completion = descriptor.write_via_stream(reader, offset);
    let remaining = writer.write_all(bytes).await;
    drop(writer);
    if remaining.is_empty() && completion.await.is_ok() {
        Ok(())
    } else {
        Err(5)
    }
}

fn at(base: u64, offset: u64) -> Result<u64, DeviceError> {
    base.checked_add(offset).ok_or(DeviceError::Unmapped)
}

fn read(addr: u64, len: usize) -> Result<Vec<u8>, DeviceError> {
    if len > MAX_REQUEST {
        return Err(DeviceError::TooLarge);
    }
    let mut out = Vec::with_capacity(len);
    for offset in (0..len).step_by(MAX_COPY) {
        let count = (len - offset).min(MAX_COPY);
        let address = at(
            addr,
            u64::try_from(offset).map_err(|_| DeviceError::TooLarge)?,
        )?;
        let bytes = memory::read(
            address,
            u64::try_from(count).map_err(|_| DeviceError::TooLarge)?,
        )
        .map_err(|_| DeviceError::Unmapped)?;
        if bytes.len() != count {
            return Err(DeviceError::Io);
        }
        out.extend(bytes);
    }
    Ok(out)
}

fn write(addr: u64, bytes: &[u8]) -> Result<(), DeviceError> {
    if bytes.len() > MAX_REQUEST {
        return Err(DeviceError::TooLarge);
    }
    for (offset, chunk) in bytes.chunks(MAX_COPY).enumerate() {
        let offset = offset.checked_mul(MAX_COPY).ok_or(DeviceError::TooLarge)?;
        memory::write(
            at(
                addr,
                u64::try_from(offset).map_err(|_| DeviceError::TooLarge)?,
            )?,
            chunk,
        )
        .map_err(|_| DeviceError::Unmapped)?;
    }
    Ok(())
}

fn available(queue: usize) -> Result<Option<(u16, u64, u64, u16)>, DeviceError> {
    let (desc, avail, used, size, next, generation) = transport(|transport| {
        if transport.mmio.negotiated() & VIRTIO_F_VERSION_1 == 0 {
            return Err(DeviceError::NotReady);
        }
        let (desc, avail, used, size) = transport
            .mmio
            .queue_addrs_for(queue)
            .ok_or(DeviceError::NotReady)?;
        Ok((
            desc,
            avail,
            used,
            size,
            transport.next[queue],
            transport.generation,
        ))
    })?;
    let mut next = next;
    let ring_size = core::num::NonZeroU16::new(size).ok_or(DeviceError::BadLen)?;
    let head = read_split_ring_available_head(avail, ring_size, &mut next, at, |address| {
        Ok(u16::from_le_bytes(
            read(address, 2)?
                .try_into()
                .map_err(|_| DeviceError::BadLen)?,
        ))
    })?;
    if !transport(|transport| {
        if generation != transport.generation {
            return Ok(false);
        }
        transport.next[queue] = next;
        Ok(true)
    })? {
        return Ok(None);
    }
    Ok(head.map(|head| (head, desc, used, size)))
}

fn complete(queue: usize, head: u16, used: u32) -> Result<(), DeviceError> {
    let (used_ring, size) = transport(|transport| {
        let (_, _, used_ring, size) = transport
            .mmio
            .queue_addrs_for(queue)
            .ok_or(DeviceError::NotReady)?;
        Ok((used_ring, size))
    })?;
    complete_split_ring_entry(
        used_ring,
        core::num::NonZeroU16::new(size).ok_or(DeviceError::BadLen)?,
        head,
        used,
        at,
        |address| {
            Ok(u16::from_le_bytes(
                read(address, 2)?
                    .try_into()
                    .map_err(|_| DeviceError::BadLen)?,
            ))
        },
        write,
    )?;
    transport(|transport| {
        transport.mmio.signal(INT_USED_BUFFER);
        Ok(())
    })?;
    interrupt::signal();
    Ok(())
}

#[allow(clippy::needless_pass_by_value)]
fn reply(
    queue: usize,
    head: u16,
    output: &[Descriptor],
    payload: Vec<u8>,
) -> Result<(), DeviceError> {
    let mut copied = 0_usize;
    for descriptor in output {
        if copied == payload.len() {
            break;
        }
        let available = usize::try_from(descriptor.len).map_err(|_| DeviceError::TooLarge)?;
        let end = copied.saturating_add(available).min(payload.len());
        write(descriptor.addr, &payload[copied..end])?;
        copied = end;
    }
    if copied != payload.len() {
        return Err(DeviceError::TooLarge);
    }
    complete(
        queue,
        head,
        u32::try_from(payload.len()).map_err(|_| DeviceError::TooLarge)?,
    )
}

fn forget_request(state: &mut State, request: &wire::Request<'_>) -> Result<(), i32> {
    match request.opcode {
        wire::FORGET => forget(state, request.node, u64_at(request.body, 0).unwrap_or(0)),
        wire::FORGET_MULTI => {
            let count = usize::try_from(u32_at(request.body, 0)?).map_err(|_| wire::EINVAL)?;
            if count > MAX_NODES || request.body.len() != 8 + count.saturating_mul(16) {
                return Err(wire::EINVAL);
            }
            for offset in (8..request.body.len()).step_by(16) {
                forget(
                    state,
                    u64_at(request.body, offset)?,
                    u64_at(request.body, offset + 8)?,
                );
            }
        }
        _ => return Err(wire::EINVAL),
    }
    Ok(())
}

struct RequestBuffers {
    input: Vec<u8>,
    output: Vec<Descriptor>,
}

fn read_request_buffers(desc: u64, head: u16, size: u16) -> Result<RequestBuffers, DeviceError> {
    let table = read(
        desc,
        usize::from(size) * terra_device_transport::SPLIT_RING_DESCRIPTOR_BYTES,
    )?;
    let chain = split_ring_chain(
        &table,
        head,
        size,
        MAX_CHAIN,
        SPLIT_RING_DESC_F_NEXT | WRITE,
    )
    .map_err(|_| DeviceError::BadLen)?;
    let (input, output) = chain.split_at(
        chain
            .iter()
            .position(|descriptor| descriptor.flags & WRITE != 0)
            .unwrap_or(chain.len()),
    );
    if input.is_empty()
        || output
            .iter()
            .any(|descriptor| descriptor.flags & WRITE == 0)
    {
        return Err(DeviceError::BadLen);
    }
    let mut request = Vec::new();
    for descriptor in input {
        let length = usize::try_from(descriptor.len).map_err(|_| DeviceError::TooLarge)?;
        if length > MAX_REQUEST.saturating_sub(request.len()) {
            return Err(DeviceError::TooLarge);
        }
        request.extend(read(descriptor.addr, length)?);
    }
    Ok(RequestBuffers {
        input: request,
        output: output.to_vec(),
    })
}

fn cancel_event_request(state: &mut State) -> Result<(), DeviceError> {
    state.events_enabled = false;
    if let Some(pending) = state.event_request.take() {
        let _completion = COMPLETION_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if generation()? == pending.generation {
            reply(
                pending.queue,
                pending.head,
                &pending.output,
                wire::reply(pending.unique, 19, &[]),
            )?;
        }
    }
    Ok(())
}

fn remember_lookup(state: &mut State, request: &wire::Request<'_>, response: &[u8]) {
    if let (Ok(name), Ok(child)) = (name(request.body), u64_at(response, 0)) {
        if state.event_entries.len() == MAX_NODES {
            state.event_entries.pop_first();
        }
        let key = (request.node, name);
        if state
            .event_entries
            .get(&key)
            .is_none_or(|id| state.nodes.get(id).is_none_or(|record| record.lookups == 0))
        {
            state.event_entries.insert(key, child);
        }
    }
}

fn process_request(
    state: &mut State,
    scheduler: &mut io::IoScheduler,
    queue: usize,
) -> Result<bool, DeviceError> {
    let request_generation = generation()?;
    let Some((head, desc, _, size)) = available(queue)? else {
        return Ok(false);
    };
    transport(|transport| {
        transport.next[queue] = transport.next[queue].wrapping_add(1);
        Ok(())
    })?;
    let malformed =
        || complete(queue, head, 0).and_then(|()| available(queue).map(|next| next.is_some()));
    let Ok(RequestBuffers {
        input: request,
        output,
    }) = read_request_buffers(desc, head, size)
    else {
        return malformed();
    };
    let parsed = wire::request(&request);

    if let Ok(request) = &parsed
        && matches!(request.opcode, wire::FORGET | wire::FORGET_MULTI)
    {
        if forget_request(state, request).is_err() {
            return malformed();
        }
        let _completion = COMPLETION_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if request_generation != generation()? {
            clear_runtime(state);
            return Ok(false);
        }
        complete(queue, head, 0)?;
        return available(queue).map(|next| next.is_some());
    }
    if output.is_empty() {
        return malformed();
    }
    if let Ok(request) = &parsed
        && request.opcode == wire::RECEIVE_EVENT
        && state.events_enabled
        && state.event_request.is_none()
        && request.node == 1
        && request.body.is_empty()
        && output
            .iter()
            .map(|descriptor| u64::from(descriptor.len))
            .sum::<u64>()
            >= 296
    {
        state.event_request = Some(PendingReply {
            queue,
            head,
            output,
            unique: request.unique,
            generation: request_generation,
        });
        return available(queue).map(|next| next.is_some());
    }
    if let Ok(request) = &parsed
        && request.opcode == wire::CANCEL_EVENTS
    {
        cancel_event_request(state)?;
    }
    let response = match &parsed {
        Ok(request) => {
            let target = PendingReply {
                queue,
                head,
                output: output.clone(),
                unique: request.unique,
                generation: request_generation,
            };
            let Some(response) = execute_request(state, scheduler, request, target) else {
                return available(queue).map(|next| next.is_some());
            };
            response
        }
        Err(errno) => wire::reply(0, *errno, &[]),
    };
    let _completion = COMPLETION_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if request_generation != generation()? {
        clear_runtime(state);
        return Ok(false);
    }
    if reply(queue, head, &output, response).is_err() {
        return malformed();
    }
    available(queue).map(|next| next.is_some())
}

fn execute_request(
    state: &mut State,
    scheduler: &mut io::IoScheduler,
    request: &wire::Request<'_>,
    target: PendingReply,
) -> Option<Vec<u8>> {
    if request.opcode == wire::INIT && scheduler.contains_generation(target.generation) {
        return Some(wire::reply(request.unique, 16, &[]));
    }
    let result = if let Some(result) = requests::execute_immediate(state, request) {
        result
    } else {
        match requests::prepare_io(state, request, target.generation)
            .and_then(|operation| scheduler.enqueue(operation, target))
        {
            Ok(()) => return None,
            Err(errno) => Err(errno),
        }
    };
    Some(encode_response(request.unique, result))
}

fn dispatch_event(state: &mut State, payload: &[u8]) {
    let Some(request) = state.event_request.take() else {
        return;
    };
    let _completion = COMPLETION_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if generation().ok() == Some(request.generation) {
        let _ = reply(
            request.queue,
            request.head,
            &request.output,
            wire::reply(request.unique, 0, payload),
        );
    }
}

async fn encode_event(
    state: requests::RequestState,
    event: crate::terra::fs::host::FileEvent,
) -> Option<Vec<u8>> {
    use crate::terra::fs::host::EventKind;
    let mut parts = event.path.split('/').collect::<Vec<_>>();
    if parts
        .iter()
        .any(|part| part.is_empty() || matches!(*part, "." | "..") || part.contains('\0'))
    {
        return None;
    }
    let name = parts.pop()?;
    if name.len() > 255 {
        return None;
    }
    let mut parent = host::root().ok()?;
    for part in parts {
        parent = host::lookup(&parent, part.as_bytes().to_vec()).await.ok()?;
    }
    let stat = parent.stat().await.ok()?;
    let (id, child) = state
        .with(|state| {
            let id = *state
                .node_id_by_identity
                .get(&(stat.dev, stat.ino))
                .ok_or(2)?;
            let child = state
                .event_entries
                .get(&(id, name.as_bytes().to_vec()))
                .copied()
                .unwrap_or(0);
            Ok((id, child))
        })
        .ok()?;
    let identity = if child != 0 && matches!(event.kind, EventKind::Modify | EventKind::Metadata) {
        parent.child_identity(name).await.ok()
    } else {
        None
    };
    let same_inode = state
        .with(|state| {
            let same_inode = identity.is_some_and(|identity| {
                state
                    .node_id_by_identity
                    .get(&(identity.upper, identity.lower))
                    == Some(&child)
            });
            if !same_inode {
                state.event_entries.remove(&(id, name.as_bytes().to_vec()));
            }
            Ok(same_inode)
        })
        .ok()?;
    let kind: u32 = match event.kind {
        EventKind::Create => 1,
        EventKind::Remove => 2,
        EventKind::Modify => 3,
        EventKind::Metadata => 4,
    } | if event.is_directory { 0x100 } else { 0 }
        | if same_inode {
            wire::EVENT_SAME_INODE
        } else {
            0
        };
    let mut payload = vec![0; 280];
    payload[..8].copy_from_slice(&id.to_le_bytes());
    payload[8..16].copy_from_slice(&child.to_le_bytes());
    payload[16..20].copy_from_slice(&kind.to_le_bytes());
    payload[20..24].copy_from_slice(&u32::try_from(name.len()).ok()?.to_le_bytes());
    payload[24..24 + name.len()].copy_from_slice(name.as_bytes());
    Some(payload)
}

pub async fn configure(tag: &str, max_nodes: u32) -> Result<(), DeviceError> {
    let max_nodes = usize::try_from(max_nodes).map_err(|_| DeviceError::BadLen)?;
    if tag.is_empty() || tag.len() > 36 || !(1..=MAX_NODES).contains(&max_nodes) {
        return Err(DeviceError::BadLen);
    }
    let mut config = vec![0; 40];
    config[..tag.len()].copy_from_slice(tag.as_bytes());
    config[36..40].copy_from_slice(&1_u32.to_le_bytes());
    let root = host::root().map_err(|_| DeviceError::Io)?;
    let root_stat = root.stat().await.map_err(|_| DeviceError::Io)?;
    *STATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(State {
        event_request: None,
        event_entries: std::collections::BTreeMap::new(),
        events_enabled: false,
        max_nodes,
        nodes: std::collections::BTreeMap::from([(
            1,
            NodeRecord {
                id: 1,
                dev: root_stat.dev,
                ino: root_stat.ino,
                lookups: 1,
                node: root,
            },
        )]),
        node_id_by_identity: std::collections::BTreeMap::from([(
            (root_stat.dev, root_stat.ino),
            1,
        )]),
        unused_nodes: std::collections::BTreeSet::new(),
        handles: Vec::new(),
        directories: Vec::new(),
        next_handle: 2,
        next_node: 2,
    });
    *TRANSPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(new_transport(memory::address_limit(), config));
    publish_interrupt_level(false);
    clear_work();
    RUNNING.store(true, Ordering::Release);
    Ok(())
}

fn new_transport(ram_size: u64, config: Vec<u8>) -> Transport {
    Transport {
        mmio: MmioTransport::new(
            0,
            0x200,
            ram_size,
            DEVICE_ID,
            VIRTIO_F_VERSION_1,
            QUEUE_SIZE,
            config,
        )
        .with_queue_count(2),
        next: [0; 2],
        generation: 0,
    }
}

pub fn mmio_read(addr: u64, len: u32) -> Result<Vec<u8>, DeviceError> {
    transport(|transport| {
        transport
            .mmio
            .read(addr, usize::try_from(len).map_err(|_| DeviceError::BadLen)?)
            .map_err(error)
    })
}

fn clear_runtime(state: &mut State) {
    state.event_request = None;
    state.event_entries.clear();
    state.events_enabled = false;
    state.handles.clear();
    state.directories.clear();
    state.nodes.retain(|_, record| record.id == 1);
    state.node_id_by_identity.retain(|_, id| *id == 1);
    state.unused_nodes.clear();
    state.next_handle = 2;
    state.next_node = 2;
}

fn resets_transport(addr: u64, data: &[u8]) -> bool {
    addr == STATUS
        && data.first().is_some_and(|status| {
            *status == 0 || *status & terra_device_transport::STATUS_FAILED != 0
        })
}

pub fn mmio_write(addr: u64, data: &[u8]) -> Result<bool, DeviceError> {
    let resets = resets_transport(addr, data);
    let _completion = resets.then(|| {
        COMPLETION_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    });
    let bell = transport(|transport| {
        let reset = transport.mmio.reset_generation();
        let bell = transport.mmio.write(addr, data).map_err(error)?;
        if reset != transport.mmio.reset_generation() {
            transport.generation = transport.generation.wrapping_add(1);
            transport.next = [0; 2];
            clear_work();
            WORK_WAKER.wake();
        }
        Ok(bell.map(usize::from))
    })?;
    if let Some(queue) = bell {
        if queue >= 2 {
            return Err(DeviceError::BadQueue);
        }
        queue_work(queue);
        return Ok(true);
    }
    Ok(false)
}

fn encode_response(unique: u64, result: Result<Vec<u8>, i32>) -> Vec<u8> {
    match result {
        Ok(body) => wire::reply(unique, 0, &body),
        Err(errno) => wire::reply(unique, errno, &[]),
    }
}

fn complete_io(completed: io::CompletedIo) {
    let target = completed.reply;
    let _completion = COMPLETION_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if generation().ok() == Some(target.generation)
        && reply(
            target.queue,
            target.head,
            &target.output,
            encode_response(target.unique, completed.result),
        )
        .is_err()
    {
        let _ = complete(target.queue, target.head, 0);
    }
}

struct ReadyWork {
    completed: Option<io::CompletedIo>,
    event: Poll<Option<crate::terra::fs::host::FileEvent>>,
    queue: Option<usize>,
}

fn poll_work(
    context: &mut Context<'_>,
    scheduler: &mut io::IoScheduler,
    events: &mut (impl futures::Stream<Item = crate::terra::fs::host::FileEvent> + Unpin),
    can_receive_event: bool,
    current_generation: u64,
) -> Poll<ReadyWork> {
    WORK_WAKER.register(context.waker());
    let completed = scheduler.poll_complete(context);
    let event = if can_receive_event {
        events.poll_next_unpin(context)
    } else {
        Poll::Pending
    };
    let queue = take_work();
    if completed.is_some()
        || event.is_ready()
        || queue.is_some()
        || !RUNNING.load(Ordering::Acquire)
        || generation().ok() != Some(current_generation)
    {
        Poll::Ready(ReadyWork {
            completed,
            event,
            queue,
        })
    } else {
        Poll::Pending
    }
}

struct EventWork {
    generation: u64,
    unique: u64,
    work: futures::future::LocalBoxFuture<'static, Option<Vec<u8>>>,
}

fn poll_event(context: &mut Context<'_>, pending: &mut Option<EventWork>) {
    let Some(event) = pending.as_mut() else {
        return;
    };
    let Poll::Ready(payload) = event.work.poll_unpin(context) else {
        return;
    };
    let _ = requests::RequestState(event.generation).with(|state| {
        if state
            .event_request
            .as_ref()
            .is_some_and(|request| request.unique == event.unique)
            && let Some(payload) = payload
        {
            dispatch_event(state, &payload);
        }
        Ok(())
    });
    *pending = None;
    context.waker().wake_by_ref();
}

pub async fn run() -> Result<(), DeviceError> {
    let mut events = crate::terra::fs::host::file_events().into_stream();
    let mut events_closed = false;
    let mut pending_event = None;
    let mut event_work = None;
    let mut scheduler = io::IoScheduler::default();
    let Ok(mut current_generation) = generation() else {
        return Ok(());
    };
    while RUNNING.load(Ordering::Acquire) {
        let Ok(observed_generation) = generation() else {
            break;
        };
        if observed_generation != current_generation {
            scheduler.discard_pending();
            pending_event = None;
            if let Some(state) = STATE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
            {
                clear_runtime(state);
            }
            current_generation = observed_generation;
        }
        if event_work.is_none() {
            let state = STATE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(state) = state.as_ref() {
                if let Some(request) = state.event_request.as_ref() {
                    if let Some(event) = pending_event.take() {
                        event_work = Some(EventWork {
                            generation: current_generation,
                            unique: request.unique,
                            work: encode_event(requests::RequestState(current_generation), event)
                                .boxed_local(),
                        });
                    }
                } else if !state.events_enabled {
                    pending_event = None;
                }
            }
        }
        let ReadyWork {
            completed,
            event,
            queue,
        } = poll_fn(|context| {
            poll_event(context, &mut event_work);
            poll_work(
                context,
                &mut scheduler,
                &mut events,
                pending_event.is_none() && !events_closed && event_work.is_none(),
                current_generation,
            )
        })
        .await;
        if let Some(completed) = completed {
            complete_io(completed);
        }
        match event {
            Poll::Ready(Some(event)) => pending_event = Some(event),
            Poll::Ready(None) => events_closed = true,
            Poll::Pending => {}
        }
        if !RUNNING.load(Ordering::Acquire) {
            continue;
        }
        if generation().ok() != Some(current_generation) {
            if let Some(queue) = queue {
                queue_work(queue);
            }
            continue;
        }
        let Some(queue) = queue else {
            continue;
        };
        let mut state = STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pending = match state.as_mut() {
            // An unaddressable ring cannot be completed; wait for reset or another doorbell.
            Some(state) => process_request(state, &mut scheduler, queue).unwrap_or(false),
            None => false,
        };
        drop(state);
        if pending {
            let _ = queue_work_if_current(queue, current_generation);
        }
    }
    Ok(())
}

pub fn interrupt_level() -> bool {
    transport(|transport| Ok(transport.mmio.read(0x60, 4).map_err(error)? != [0, 0, 0, 0]))
        .unwrap_or(false)
}

pub fn reset() {
    let _completion = COMPLETION_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    invalidate_transport();
    clear_work();
    WORK_WAKER.wake();
}

fn invalidate_transport() {
    let _ = transport(reset_transport);
}

fn reset_transport(transport: &mut Transport) -> Result<(), DeviceError> {
    transport.generation = transport.generation.wrapping_add(1);
    transport.next = [0; 2];
    transport.mmio.write(STATUS, &[0; 4]).map_err(error)?;
    Ok(())
}

pub async fn close() -> Result<(), DeviceError> {
    {
        let _completion = COMPLETION_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        invalidate_transport();
    }
    RUNNING.store(false, Ordering::Release);
    clear_work();
    WORK_WAKER.wake();
    *TRANSPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    let flush = async {
        let state = STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        let mut result = Ok(());
        if let Some(state) = state {
            for handle in state.handles.iter().filter(|handle| handle.writable) {
                if handle.descriptor.sync_data().await.is_err() {
                    result = Err(DeviceError::Io);
                }
            }
        }
        result
    };
    let deadline = crate::wasi::clocks::monotonic_clock::wait_for(CLOSE_FLUSH_TIMEOUT);
    futures::pin_mut!(flush, deadline);
    match futures::future::select(flush, deadline).await {
        futures::future::Either::Left((result, _)) => result,
        futures::future::Either::Right(((), _)) => Err(DeviceError::Io),
    }
}

#[cfg(test)]
mod allocation_tests {
    use super::*;

    #[test]
    fn busy_request_queue_does_not_starve_events_or_io_completions() {
        use futures::FutureExt;
        let waker = futures::task::noop_waker();
        let mut context = Context::from_waker(&waker);
        let mut scheduler = io::IoScheduler::default();
        let mut events = futures::stream::repeat_with(|| crate::terra::fs::host::FileEvent {
            path: "changed".into(),
            kind: crate::terra::fs::host::EventKind::Modify,
            is_directory: false,
        });
        for unique in 0..32 {
            queue_work(REQUEST_QUEUE);
            scheduler
                .enqueue(
                    io::PreparedIo {
                        identity: (0, unique),
                        work: async { Ok(Vec::new()) }.boxed_local(),
                    },
                    PendingReply {
                        queue: REQUEST_QUEUE,
                        head: 0,
                        output: Vec::new(),
                        unique,
                        generation: 0,
                    },
                )
                .unwrap();
            let Poll::Ready(ready) = poll_work(&mut context, &mut scheduler, &mut events, true, 0)
            else {
                panic!("queued work must be ready");
            };
            assert_eq!(ready.queue, Some(REQUEST_QUEUE));
            assert!(matches!(ready.event, Poll::Ready(Some(_))));
            assert_eq!(ready.completed.unwrap().reply.unique, unique);
        }
    }

    #[test]
    fn reset_discards_pending_indices_and_interrupts() {
        let mut transport = Transport {
            mmio: MmioTransport::new(
                0,
                0x200,
                65536,
                DEVICE_ID,
                VIRTIO_F_VERSION_1,
                QUEUE_SIZE,
                Vec::new(),
            )
            .with_queue_count(2),
            next: [3, 7],
            generation: 11,
        };
        transport.mmio.signal(INT_USED_BUFFER);
        reset_transport(&mut transport).unwrap();
        assert_eq!(transport.generation, 12);
        assert_eq!(transport.next, [0, 0]);
        assert_eq!(transport.mmio.read(0x60, 4).unwrap(), [0; 4]);
    }

    #[test]
    fn status_reset_detection_matches_transport_status_writes() {
        assert!(resets_transport(STATUS, &[0, 1, 0, 0]));
        assert!(resets_transport(
            STATUS,
            &[terra_device_transport::STATUS_FAILED]
        ));
        assert!(!resets_transport(STATUS, &[1, 0, 0, 0]));
        assert!(!resets_transport(STATUS, &[]));
    }

    #[test]
    fn keeps_directory_error_kinds() {
        assert_eq!(host_error(host::Error::IsDirectory), 21);
        assert_eq!(host_error(host::Error::Loop), 40);
        assert_eq!(host_error(host::Error::NotDirectory), 20);
    }

    #[test]
    fn attr_out_has_its_cache_timeout_prefix() {
        let timestamp = host::Timestamp {
            seconds: 0,
            nanoseconds: 0,
        };
        let stat = host::Stat {
            dev: 0,
            ino: 9,
            mode: 0,
            nlink: 0,
            uid: 0,
            gid: 0,
            size: 0,
            blocks: 0,
            atime: timestamp,
            mtime: timestamp,
            ctime: timestamp,
        };
        let out = attr_out(&stat);
        assert_eq!(out.len(), 104);
        assert_eq!(&out[..16], &[0; 16]);
        assert_eq!(&out[16..24], &9_u64.to_le_bytes());
    }

    #[test]
    fn relookup_changes_the_node_handle_not_the_stat_inode() {
        let timestamp = host::Timestamp {
            seconds: 0,
            nanoseconds: 0,
        };
        let stat = host::Stat {
            dev: 7,
            ino: 99,
            mode: 0o120_777,
            nlink: 1,
            uid: 0,
            gid: 0,
            size: 4,
            blocks: 0,
            atime: timestamp,
            mtime: timestamp,
            ctime: timestamp,
        };
        let before_forget = entry(&stat, 2);
        let after_relookup = entry(&stat, 3);
        assert_eq!(&before_forget[..8], &2_u64.to_le_bytes());
        assert_eq!(&after_relookup[..8], &3_u64.to_le_bytes());
        assert_eq!(&before_forget[40..48], &99_u64.to_le_bytes());
        assert_eq!(&after_relookup[40..48], &99_u64.to_le_bytes());
        assert_eq!(stable_inode(&stat), 99);
    }

    #[test]
    fn symlink_target_accepts_slashes_after_the_name() {
        assert_eq!(
            symlink_parts(b"link\0nested/target\0"),
            Ok((b"link".to_vec(), b"nested/target".to_vec()))
        );
    }

    #[test]
    fn sized_replies_include_the_kernel_padding() {
        assert_eq!(sized_out(3), [3, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn flush_is_a_noop_without_lock_support() {
        assert_eq!(flush_body(&[0; 24]), Ok(()));
        assert_eq!(flush_body(&[]), Err(wire::EINVAL));
    }

    #[test]
    fn empty_read_completes_without_retrying() {
        assert_eq!(read_progressed(0, 0, 0), Ok(false));
        assert_eq!(read_progressed(0, 1, 1), Ok(true));
        assert_eq!(read_progressed(0, 0, 1), Err(5));
        assert_eq!(read_progressed(1, 3, 1), Err(5));
    }
}
