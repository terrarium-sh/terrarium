mod io;
mod requests;

use std::sync::{
    LazyLock, Mutex,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};

use futures::{
    FutureExt, StreamExt,
    channel::mpsc,
    future::{AbortHandle, AbortRegistration, Abortable, poll_fn},
};

use terra_device_transport::{
    Doorbell, INT_USED_BUFFER, MmioTransport, SPLIT_RING_DESC_F_NEXT, SPLIT_RING_DESC_F_WRITE,
    SplitRingDescriptor, VIRTIO_F_VERSION_1, WriteOutcome, complete_split_ring_entry,
    read_split_ring_available, split_ring_chain,
};

use crate::host;
use crate::terra::fs::host::FilesystemStat;
use crate::terra::host::memory;
use crate::terra::mmio::types::DeviceError;
use crate::wasi::clocks::system_clock::Instant;
use crate::wire;
use crate::wire::{u32_at, u64_at};

const HIPRIO_QUEUE: usize = 0;
const REQUEST_QUEUE: usize = 1;
const STATUS: u64 = 0x70;
const QUEUE_SIZE: u16 = 256;
const DEVICE_ID: u32 = 26;
const MAX_CHAIN: usize = 32;
const MAX_REQUEST: usize = 128 * 1024;
const MAX_READ: usize = 64 * 1024;
const MAX_NODES: usize = 8192;
const MAX_HANDLES: usize = 2048;
const MAX_DIRECTORIES: usize = 2048;
const CLOSE_FLUSH_TIMEOUT: u64 = 1_000_000_000;

struct NodeRecord {
    dev: u64,
    ino: u64,
    lookups: u64,
    node: host::Node,
}

struct OpenHandle {
    node: u64,
    writable: bool,
    descriptor: host::Descriptor,
}

struct OpenDirectory {
    node: u64,
    directory: std::sync::Arc<futures::lock::Mutex<host::Directory>>,
    descriptor: host::Descriptor,
}

struct PendingReply {
    queue: usize,
    head: u16,
    output: Vec<SplitRingDescriptor>,
    unique: u64,
    generation: u64,
}

struct EventRequest {
    reply: PendingReply,
    abort: AbortHandle,
    cancellation: Option<AbortRegistration>,
}

struct State {
    event_request: Option<EventRequest>,
    event_entries: std::collections::BTreeMap<(u64, Vec<u8>), u64>,
    events_enabled: bool,
    max_nodes: usize,
    nodes: std::collections::BTreeMap<u64, NodeRecord>,
    node_id_by_identity: std::collections::BTreeMap<(u64, u64), u64>,
    unused_nodes: std::collections::BTreeSet<u64>,
    handles: std::collections::BTreeMap<u64, OpenHandle>,
    directories: std::collections::BTreeMap<u64, OpenDirectory>,
    next_handle: u64,
    next_node: u64,
}

impl State {
    fn new(max_nodes: usize, root: Option<NodeRecord>) -> Self {
        Self {
            event_request: None,
            event_entries: std::collections::BTreeMap::new(),
            events_enabled: false,
            max_nodes,
            node_id_by_identity: root
                .iter()
                .map(|record| ((record.dev, record.ino), 1))
                .collect(),
            nodes: root.map(|record| (1, record)).into_iter().collect(),
            unused_nodes: std::collections::BTreeSet::new(),
            handles: std::collections::BTreeMap::new(),
            directories: std::collections::BTreeMap::new(),
            next_handle: 2,
            next_node: 2,
        }
    }
}

struct Transport {
    mmio: MmioTransport,
    next: [u16; 2],
    generation: u64,
}

impl Transport {
    fn invalidate_queues(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.next = [0; 2];
    }
}

static STATE: LazyLock<Mutex<Option<State>>> = LazyLock::new(|| Mutex::new(None));
static TRANSPORT: LazyLock<Mutex<Option<Transport>>> = LazyLock::new(|| Mutex::new(None));
static WORK: Doorbell = Doorbell::new();
static NEXT_QUEUE: AtomicUsize = AtomicUsize::new(0);

terra_device_transport::device_error!(DeviceError);
terra_device_transport::guest_memory!(DeviceError);

fn transport<T>(
    f: impl FnOnce(&mut Transport) -> Result<T, DeviceError>,
) -> Result<T, DeviceError> {
    let mut transport = TRANSPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let transport = transport.as_mut().ok_or(DeviceError::NotReady)?;
    let result = f(transport);
    if let Some(asserted) = transport.mmio.take_irq() {
        terra_device_transport::publish_interrupt_asserted(
            asserted,
            crate::terra::host::interrupt::set_asserted,
        );
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
    WORK.ring(1 << queue);
}

fn queue_work_if_current(queue: usize, expected_generation: u64) -> Result<(), DeviceError> {
    if generation()? == expected_generation {
        queue_work(queue);
    }
    Ok(())
}

fn take_work() -> Option<usize> {
    let pending = WORK.take();
    let next = NEXT_QUEUE.load(Ordering::Relaxed);
    for offset in 0..2 {
        let queue = (next + offset) % 2;
        if pending & (1 << queue) != 0 {
            WORK.ring(pending & !(1 << queue));
            NEXT_QUEUE.store((queue + 1) % 2, Ordering::Relaxed);
            return Some(queue);
        }
    }
    None
}

fn clear_work() {
    WORK.clear();
    NEXT_QUEUE.store(0, Ordering::Relaxed);
}

fn node(state: &State, inode: u64) -> Option<&host::Node> {
    state.nodes.get(&inode).map(|record| &record.node)
}

fn node_id(state: &mut State, node: host::Node, stat: &host::Stat) -> Result<u64, i32> {
    if let Some(&id) = state.node_id_by_identity.get(&(stat.dev, stat.ino)) {
        let record = state.nodes.get_mut(&id).ok_or(wire::EIO)?;
        record.node = node;
        record.lookups = record.lookups.saturating_add(1);
        state.unused_nodes.remove(&id);
        return Ok(id);
    }
    if state.nodes.len() == state.max_nodes {
        evict_unused_node(state);
    }
    if state.nodes.len() == state.max_nodes {
        return Err(wire::EMFILE);
    }
    let id = state.next_node;
    state.next_node = state.next_node.wrapping_add(1).max(2);
    state.nodes.insert(
        id,
        NodeRecord {
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
        .values()
        .map(|handle| handle.node)
        .chain(state.directories.values().map(|directory| directory.node))
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

fn repoint_node(state: &mut State, stat: &host::Stat, parent: &host::Descriptor, name: &[u8]) {
    if let Some(&id) = state.node_id_by_identity.get(&(stat.dev, stat.ino))
        && let Some(record) = state.nodes.get_mut(&id)
    {
        record.node.repoint(parent, name);
    }
}

fn increment_lookup(state: &mut State, id: u64) {
    if let Some(record) = state.nodes.get_mut(&id) {
        record.lookups = record.lookups.saturating_add(1);
        state.unused_nodes.remove(&id);
    }
}

fn directory(state: &State, handle: u64) -> Option<&OpenDirectory> {
    state.directories.get(&handle)
}

fn handle(state: &State, id: u64) -> Option<&OpenHandle> {
    state.handles.get(&id)
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

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn wasi_error(error: crate::wasi::filesystem::types::ErrorCode) -> i32 {
    use crate::wasi::filesystem::types::ErrorCode;
    match error {
        ErrorCode::Access => wire::EACCES,
        ErrorCode::Already => wire::EALREADY,
        ErrorCode::BadDescriptor => wire::EBADF,
        ErrorCode::Busy => wire::EBUSY,
        ErrorCode::Deadlock => wire::EDEADLK,
        ErrorCode::Quota => wire::EDQUOT,
        ErrorCode::Exist => wire::EEXIST,
        ErrorCode::FileTooLarge => wire::EFBIG,
        ErrorCode::IllegalByteSequence => wire::EILSEQ,
        ErrorCode::InProgress => wire::EINPROGRESS,
        ErrorCode::Interrupted => wire::EINTR,
        ErrorCode::Invalid => wire::EINVAL,
        ErrorCode::Io | ErrorCode::Other(_) => wire::EIO,
        ErrorCode::IsDirectory => wire::EISDIR,
        ErrorCode::Loop => wire::ELOOP,
        ErrorCode::TooManyLinks => wire::EMLINK,
        ErrorCode::MessageSize => wire::EMSGSIZE,
        ErrorCode::NameTooLong => wire::ENAMETOOLONG,
        ErrorCode::NoDevice => wire::ENODEV,
        ErrorCode::NoEntry => wire::ENOENT,
        ErrorCode::NoLock => wire::ENOLCK,
        ErrorCode::InsufficientMemory => wire::ENOMEM,
        ErrorCode::InsufficientSpace => wire::ENOSPC,
        ErrorCode::NotDirectory => wire::ENOTDIR,
        ErrorCode::NotEmpty => wire::ENOTEMPTY,
        ErrorCode::NotRecoverable => wire::ENOTRECOVERABLE,
        ErrorCode::Unsupported => wire::EOPNOTSUPP,
        ErrorCode::NoTty => wire::ENOTTY,
        ErrorCode::NoSuchDevice => wire::ENXIO,
        ErrorCode::Overflow => wire::EOVERFLOW,
        ErrorCode::NotPermitted => wire::EPERM,
        ErrorCode::Pipe => wire::EPIPE,
        ErrorCode::ReadOnly => wire::EROFS,
        ErrorCode::InvalidSeek => wire::ESPIPE,
        ErrorCode::TextFileBusy => wire::ETXTBSY,
        ErrorCode::CrossDevice => wire::EXDEV,
    }
}

fn flush_body(body: &[u8]) -> Result<(), i32> {
    (body.len() == 24).then_some(()).ok_or(wire::EINVAL)
}

fn attr(stat: &host::Stat) -> Vec<u8> {
    let mut out = vec![0; 88];
    out[0..8].copy_from_slice(&stat.ino.to_le_bytes());
    out[8..16].copy_from_slice(&stat.size.to_le_bytes());
    out[16..24].copy_from_slice(&stat.blocks.to_le_bytes());
    for (index, time) in [stat.atime, stat.mtime, stat.ctime].into_iter().enumerate() {
        let seconds = u64::try_from(time.seconds).unwrap_or_default();
        out[24 + 8 * index..32 + 8 * index].copy_from_slice(&seconds.to_le_bytes());
        out[48 + 4 * index..52 + 4 * index].copy_from_slice(&time.nanoseconds.to_le_bytes());
    }
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

fn entry_out(stat: &host::Stat, node: u64) -> Vec<u8> {
    let mut out = vec![0; 128];
    out[..8].copy_from_slice(&node.to_le_bytes());
    out[40..].copy_from_slice(&attr(stat));
    out
}

fn dirent_type(type_: &crate::wasi::filesystem::types::DescriptorType) -> u32 {
    use crate::wasi::filesystem::types::DescriptorType;
    match type_ {
        DescriptorType::Directory => 4,
        DescriptorType::SymbolicLink => 10,
        DescriptorType::RegularFile => 8,
        DescriptorType::BlockDevice => 6,
        DescriptorType::CharacterDevice => 2,
        DescriptorType::Fifo => 1,
        DescriptorType::Socket => 12,
        DescriptorType::Other(_) => 0,
    }
}

fn timestamp(seconds: u64, nanoseconds: u32) -> Instant {
    Instant {
        seconds: i64::try_from(seconds).unwrap_or(i64::MAX),
        nanoseconds,
    }
}

fn dirents_out(entries: Vec<host::DirectoryEntry>, max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for entry in entries {
        let size = 24_usize.saturating_add(entry.name.len());
        let padded = (size + 7) & !7;
        if padded > max.saturating_sub(out.len()) {
            break;
        }
        out.extend_from_slice(&entry.inode.to_le_bytes());
        out.extend_from_slice(&entry.next.to_le_bytes());
        out.extend_from_slice(
            &u32::try_from(entry.name.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        out.extend_from_slice(&dirent_type(&entry.type_).to_le_bytes());
        out.extend_from_slice(&entry.name);
        out.resize(out.len() + padded - size, 0);
    }
    out
}

fn open_out(inode: u64) -> Vec<u8> {
    let mut out = vec![0; 16];
    out[..8].copy_from_slice(&inode.to_le_bytes());
    out
}

fn write_out(size: u32) -> Vec<u8> {
    let mut out = vec![0; 8];
    out[..4].copy_from_slice(&size.to_le_bytes());
    out
}

const O_ACCMODE: u32 = 3;
const O_CREAT: u32 = 0o100;
const O_EXCL: u32 = 0o200;
const O_TRUNC: u32 = 0o1000;
const O_APPEND: u32 = 0o2000;
const O_NONBLOCK: u32 = 0o4000;
const O_LARGEFILE: u32 = 0o100_000;
const O_NOFOLLOW: u32 = 0o400_000;
const O_CLOEXEC: u32 = 0o2_000_000;
const FMODE_EXEC: u32 = 0x20;
const ACCEPTED_OPEN_FLAGS: u32 =
    O_ACCMODE | O_TRUNC | O_APPEND | O_NONBLOCK | O_LARGEFILE | O_NOFOLLOW | O_CLOEXEC | FMODE_EXEC;

fn validate_flags(flags: u32, accepted: u32) -> Result<(), i32> {
    if flags & !accepted != 0 || flags & O_ACCMODE == O_ACCMODE {
        return Err(wire::EINVAL);
    }
    Ok(())
}

fn create_flags(flags: u32) -> Result<crate::wasi::filesystem::types::OpenFlags, i32> {
    use crate::wasi::filesystem::types::OpenFlags;
    validate_flags(flags, ACCEPTED_OPEN_FLAGS | O_CREAT | O_EXCL)?;
    let mut result = OpenFlags::CREATE;
    if flags & O_TRUNC != 0 {
        result |= OpenFlags::TRUNCATE;
    }
    if flags & O_EXCL != 0 {
        result |= OpenFlags::EXCLUSIVE;
    }
    Ok(result)
}

fn open_flags(
    flags: u32,
) -> Result<(crate::wasi::filesystem::types::DescriptorFlags, bool, bool), i32> {
    use crate::wasi::filesystem::types::DescriptorFlags;
    validate_flags(flags, ACCEPTED_OPEN_FLAGS)?;
    let access = match flags & O_ACCMODE {
        0 => DescriptorFlags::READ,
        1 => DescriptorFlags::WRITE,
        _ => DescriptorFlags::READ | DescriptorFlags::WRITE,
    };
    Ok((access, flags & O_ACCMODE != 0, flags & O_TRUNC != 0))
}

fn allocate_handle(state: &mut State) -> u64 {
    let id = state.next_handle;
    state.next_handle = state.next_handle.wrapping_add(1).max(2);
    id
}

fn store_handle(
    state: &mut State,
    node: u64,
    descriptor: host::Descriptor,
    writable: bool,
) -> Result<u64, i32> {
    if state.handles.len() == MAX_HANDLES {
        return Err(wire::EMFILE);
    }
    let id = allocate_handle(state);
    state.handles.insert(
        id,
        OpenHandle {
            node,
            writable,
            descriptor,
        },
    );
    state.unused_nodes.remove(&node);
    Ok(id)
}

fn statfs_out(stat: &FilesystemStat) -> Vec<u8> {
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
            wit_bindgen::rt::async_support::StreamResult::Cancelled => return Err(wire::EIO),
        }
    }
    drop(stream);
    match completion.await {
        Ok(()) => Ok(bytes),
        Err(_) => Err(wire::EIO),
    }
}

fn read_progressed(before: usize, after: usize, read: usize) -> Result<bool, i32> {
    if read == 0 {
        return Ok(false);
    }
    (after.checked_sub(before) == Some(read))
        .then_some(true)
        .ok_or(wire::EIO)
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
        Err(wire::EIO)
    }
}

fn read(addr: u64, len: u64) -> Result<Vec<u8>, DeviceError> {
    if len > MAX_REQUEST as u64 {
        return Err(DeviceError::TooLarge);
    }
    read_guest_memory(&[(addr, len)])
}

fn write(addr: u64, bytes: &[u8]) -> Result<(), DeviceError> {
    if bytes.len() > MAX_REQUEST {
        return Err(DeviceError::TooLarge);
    }
    write_guest_memory(&[(addr, bytes)])
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
    let (_, head) = read_split_ring_available(avail, size, &mut next, read)?;
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
    complete_split_ring_entry(used_ring, size, head, used, read, write)?;
    transport(|transport| {
        transport.mmio.signal(INT_USED_BUFFER);
        Ok(())
    })
}

fn send_reply(
    queue: usize,
    head: u16,
    output: &[SplitRingDescriptor],
    payload: &[u8],
) -> Result<(), DeviceError> {
    let mut copied = 0_usize;
    let mut ranges = Vec::new();
    for descriptor in output {
        if copied == payload.len() {
            break;
        }
        let available = usize::try_from(descriptor.len).map_err(|_| DeviceError::TooLarge)?;
        let end = copied.saturating_add(available).min(payload.len());
        ranges.push((descriptor.addr, &payload[copied..end]));
        copied = end;
    }
    if copied != payload.len() {
        return Err(DeviceError::TooLarge);
    }
    write_guest_memory(&ranges)?;
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
    output: Vec<SplitRingDescriptor>,
}

fn read_request_buffers(desc: u64, head: u16, size: u16) -> Result<RequestBuffers, DeviceError> {
    let table = read(
        desc,
        u64::from(size) * terra_device_transport::SPLIT_RING_DESCRIPTOR_BYTES as u64,
    )?;
    let chain = split_ring_chain(
        &table,
        head,
        size,
        MAX_CHAIN,
        SPLIT_RING_DESC_F_NEXT | SPLIT_RING_DESC_F_WRITE,
    )
    .map_err(DeviceError::from)?;
    let (input, output) = chain.split_at(
        chain
            .iter()
            .position(|descriptor| descriptor.flags & SPLIT_RING_DESC_F_WRITE != 0)
            .unwrap_or(chain.len()),
    );
    if input.is_empty()
        || output
            .iter()
            .any(|descriptor| descriptor.flags & SPLIT_RING_DESC_F_WRITE == 0)
    {
        return Err(DeviceError::BadLen);
    }
    let ranges = input
        .iter()
        .map(|descriptor| (descriptor.addr, u64::from(descriptor.len)))
        .collect::<Vec<_>>();
    let total = ranges.iter().try_fold(0_u64, |total, &(_, len)| {
        total.checked_add(len).ok_or(DeviceError::TooLarge)
    })?;
    if total > MAX_REQUEST as u64 {
        return Err(DeviceError::TooLarge);
    }
    let request = read_guest_memory(&ranges)?;
    Ok(RequestBuffers {
        input: request,
        output: output.to_vec(),
    })
}

fn reply_to_event_request(
    state: &mut State,
    errno: i32,
    payload: &[u8],
) -> Result<(), DeviceError> {
    let Some(request) = state.event_request.take() else {
        return Ok(());
    };
    request.abort.abort();
    let pending = request.reply;
    if generation()? == pending.generation {
        send_reply(
            pending.queue,
            pending.head,
            &pending.output,
            &wire::reply(pending.unique, errno, payload),
        )?;
    }
    Ok(())
}

fn cancel_event_request(state: &mut State) -> Result<(), DeviceError> {
    state.events_enabled = false;
    reply_to_event_request(state, wire::ENODEV, &[])
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
    event_sender: &mut mpsc::Sender<()>,
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
        input: mut request,
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
        let (abort, cancellation) = AbortHandle::new_pair();
        state.event_request = Some(EventRequest {
            reply: PendingReply {
                queue,
                head,
                output,
                unique: request.unique,
                generation: request_generation,
            },
            abort,
            cancellation: Some(cancellation),
        });
        let _ = event_sender.try_send(());
        return available(queue).map(|next| next.is_some());
    }
    if let Ok(request) = &parsed
        && request.opcode == wire::CANCEL_EVENTS
    {
        cancel_event_request(state)?;
    }
    let response = match parsed {
        Ok(parsed_request) => {
            let target = PendingReply {
                queue,
                head,
                output: output.clone(),
                unique: parsed_request.unique,
                generation: request_generation,
            };
            let opcode = parsed_request.opcode;
            let node = parsed_request.node;
            let unique = parsed_request.unique;
            let request_len = wire::HEADER + parsed_request.body.len();
            request.truncate(request_len);
            let owned_request = requests::OwnedRequest {
                opcode,
                node,
                unique,
                bytes: request,
            };
            let Some(response) = execute_request(state, scheduler, owned_request, target) else {
                return available(queue).map(|next| next.is_some());
            };
            response
        }
        Err(errno) => wire::reply(0, errno, &[]),
    };
    if request_generation != generation()? {
        clear_runtime(state);
        return Ok(false);
    }
    if send_reply(queue, head, &output, &response).is_err() {
        return malformed();
    }
    available(queue).map(|next| next.is_some())
}

fn execute_request(
    state: &mut State,
    scheduler: &mut io::IoScheduler,
    owned_request: requests::OwnedRequest,
    target: PendingReply,
) -> Option<Vec<u8>> {
    let request = owned_request.borrow();
    if request.opcode == wire::INIT && scheduler.contains_generation(target.generation) {
        return Some(wire::reply(request.unique, wire::EBUSY, &[]));
    }
    let unique = request.unique;
    let result = if let Some(result) = requests::execute_immediate(state, &request) {
        result
    } else {
        match requests::prepare_io(state, owned_request, target.generation)
            .and_then(|operation| scheduler.enqueue(operation, target))
        {
            Ok(()) => return None,
            Err(errno) => Err(errno),
        }
    };
    Some(encode_response(unique, result))
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
    let root = host::root().ok()?;
    let parent_path = parts.join("/");
    let parent_identity = if parent_path.is_empty() {
        root.resolve_descriptor()
            .await
            .ok()?
            .metadata_hash()
            .await
            .ok()?
    } else {
        root.child_identity(&parent_path).await.ok()?
    };
    let (id, child) = state
        .with(|state| {
            let id = *state
                .node_id_by_identity
                .get(&(parent_identity.upper, parent_identity.lower))
                .ok_or(wire::ENOENT)?;
            let child = state
                .event_entries
                .get(&(id, name.as_bytes().to_vec()))
                .copied()
                .unwrap_or(0);
            Ok((id, child))
        })
        .ok()?;
    let identity = if child != 0 && matches!(event.kind, EventKind::Modify | EventKind::Metadata) {
        root.child_identity(&event.path).await.ok()
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
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(State::new(
        max_nodes,
        Some(NodeRecord {
            dev: root_stat.dev,
            ino: root_stat.ino,
            lookups: 1,
            node: root,
        }),
    ));
    *TRANSPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some(new_transport(memory::address_limit(), config));
    terra_device_transport::publish_interrupt_asserted(
        false,
        crate::terra::host::interrupt::set_asserted,
    );
    clear_work();
    WORK.reset();
    Ok(())
}

fn new_transport(ram_size: u64, config: Vec<u8>) -> Transport {
    Transport {
        mmio: MmioTransport::new(ram_size, DEVICE_ID, VIRTIO_F_VERSION_1, QUEUE_SIZE, config)
            .with_queue_count(2),
        next: [0; 2],
        generation: 0,
    }
}

pub fn mmio_read(addr: u64, width: u8) -> Result<u64, DeviceError> {
    transport(|transport| transport.mmio.read(addr, width).map_err(DeviceError::from))
}

fn clear_runtime(state: &mut State) {
    if let Some(request) = state.event_request.take() {
        request.abort.abort();
    }
    *state = State::new(state.max_nodes, state.nodes.remove(&1));
}

pub fn mmio_write(addr: u64, width: u8, value: u64) -> Result<(), DeviceError> {
    let bell = transport(|transport| {
        match transport
            .mmio
            .write(addr, width, value)
            .map_err(DeviceError::from)?
        {
            WriteOutcome::None => Ok(None),
            WriteOutcome::QueueNotify(queue) => Ok(Some(usize::from(queue))),
            WriteOutcome::Reset => {
                transport.invalidate_queues();
                clear_work();
                WORK.ring(0);
                Ok(None)
            }
        }
    })?;
    if let Some(queue) = bell {
        if queue >= 2 {
            return Err(DeviceError::BadQueue);
        }
        queue_work(queue);
    }
    Ok(())
}

fn encode_response(unique: u64, result: Result<Vec<u8>, i32>) -> Vec<u8> {
    match result {
        Ok(body) => wire::reply(unique, 0, &body),
        Err(errno) => wire::reply(unique, errno, &[]),
    }
}

fn complete_io(completed: io::CompletedIo) {
    let target = completed.reply;
    if generation().ok() == Some(target.generation)
        && send_reply(
            target.queue,
            target.head,
            &target.output,
            &encode_response(target.unique, completed.result),
        )
        .is_err()
    {
        let _ = complete(target.queue, target.head, 0);
    }
}

struct ReadyWork {
    completed: Option<io::CompletedIo>,
    queue: Option<usize>,
}

fn poll_work(
    context: &mut Context<'_>,
    scheduler: &mut io::IoScheduler,
    current_generation: u64,
) -> Poll<ReadyWork> {
    WORK.register(context.waker());
    let completed = scheduler.poll_complete(context);
    let queue = take_work();
    if completed.is_some()
        || queue.is_some()
        || WORK.is_closed()
        || generation().ok() != Some(current_generation)
    {
        Poll::Ready(ReadyWork { completed, queue })
    } else {
        Poll::Pending
    }
}

async fn receive_events(
    mut events: impl futures::Stream<Item = crate::terra::fs::host::FileEvent> + Unpin,
    mut requests: mpsc::Receiver<()>,
) {
    while requests.next().await.is_some() {
        let pending = STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
            .and_then(|state| state.event_request.as_mut())
            .and_then(|request| {
                request.cancellation.take().map(|cancellation| {
                    (request.reply.generation, request.reply.unique, cancellation)
                })
            });
        let Some((generation, unique, cancellation)) = pending else {
            continue;
        };
        let payload = async {
            loop {
                let event = events.next().await?;
                if let Some(payload) = encode_event(requests::RequestState(generation), event).await
                {
                    return Some(payload);
                }
            }
        };
        match Abortable::new(payload, cancellation).await {
            Ok(Some(payload)) => {
                let _ = requests::RequestState(generation).with(|state| {
                    if state
                        .event_request
                        .as_ref()
                        .is_some_and(|request| request.reply.unique == unique)
                    {
                        let _ = reply_to_event_request(state, 0, &payload);
                    }
                    Ok(())
                });
            }
            Ok(None) => break,
            Err(_) => {}
        }
    }
}

pub async fn run() -> Result<(), DeviceError> {
    let events = crate::terra::fs::host::file_events().into_stream();
    let (mut event_sender, event_requests) = mpsc::channel(0);
    let (event_worker, _event_handle) = receive_events(events, event_requests).remote_handle();
    wit_bindgen::spawn_local(event_worker);
    let mut scheduler = io::IoScheduler::default();
    let Ok(mut current_generation) = generation() else {
        return Ok(());
    };
    while !WORK.is_closed() {
        wit_bindgen::rt::async_support::yield_async().await;
        let Ok(observed_generation) = generation() else {
            break;
        };
        if observed_generation != current_generation {
            scheduler.discard_pending();
            if let Some(state) = STATE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_mut()
            {
                clear_runtime(state);
            }
            current_generation = observed_generation;
        }
        let ReadyWork { completed, queue } =
            poll_fn(|context| poll_work(context, &mut scheduler, current_generation)).await;
        if let Some(completed) = completed {
            complete_io(completed);
        }
        if WORK.is_closed() {
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
            Some(state) => {
                process_request(state, &mut scheduler, queue, &mut event_sender).unwrap_or(false)
            }
            None => false,
        };
        drop(state);
        if pending {
            let _ = queue_work_if_current(queue, current_generation);
        }
    }
    Ok(())
}

pub fn reset() {
    let _ = transport(reset_transport);
    clear_work();
    WORK.ring(0);
}

fn reset_transport(transport: &mut Transport) -> Result<(), DeviceError> {
    transport.invalidate_queues();
    transport
        .mmio
        .write(STATUS, 4, 0)
        .map_err(DeviceError::from)?;
    Ok(())
}

pub async fn close() -> Result<(), DeviceError> {
    let _ = transport(reset_transport);
    WORK.close();
    clear_work();
    WORK.ring(0);
    *TRANSPORT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    let flush = async {
        let Some(state) = STATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        else {
            return Ok(());
        };
        let results = futures::future::join_all(
            state
                .handles
                .values()
                .filter(|handle| handle.writable)
                .map(|handle| handle.descriptor.sync_data()),
        )
        .await;
        if results.iter().any(Result::is_err) {
            Err(DeviceError::Io)
        } else {
            Ok(())
        }
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
        let (abort, cancellation) = AbortHandle::new_pair();
        let mut state = State::new(1, None);
        state.event_request = Some(EventRequest {
            reply: PendingReply {
                queue: HIPRIO_QUEUE,
                head: 0,
                output: Vec::new(),
                unique: 1,
                generation: 0,
            },
            abort,
            cancellation: Some(cancellation),
        });
        state.events_enabled = true;
        *STATE.lock().unwrap() = Some(state);
        let (mut event_requests, requests) = mpsc::channel(0);
        event_requests.try_send(()).unwrap();
        let (events, stream) = mpsc::unbounded();
        let received = std::sync::Arc::new(AtomicUsize::new(0));
        let count = received.clone();
        let mut event_worker = receive_events(
            stream.inspect(move |_| {
                count.fetch_add(1, Ordering::Relaxed);
            }),
            requests,
        )
        .boxed_local();
        for unique in 0..32 {
            queue_work(REQUEST_QUEUE);
            scheduler
                .enqueue(
                    io::PreparedIo {
                        identity: Some((0, unique)),
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
            let Poll::Ready(ready) = poll_work(&mut context, &mut scheduler, 0) else {
                panic!("queued work must be ready");
            };
            assert_eq!(ready.queue, Some(REQUEST_QUEUE));
            assert_eq!(ready.completed.unwrap().reply.unique, unique);
            events
                .unbounded_send(crate::terra::fs::host::FileEvent {
                    path: "/".into(),
                    kind: crate::terra::fs::host::EventKind::Modify,
                    is_directory: false,
                })
                .unwrap();
            assert!(event_worker.poll_unpin(&mut context).is_pending());
            assert_eq!(
                received.load(Ordering::Relaxed),
                usize::try_from(unique).unwrap() + 1
            );
        }
        clear_runtime(STATE.lock().unwrap().as_mut().unwrap());
        drop(event_requests);
        assert!(event_worker.poll_unpin(&mut context).is_ready());
        *STATE.lock().unwrap() = None;
    }

    #[test]
    fn reset_discards_pending_indices_and_interrupts() {
        let mut transport = Transport {
            mmio: MmioTransport::new(65536, DEVICE_ID, VIRTIO_F_VERSION_1, QUEUE_SIZE, Vec::new())
                .with_queue_count(2),
            next: [3, 7],
            generation: 11,
        };
        transport.mmio.signal(INT_USED_BUFFER);
        reset_transport(&mut transport).unwrap();
        assert_eq!(transport.generation, 12);
        assert_eq!(transport.next, [0, 0]);
        assert_eq!(transport.mmio.read(0x60, 4).unwrap(), 0);
    }

    #[test]
    fn keeps_directory_error_kinds() {
        assert_eq!(
            wasi_error(crate::wasi::filesystem::types::ErrorCode::IsDirectory),
            21
        );
        assert_eq!(
            wasi_error(crate::wasi::filesystem::types::ErrorCode::Loop),
            40
        );
        assert_eq!(
            wasi_error(crate::wasi::filesystem::types::ErrorCode::NotDirectory),
            20
        );
    }

    #[test]
    fn keeps_wasi_errno_precision() {
        use crate::wasi::filesystem::types::ErrorCode;
        for (error, errno) in [
            (ErrorCode::CrossDevice, 18),
            (ErrorCode::NameTooLong, 36),
            (ErrorCode::Overflow, 75),
            (ErrorCode::NotPermitted, 1),
            (ErrorCode::Busy, 16),
            (ErrorCode::TooManyLinks, 31),
            (ErrorCode::MessageSize, 90),
            (ErrorCode::InsufficientMemory, 12),
            (ErrorCode::BadDescriptor, 9),
        ] {
            assert_eq!(wasi_error(error), errno);
        }
    }

    #[test]
    fn attr_out_has_its_cache_timeout_prefix() {
        let timestamp = Instant {
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
        let timestamp = Instant {
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
        let before_forget = entry_out(&stat, 2);
        let after_relookup = entry_out(&stat, 3);
        assert_eq!(&before_forget[..8], &2_u64.to_le_bytes());
        assert_eq!(&after_relookup[..8], &3_u64.to_le_bytes());
        assert_eq!(&before_forget[40..48], &99_u64.to_le_bytes());
        assert_eq!(&after_relookup[40..48], &99_u64.to_le_bytes());
        assert_eq!(stat.ino, 99);
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
        assert_eq!(write_out(3), [3, 0, 0, 0, 0, 0, 0, 0]);
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
        assert_eq!(read_progressed(0, 0, 1), Err(wire::EIO));
        assert_eq!(read_progressed(1, 3, 1), Err(wire::EIO));
    }
}
