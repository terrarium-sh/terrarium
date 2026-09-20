use std::future::Future;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::sync::{Notify, Semaphore};
use wasmtime::component::{
    Component, Destination, FutureReader, Linker, Resource, StreamProducer, StreamReader,
    StreamResult,
};
use wasmtime_wasi::filesystem::Descriptor;
use wasmtime_wasi::p3::bindings::filesystem::types::ErrorCode;

use super::host::{FsHost, ShareGrant};
use crate::box_runtime::{BoxHost, BoxRuntime, BoxRuntimeHandle};
use crate::component::DeviceChannel;
use crate::engine::{DeviceHost, device_engine};
use crate::{BoundedMemory, SyntheticRam};

pub(super) struct IoGate {
    operation: Operation,
    armed: AtomicBool,
    blocked_host: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    blocked_drop: std::sync::Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    count_blocked_drops: AtomicBool,
    drop_started: Semaphore,
    started: Semaphore,
    release: Arc<Notify>,
    dropped: Semaphore,
}

#[derive(Clone, Copy)]
enum Operation {
    Read,
    Write,
    Sync,
    Lookup,
    Stat,
    ReadDirectory,
    HostMetadata,
}

struct StalledRead {
    gate: Arc<IoGate>,
    ready: Pin<Box<dyn Future<Output = ()> + Send>>,
    started: bool,
}

impl Drop for StalledRead {
    fn drop(&mut self) {
        self.gate.dropped.add_permits(1);
    }
}

impl StreamProducer<BoxHost> for StalledRead {
    type Item = u8;
    type Buffer = Option<u8>;

    fn poll_produce<'a>(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        _: wasmtime::StoreContextMut<'a, BoxHost>,
        mut destination: Destination<'a, Self::Item, Self::Buffer>,
        _finish: bool,
    ) -> Poll<wasmtime::Result<StreamResult>> {
        if !self.started {
            self.started = true;
            self.gate.started.add_permits(1);
        }
        if self.ready.as_mut().poll(context).is_pending() {
            return Poll::Pending;
        }
        destination.set_buffer(Some(7));
        Poll::Ready(Ok(StreamResult::Dropped))
    }
}

pub(super) fn install_io_gate(
    mut linker: Linker<BoxHost>,
    gate: Option<Arc<IoGate>>,
) -> wasmtime::Result<Linker<BoxHost>> {
    if let Some(gate) = gate {
        linker.allow_shadowing(true);
        if matches!(gate.operation, Operation::HostMetadata) {
            return Ok(linker);
        }
        if matches!(
            gate.operation,
            Operation::Lookup | Operation::Stat | Operation::ReadDirectory
        ) {
            return install_metadata_gate(linker, gate);
        }
        if matches!(gate.operation, Operation::Write | Operation::Sync) {
            let sync_gate = gate.clone();
            linker
                .instance("wasi:filesystem/types@0.3.0")?
                .func_wrap_concurrent(
                    "[method]descriptor.sync-data",
                    move |_accessor, (_descriptor,): (Resource<Descriptor>,)| {
                        let gate = sync_gate.clone();
                        Box::pin(async move {
                            gate.started.add_permits(1);
                            gate.release.notified().await;
                            Ok((Ok::<(), ErrorCode>(()),))
                        })
                    },
                )?;
        }
        if matches!(gate.operation, Operation::Write) {
            linker.instance("wasi:filesystem/types@0.3.0")?.func_wrap(
                "[method]descriptor.write-via-stream",
                move |mut store,
                      (_descriptor, _stream, _offset): (
                    Resource<Descriptor>,
                    StreamReader<u8>,
                    u64,
                )| {
                    let gate = gate.clone();
                    gate.started.add_permits(1);
                    let completion = FutureReader::new(&mut store, async move {
                        gate.release.notified().await;
                        Ok::<Result<(), ErrorCode>, wasmtime::Error>(Ok(()))
                    })?;
                    Ok((completion,))
                },
            )?;
            return Ok(linker);
        }
        if matches!(gate.operation, Operation::Sync) {
            return Ok(linker);
        }
        linker.instance("wasi:filesystem/types@0.3.0")?.func_wrap(
            "[method]descriptor.read-via-stream",
            move |mut store, (_descriptor, offset): (Resource<Descriptor>, u64)| {
                let stream = if offset == 0 {
                    StreamReader::new(
                        &mut store,
                        StalledRead {
                            gate: gate.clone(),
                            ready: Box::pin(gate.release.clone().notified_owned()),
                            started: false,
                        },
                    )?
                } else {
                    StreamReader::new(&mut store, vec![9_u8])?
                };
                let completion = FutureReader::new(&mut store, async {
                    Ok::<Result<(), ErrorCode>, wasmtime::Error>(Ok(()))
                })?;
                Ok(((stream, completion),))
            },
        )?;
    }
    Ok(linker)
}

fn install_metadata_gate(
    mut linker: Linker<BoxHost>,
    gate: Arc<IoGate>,
) -> wasmtime::Result<Linker<BoxHost>> {
    use wasmtime_wasi::filesystem::WasiFilesystem;
    use wasmtime_wasi::p3::bindings::filesystem::types::{HostDescriptorWithStore, PathFlags};
    if matches!(gate.operation, Operation::Lookup) {
        linker.instance("wasi:filesystem/types@0.3.0")?.func_wrap_concurrent(
            "[method]descriptor.stat-at",
            move |accessor, (descriptor, flags, path): (Resource<Descriptor>, PathFlags, String)| {
                let gate = gate.clone();
                Box::pin(async move {
                    gate.wait_if_armed().await;
                    let wasi = accessor.with_getter::<WasiFilesystem>(super::shared_filesystem);
                    Ok((match WasiFilesystem::stat_at(&wasi, descriptor, flags, path).await { Ok(value) => Ok(value), Err(error) => Err(error.downcast()?), },))
                })
            },
        )?;
    } else if matches!(gate.operation, Operation::Stat) {
        linker
            .instance("wasi:filesystem/types@0.3.0")?
            .func_wrap_concurrent(
                "[method]descriptor.stat",
                move |accessor, (descriptor,): (Resource<Descriptor>,)| {
                    let gate = gate.clone();
                    Box::pin(async move {
                        gate.wait_if_armed().await;
                        let wasi = accessor.with_getter::<WasiFilesystem>(super::shared_filesystem);
                        Ok((match WasiFilesystem::stat(&wasi, descriptor).await {
                            Ok(value) => Ok(value),
                            Err(error) => Err(error.downcast()?),
                        },))
                    })
                },
            )?;
    } else {
        linker.instance("wasi:filesystem/types@0.3.0")?.func_wrap(
            "[method]descriptor.read-directory",
            move |mut store, (_descriptor,): (Resource<Descriptor>,)| {
                let gate = gate.clone();
                gate.started.add_permits(1);
                let stream = StreamReader::new(
                    &mut store,
                    Vec::<wasmtime_wasi::p3::bindings::filesystem::types::DirectoryEntry>::new(),
                )?;
                let completion = FutureReader::new(&mut store, async move {
                    gate.release.notified().await;
                    Ok::<Result<(), ErrorCode>, wasmtime::Error>(Ok(()))
                })?;
                Ok(((stream, completion),))
            },
        )?;
    }
    Ok(linker)
}

impl IoGate {
    pub(super) fn wait_on_descriptor_drop(&self) {
        if self.count_blocked_drops.load(Ordering::Acquire) {
            self.drop_started.add_permits(1);
        }
        let receiver = self.blocked_drop.lock().unwrap();
        if let Some(receiver) = receiver.as_ref() {
            self.started.add_permits(1);
            let _ = receiver.recv();
        }
    }

    pub(super) fn wait_on_host_thread(&self) {
        let receiver = self.blocked_host.lock().unwrap().take();
        if let Some(receiver) = receiver {
            self.started.add_permits(1);
            let _ = receiver.recv();
        }
    }

    async fn wait_if_armed(&self) {
        if self.armed.swap(false, Ordering::AcqRel) {
            self.started.add_permits(1);
            self.release.notified().await;
        }
    }
}

struct Mounted {
    channel: DeviceChannel,
    ram: SyntheticRam,
    runtime: BoxRuntimeHandle,
    next: u16,
    request_head: u16,
}

impl Mounted {
    async fn new(grant: ShareGrant, gate: Arc<IoGate>, capacity: usize) -> Self {
        let ram = SyntheticRam::new(1024 * 1024).unwrap();
        let engine = device_engine().unwrap();
        let component = Component::new(
            &engine,
            include_bytes!(
                "../../../../../components/fs/target/wasm32-wasip3/release/terra_fs_component.wasm"
            ),
        )
        .unwrap();
        let router = Component::new(&engine, include_bytes!("../../../../../components/vmm/target/wasm32-wasip3/release/terra_vmm_component.wasm")).unwrap();
        let mut host =
            FsHost::with_resource_capacity(DeviceHost::with_ram(ram.clone()), grant, capacity);
        host.io_gate = Some(gate);
        let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).unwrap();
        runtime.initialize_mmio(&router).await.unwrap();
        let channel = super::instantiate_shared(
            &mut runtime,
            host,
            &component,
            "test",
            8192,
            Arc::new(|_| Ok(())),
        )
        .await
        .unwrap();
        let mut mounted = Self {
            channel,
            ram,
            runtime: runtime.start(),
            next: 0,
            request_head: 2,
        };
        mounted.initialize_transport();
        mounted.initialize_events().await;
        mounted
    }

    fn initialize_transport(&mut self) {
        self.next = 0;
        let memory = BoundedMemory::new(&self.ram);
        memory.write(0x2002, &[0; 2]).unwrap();
        memory.write(0x3002, &[0; 2]).unwrap();
        for (offset, value) in [
            (0x70, 1_u32),
            (0x70, 3),
            (0x24, 1),
            (0x20, 1),
            (0x70, 11),
            (0x30, 1),
            (0x38, 128),
            (0x80, 0x1000),
            (0x90, 0x2000),
            (0xa0, 0x3000),
            (0x44, 1),
            (0x70, 15),
        ] {
            self.channel.write(offset, &value.to_le_bytes()).unwrap();
        }
    }

    async fn initialize_events(&mut self) {
        let mut init = vec![0; 20];
        init[..4].copy_from_slice(&7_u32.to_le_bytes());
        init[4..8].copy_from_slice(&40_u32.to_le_bytes());
        init[12..16].copy_from_slice(&(1_u32 << 30).to_le_bytes());
        init[16..20].copy_from_slice(&(1_u32 << 31).to_le_bytes());
        self.request(26, 1, &init).await;
    }

    fn submit(&mut self, head: u16, opcode: u32, node: u64, body: &[u8]) -> (u64, u64) {
        let memory = BoundedMemory::new(&self.ram);
        let unique = u64::from(self.next) + 1;
        let input = 0x4000 + u64::from(head) * 0x1000;
        let output = input + 0x800;
        let mut request = vec![0; 40];
        request[..4].copy_from_slice(&u32::try_from(40 + body.len()).unwrap().to_le_bytes());
        request[4..8].copy_from_slice(&opcode.to_le_bytes());
        request[8..16].copy_from_slice(&unique.to_le_bytes());
        request[16..24].copy_from_slice(&node.to_le_bytes());
        request.extend_from_slice(body);
        memory.write(input, &request).unwrap();
        memory.write(output, &[0; 16]).unwrap();
        let mut descriptors = [0; 32];
        descriptors[..8].copy_from_slice(&input.to_le_bytes());
        descriptors[8..12].copy_from_slice(&u32::try_from(request.len()).unwrap().to_le_bytes());
        descriptors[12..14].copy_from_slice(&1_u16.to_le_bytes());
        descriptors[14..16].copy_from_slice(&(head + 1).to_le_bytes());
        descriptors[16..24].copy_from_slice(&output.to_le_bytes());
        descriptors[24..28].copy_from_slice(&1024_u32.to_le_bytes());
        descriptors[28..30].copy_from_slice(&2_u16.to_le_bytes());
        memory
            .write(0x1000 + u64::from(head) * 16, &descriptors)
            .unwrap();
        memory
            .write(0x2004 + u64::from(self.next % 128) * 2, &head.to_le_bytes())
            .unwrap();
        self.next += 1;
        memory.write(0x2002, &self.next.to_le_bytes()).unwrap();
        self.channel.write(0x50, &1_u32.to_le_bytes()).unwrap();
        (output, unique)
    }

    async fn receive(&self, target: (u64, u64)) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(3), async {
            let memory = BoundedMemory::new(&self.ram);
            loop {
                let header = memory.read(target.0, 16).unwrap();
                if header[8..16] == target.1.to_le_bytes() {
                    let length = u32::from_le_bytes(header[..4].try_into().unwrap());
                    return memory.read(target.0, u64::from(length)).unwrap();
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("a stalled read must not block this request")
    }

    async fn request(&mut self, opcode: u32, node: u64, body: &[u8]) -> Vec<u8> {
        let target = self.submit(self.request_head, opcode, node, body);
        let response = self.receive(target).await;
        assert_eq!(&response[4..8], &[0; 4]);
        response
    }

    async fn open(&mut self, name: &[u8]) -> (u64, u64) {
        self.open_with_flags(name, 0).await
    }

    async fn open_with_flags(&mut self, name: &[u8], flags: u32) -> (u64, u64) {
        let entry = self.request(1, 1, name).await;
        let node = u64::from_le_bytes(entry[16..24].try_into().unwrap());
        let mut body = [0; 8];
        body[..4].copy_from_slice(&flags.to_le_bytes());
        let opened = self.request(14, node, &body).await;
        (node, u64::from_le_bytes(opened[16..24].try_into().unwrap()))
    }
}

fn read_body(handle: u64, offset: u64) -> Vec<u8> {
    let mut body = vec![0; 40];
    body[..8].copy_from_slice(&handle.to_le_bytes());
    body[8..16].copy_from_slice(&offset.to_le_bytes());
    body[16..20].copy_from_slice(&1_u32.to_le_bytes());
    body
}

async fn mount() -> (tempfile::TempDir, Mounted, Arc<IoGate>) {
    mount_with_operation(Operation::Read).await
}

async fn mount_with_operation(operation: Operation) -> (tempfile::TempDir, Mounted, Arc<IoGate>) {
    mount_with_capacity(operation, 16_384).await
}

async fn mount_with_capacity(
    operation: Operation,
    capacity: usize,
) -> (tempfile::TempDir, Mounted, Arc<IoGate>) {
    mount_with_registration(operation, capacity, None).await
}

async fn mount_with_registration(
    operation: Operation,
    capacity: usize,
    registration: Option<Arc<dyn Fn() + Send + Sync>>,
) -> (tempfile::TempDir, Mounted, Arc<IoGate>) {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap();
    std::fs::write(path.join("slow"), "slow").unwrap();
    std::fs::write(path.join("fast"), "fast").unwrap();
    for index in 0..64 {
        std::fs::write(path.join(format!("slot-{index}")), "slot").unwrap();
    }
    let gate = Arc::new(IoGate {
        operation,
        armed: AtomicBool::new(false),
        blocked_host: std::sync::Mutex::new(None),
        blocked_drop: std::sync::Mutex::new(None),
        count_blocked_drops: AtomicBool::new(false),
        drop_started: Semaphore::new(0),
        started: Semaphore::new(0),
        release: Arc::new(Notify::new()),
        dropped: Semaphore::new(0),
    });
    let mut grant = ShareGrant::new(&path, matches!(operation, Operation::Read)).unwrap();
    grant.watch_registration = registration;
    let mounted = Mounted::new(grant, gate.clone(), capacity).await;
    (root, mounted, gate)
}

#[tokio::test(flavor = "multi_thread")]
/// Native blocking reads may outlive their WASI readers; close must finish before the read is released.
async fn stalled_read_allows_other_io_events_cancellation_and_shutdown() {
    let (root, mut mounted, gate) = mount().await;
    let (slow_node, slow_handle) = mounted.open(b"slow\0").await;
    let (fast_node, fast_handle) = mounted.open(b"fast\0").await;
    let slow = mounted.submit(0, 15, slow_node, &read_body(slow_handle, 0));
    tokio::time::timeout(Duration::from_secs(3), gate.started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    let fast = mounted
        .request(15, fast_node, &read_body(fast_handle, 1))
        .await;
    assert_eq!(&fast[16..], &[9]);
    let notification = mounted.submit(4, 4096, 1, &[]);
    std::fs::write(root.path().join("changed"), "new").unwrap();
    for _ in 0..32 {
        mounted.request(3, 1, &[]).await;
    }
    let event = mounted.receive(notification).await;
    assert_eq!(&event[40..47], b"changed");
    mounted.request(4097, 1, &[]).await;
    assert_eq!(
        BoundedMemory::new(&mounted.ram).read(slow.0, 16).unwrap(),
        vec![0; 16]
    );
    gate.release.notify_one();
    assert_eq!(&mounted.receive(slow).await[16..], &[7]);
    let _slow = mounted.submit(0, 15, slow_node, &read_body(slow_handle, 0));
    tokio::time::timeout(Duration::from_secs(3), gate.started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    gate.dropped.acquire().await.unwrap().forget();
    let shutdown = std::time::Instant::now();
    mounted.channel.close().unwrap();
    assert!(shutdown.elapsed() < Duration::from_secs(3));
    gate.release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), gate.dropped.acquire())
        .await
        .expect("the abandoned host read eventually releases its resources")
        .unwrap()
        .forget();
    mounted.runtime.abort_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_retains_running_reads_without_publishing_old_replies() {
    let (_root, mut mounted, gate) = mount().await;
    let (node, handle) = mounted.open(b"slow\0").await;
    let slow = mounted.submit(0, 15, node, &read_body(handle, 0));
    tokio::time::timeout(Duration::from_secs(3), gate.started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    mounted.channel.reset().unwrap();
    mounted.initialize_transport();
    mounted.initialize_events().await;
    mounted.request(3, 1, &[]).await;
    let (fast_node, fast_handle) = mounted.open(b"fast\0").await;
    assert_eq!(fast_node, node);
    assert_eq!(
        &mounted
            .request(15, fast_node, &read_body(fast_handle, 1))
            .await[16..],
        &[9]
    );
    assert_eq!(gate.dropped.available_permits(), 0);
    gate.release.notify_one();
    tokio::time::timeout(Duration::from_secs(3), gate.dropped.acquire())
        .await
        .expect("the old read eventually finishes")
        .unwrap()
        .forget();
    mounted.request(3, 1, &[]).await;
    assert_eq!(
        BoundedMemory::new(&mounted.ram).read(slow.0, 16).unwrap(),
        vec![0; 16]
    );
    mounted.channel.close().unwrap();
    mounted.runtime.abort_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
/// A blocked write or fsync must permit unrelated I/O and events, and close must
/// return the component's I/O error before the MMIO bridge's two-second timeout.
async fn stalled_writes_and_flushes_do_not_block_shutdown() {
    for operation in [Operation::Write, Operation::Sync] {
        let (root, mut mounted, gate) = mount_with_operation(operation).await;
        let (node, handle) = mounted.open_with_flags(b"slow\0", 2).await;
        let (fast_node, fast_handle) = mounted.open(b"fast\0").await;
        let mut body = read_body(handle, 0);
        let opcode = match operation {
            Operation::Write => {
                body.push(42);
                16
            }
            Operation::Sync => 20,
            Operation::Read
            | Operation::Lookup
            | Operation::Stat
            | Operation::ReadDirectory
            | Operation::HostMetadata => {
                unreachable!()
            }
        };
        let pending = mounted.submit(0, opcode, node, &body);
        tokio::time::timeout(Duration::from_secs(3), gate.started.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        assert_eq!(
            &mounted
                .request(15, fast_node, &read_body(fast_handle, 0))
                .await[16..],
            b"f"
        );
        let notification = mounted.submit(4, 4096, 1, &[]);
        std::fs::write(root.path().join("changed"), "new").unwrap();
        assert_eq!(&mounted.receive(notification).await[40..47], b"changed");
        mounted.request(4097, 1, &[]).await;
        let start = std::time::Instant::now();
        let error = mounted.channel.close().unwrap_err();
        assert!(error.to_string().contains("MMIO device error"), "{error:#}");
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(
            gate.started.available_permits() > 0,
            "close attempted a flush"
        );
        assert_eq!(
            BoundedMemory::new(&mounted.ram)
                .read(pending.0, 16)
                .unwrap(),
            vec![0; 16]
        );
        mounted.channel.close().unwrap();
        gate.release.notify_waiters();
        mounted.runtime.abort_and_join().await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn close_waits_for_responsive_flush() {
    let (_root, mut mounted, gate) = mount_with_operation(Operation::Sync).await;
    mounted.open_with_flags(b"slow\0", 2).await;
    let channel = mounted.channel.clone();
    let close = tokio::task::spawn_blocking(move || channel.close());
    tokio::time::timeout(Duration::from_secs(3), gate.started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert!(!close.is_finished());
    gate.release.notify_one();
    close.await.unwrap().unwrap();
    mounted.runtime.abort_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stalled_metadata_preserves_other_io_events_reset_and_close() {
    for operation in [Operation::Lookup, Operation::Stat, Operation::ReadDirectory] {
        let (root, mut mounted, gate) = mount_with_operation(operation).await;
        let (slow_node, _) = mounted.open(b"slow\0").await;
        let (fast_node, fast_handle) = mounted.open(b"fast\0").await;
        let (opcode, node, body) = match operation {
            Operation::Lookup => (1, 1, b"slow\0".to_vec()),
            Operation::Stat => (3, slow_node, Vec::new()),
            Operation::ReadDirectory => {
                let opened = mounted.request(27, 1, &[0; 8]).await;
                let handle = u64::from_le_bytes(opened[16..24].try_into().unwrap());
                (28, 1, read_body(handle, 0))
            }
            Operation::Read | Operation::Write | Operation::Sync | Operation::HostMetadata => {
                unreachable!()
            }
        };
        gate.armed.store(true, Ordering::Release);
        let pending = mounted.submit(0, opcode, node, &body);
        tokio::time::timeout(Duration::from_secs(3), gate.started.acquire())
            .await
            .unwrap()
            .unwrap()
            .forget();
        assert_eq!(
            &mounted
                .request(15, fast_node, &read_body(fast_handle, 0))
                .await[16..],
            b"f"
        );
        let notification = mounted.submit(4, 4096, 1, &[]);
        std::fs::write(root.path().join("changed"), "new").unwrap();
        assert_eq!(&mounted.receive(notification).await[40..47], b"changed");
        mounted.request(4097, 1, &[]).await;
        mounted.channel.reset().unwrap();
        mounted.initialize_transport();
        mounted.initialize_events().await;
        mounted.channel.close().unwrap();
        gate.release.notify_waiters();
        mounted.runtime.abort_and_join().await;
        assert_eq!(
            BoundedMemory::new(&mounted.ram)
                .read(pending.0, 16)
                .unwrap(),
            vec![0; 16]
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stalled_event_resolution_preserves_requests_and_cancellation() {
    let (root, mut mounted, gate) = mount_with_operation(Operation::Stat).await;
    let (node, handle) = mounted.open(b"fast\0").await;
    gate.armed.store(true, Ordering::Release);
    let notification = mounted.submit(4, 4096, 1, &[]);
    std::fs::write(root.path().join("changed"), "new").unwrap();
    tokio::time::timeout(Duration::from_secs(3), gate.started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert_eq!(
        &mounted.request(15, node, &read_body(handle, 0)).await[16..],
        b"f"
    );
    mounted.request(4097, 1, &[]).await;
    let cancelled = mounted.receive(notification).await;
    assert_ne!(&cancelled[4..8], &[0; 4]);
    mounted.channel.close().unwrap();
    gate.release.notify_waiters();
    mounted.runtime.abort_and_join().await;
    assert_eq!(
        BoundedMemory::new(&mounted.ram)
            .read(notification.0, cancelled.len() as u64)
            .unwrap(),
        cancelled
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn saturated_io_preserves_events_cancellation_and_close() {
    let (root, mut mounted, gate) = mount().await;
    let mut handles = Vec::new();
    for index in 0..32 {
        handles.push(mounted.open(format!("slot-{index}\0").as_bytes()).await);
    }
    mounted.request_head = 66;
    for (index, (node, handle)) in handles.into_iter().enumerate() {
        mounted.submit(
            u16::try_from(index * 2).unwrap(),
            15,
            node,
            &read_body(handle, 0),
        );
    }
    tokio::time::timeout(Duration::from_secs(3), gate.started.acquire_many(32))
        .await
        .unwrap()
        .unwrap()
        .forget();
    let notification = mounted.submit(64, 4096, 1, &[]);
    std::fs::write(root.path().join("changed"), "new").unwrap();
    assert_eq!(&mounted.receive(notification).await[40..47], b"changed");
    mounted.request(4097, 1, &[]).await;
    mounted.channel.close().unwrap();
    gate.release.notify_waiters();
    mounted.runtime.abort_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn blocked_native_metadata_does_not_block_the_worker() {
    let (_root, mut mounted, gate) = mount_with_operation(Operation::HostMetadata).await;
    let (slow_node, _) = mounted.open(b"slow\0").await;
    let (fast_node, fast_handle) = mounted.open(b"fast\0").await;
    let (release, blocked) = std::sync::mpsc::channel();
    *gate.blocked_host.lock().unwrap() = Some(blocked);
    mounted.submit(0, 3, slow_node, &[]);
    tokio::time::timeout(Duration::from_secs(3), gate.started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    assert_eq!(
        &mounted
            .request(15, fast_node, &read_body(fast_handle, 0))
            .await[16..],
        b"f"
    );
    mounted.request(4097, 1, &[]).await;
    mounted.channel.close().unwrap();
    drop(release);
    mounted.runtime.abort_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn stalled_descriptor_drops_remain_bounded_and_do_not_block_reset_or_close() {
    let (_root, mut mounted, gate) = mount_with_capacity(Operation::HostMetadata, 2).await;
    mounted.open(b"slow\0").await;
    let (release, blocked) = std::sync::mpsc::channel();
    *gate.blocked_drop.lock().unwrap() = Some(blocked);
    mounted.channel.reset().unwrap();
    mounted.initialize_transport();
    mounted.initialize_events().await;
    tokio::time::timeout(Duration::from_secs(3), gate.started.acquire())
        .await
        .unwrap()
        .unwrap()
        .forget();
    let denied = mounted.submit(2, 1, 1, b"fast\0");
    assert_ne!(&mounted.receive(denied).await[4..8], &[0; 4]);
    mounted.request(4097, 1, &[]).await;
    drop(release);
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let attempt = mounted.submit(2, 1, 1, b"fast\0");
            if mounted.receive(attempt).await[4..8] == [0; 4] {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let (release, blocked) = std::sync::mpsc::channel();
    *gate.blocked_drop.lock().unwrap() = Some(blocked);
    mounted.channel.close().unwrap();
    drop(release);
    mounted.runtime.abort_and_join().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn cancellation_uses_the_reserved_descriptors_on_a_full_request_ring() {
    let (_root, mut mounted, gate) = mount().await;
    let mut handles = Vec::new();
    for index in 0..62 {
        handles.push(mounted.open(format!("slot-{index}\0").as_bytes()).await);
    }
    for (index, (node, handle)) in handles.into_iter().enumerate() {
        mounted.submit(
            u16::try_from(index * 2).unwrap(),
            15,
            node,
            &read_body(handle, 0),
        );
    }
    tokio::time::timeout(Duration::from_secs(3), gate.started.acquire_many(32))
        .await
        .unwrap()
        .unwrap()
        .forget();
    let event = mounted.submit(124, 4096, 1, &[]);
    let cancel = mounted.submit(126, 4097, 1, &[]);
    assert_eq!(&mounted.receive(cancel).await[4..8], &[0; 4]);
    assert_ne!(&mounted.receive(event).await[4..8], &[0; 4]);
    mounted.channel.close().unwrap();
    gate.release.notify_waiters();
    mounted.runtime.abort_and_join().await;
}

#[test]
fn saturated_mount_cleanup_does_not_starve_another_mount_or_guest_disk() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        use crate::component::block::backing::{DiskGrant, FileDisk};
        use crate::engine::{TerraHost, terra::host::disk::HostWithStore};

        let (_root, mut stalled, gate) = mount_with_operation(Operation::HostMetadata).await;
        let (_healthy_root, mut healthy, _) = mount_with_operation(Operation::HostMetadata).await;
        for index in 0..40 {
            stalled.open(format!("slot-{index}\0").as_bytes()).await;
        }
        let disk_root = tempfile::tempdir().unwrap();
        let disk_path = disk_root.path().join("disk");
        std::fs::write(&disk_path, b"disk contents").unwrap();
        let mut disk_host = DeviceHost::new(4096).unwrap();
        disk_host.set_disk(DiskGrant::File(FileDisk::open(&disk_path, false).unwrap()));
        let mut disk_store = wasmtime::Store::new(&device_engine().unwrap(), disk_host);

        let (release, blocked) = std::sync::mpsc::channel();
        *gate.blocked_drop.lock().unwrap() = Some(blocked);
        gate.count_blocked_drops.store(true, Ordering::Release);
        stalled.channel.reset().unwrap();
        tokio::time::timeout(
            Duration::from_secs(3),
            gate.drop_started
                .acquire_many(u32::try_from(super::MAX_BLOCKING_THREADS).unwrap()),
        )
        .await
        .unwrap()
        .unwrap()
        .forget();

        tokio::time::timeout(Duration::from_secs(3), async {
            let (node, handle) = healthy.open(b"fast\0").await;
            let mut body = read_body(handle, 0);
            body[16..20].copy_from_slice(&4_u32.to_le_bytes());
            let read = healthy.submit(0, 15, node, &body);
            let reply = healthy.receive(read).await;
            assert_eq!(&reply[16..], b"fast");
            let bytes = disk_store
                .run_concurrent(async |accessor| {
                    let disk = accessor.with_getter::<TerraHost>(|host| host);
                    TerraHost::read_at(&disk, 0, 13).await
                })
                .await
                .unwrap()
                .unwrap();
            assert_eq!(bytes, b"disk contents");
        })
        .await
        .unwrap();
        stalled.channel.close().unwrap();
        stalled.runtime.abort_and_join().await;
        healthy.channel.close().unwrap();
        healthy.runtime.abort_and_join().await;
        drop(release);
    });
    runtime.shutdown_timeout(Duration::from_secs(1));
}

#[tokio::test(flavor = "multi_thread")]
async fn stalled_watcher_registration_allows_startup_io_cancellation_and_shutdown() {
    let (release, blocked) = std::sync::mpsc::channel::<()>();
    let blocked = std::sync::Mutex::new(blocked);
    let entered = Arc::new(Semaphore::new(0));
    let registration_entered = entered.clone();
    let registration = Arc::new(move || {
        registration_entered.add_permits(1);
        let _ = blocked
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(10));
    });
    let setup = mount_with_registration(Operation::HostMetadata, 16_384, Some(registration));
    let (_root, mut mounted, _) = tokio::time::timeout(Duration::from_secs(5), setup)
        .await
        .unwrap();
    assert_eq!(entered.available_permits(), 1);
    let (node, handle) = mounted.open(b"fast\0").await;
    let read = mounted.submit(0, 15, node, &read_body(handle, 0));
    assert_eq!(&mounted.receive(read).await[16..], b"f");
    mounted.request(4097, 1, &[]).await;
    mounted.channel.close().unwrap();
    mounted.runtime.abort_and_join().await;
    drop(release);
}
