#![allow(clippy::expect_used)]

use std::sync::Arc;

use terra_runtime::{
    BoundedMemory, SyntheticRam,
    box_runtime::{BoxHost, BoxRuntime, BoxRuntimeHandle},
    component::fs::host::{FsHost, ShareGrant},
    engine::{DeviceHost, device_engine},
};
use wasmtime::component::Component;

const REQUEST_QUEUE: u32 = 1;
const DESC: u64 = 0x1000;
const AVAIL: u64 = 0x2000;
const USED: u64 = 0x3000;
const INPUT: u64 = 0x4000;
const OUTPUT: u64 = 0x6000;
const SECOND_INPUT: u64 = 0x5000;
const SECOND_OUTPUT: u64 = 0x7000;

fn write(memory: &BoundedMemory<'_>, offset: u64, bytes: &[u8]) {
    memory.write(offset, bytes).expect("guest memory write");
}

fn request(opcode: u32, unique: u64, node: u64, body: &[u8]) -> Vec<u8> {
    let mut request = vec![0; 40];
    request[..4].copy_from_slice(
        &u32::try_from(40 + body.len())
            .expect("request length")
            .to_le_bytes(),
    );
    request[4..8].copy_from_slice(&opcode.to_le_bytes());
    request[8..16].copy_from_slice(&unique.to_le_bytes());
    request[16..24].copy_from_slice(&node.to_le_bytes());
    request.extend_from_slice(body);
    request
}

fn reply_error(reply: &[u8]) -> i32 {
    i32::from_le_bytes(reply[4..8].try_into().expect("reply error"))
}

struct Mounted {
    channel: terra_runtime::component::DeviceChannel,
    ram: SyntheticRam,
    _runtime: BoxRuntimeHandle,
}

async fn mount(path: &std::path::Path, readonly: bool) -> Mounted {
    mount_with_resource_capacity(path, readonly, None).await
}

async fn mount_with_resource_capacity(
    path: &std::path::Path,
    readonly: bool,
    resource_capacity: Option<usize>,
) -> Mounted {
    let ram = SyntheticRam::new(64 * 1024).expect("ram");
    let engine = device_engine().expect("engine");
    let component = Component::new(
        &engine,
        include_bytes!(
            "../../../components/fs/target/wasm32-wasip3/release/terra_fs_component.wasm"
        ),
    )
    .expect("component");
    let grant = ShareGrant::new(path, readonly).expect("grant");
    let device = DeviceHost::with_ram(ram.clone());
    let host = match resource_capacity {
        Some(resource_capacity) => FsHost::with_resource_capacity(device, grant, resource_capacity),
        None => FsHost::new(device, grant),
    };
    let router = Component::new(
        &engine,
        include_bytes!(
            "../../../components/vmm/target/wasm32-wasip3/release/terra_vmm_component.wasm"
        ),
    )
    .expect("MMIO router");
    let mut runtime = BoxRuntime::new(&engine, BoxHost::new()).expect("runtime");
    runtime.initialize_mmio(&router).await.expect("MMIO router");
    let channel = terra_runtime::component::fs::instantiate_shared(
        &mut runtime,
        host,
        &component,
        "test",
        u32::try_from(resource_capacity.unwrap_or(8192).saturating_sub(16) / 2)
            .expect("node capacity"),
        Arc::new(|_| Ok(())),
    )
    .await
    .expect("channel");
    let runtime = runtime.start();
    for (offset, value) in [
        (0x70, 1_u32),
        (0x70, 3),
        (0x24, 1),
        (0x20, 1),
        (0x70, 11),
        (0x30, REQUEST_QUEUE),
        (0x38, 8),
        (0x80, u32::try_from(DESC).expect("descriptor address")),
        (0x90, u32::try_from(AVAIL).expect("available address")),
        (0xa0, u32::try_from(USED).expect("used address")),
        (0x44, 1),
        (0x70, 15),
    ] {
        channel
            .write(offset, &value.to_le_bytes())
            .expect("MMIO setup");
    }
    Mounted {
        channel,
        ram,
        _runtime: runtime,
    }
}

async fn initialize(channel: &terra_runtime::component::DeviceChannel, memory: &BoundedMemory<'_>) {
    let mut init = vec![0; 16];
    init[..4].copy_from_slice(&7_u32.to_le_bytes());
    init[4..8].copy_from_slice(&40_u32.to_le_bytes());
    assert_eq!(
        reply_error(&submit(channel, memory, 0, &request(26, 1, 1, &init)).await),
        0
    );
}

async fn submit(
    channel: &terra_runtime::component::DeviceChannel,
    memory: &BoundedMemory<'_>,
    index: u16,
    request: &[u8],
) -> Vec<u8> {
    write(memory, INPUT, request);
    let mut descriptor = [0; 32];
    descriptor[..8].copy_from_slice(&INPUT.to_le_bytes());
    descriptor[8..12].copy_from_slice(
        &u32::try_from(request.len())
            .expect("request length")
            .to_le_bytes(),
    );
    descriptor[12..14].copy_from_slice(&1_u16.to_le_bytes());
    descriptor[14..16].copy_from_slice(&1_u16.to_le_bytes());
    descriptor[16..24].copy_from_slice(&OUTPUT.to_le_bytes());
    descriptor[24..28].copy_from_slice(&4096_u32.to_le_bytes());
    descriptor[28..30].copy_from_slice(&2_u16.to_le_bytes());
    write(memory, DESC, &descriptor);
    write(memory, AVAIL + 2, &index.wrapping_add(1).to_le_bytes());
    write(
        memory,
        AVAIL + 4 + u64::from(index % 8) * 2,
        &0_u16.to_le_bytes(),
    );
    channel
        .write(0x50, &REQUEST_QUEUE.to_le_bytes())
        .expect("queue bell");
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if memory.read(USED + 2, 2).expect("used index") == index.wrapping_add(1).to_le_bytes()
            {
                let header = memory.read(OUTPUT, 16).expect("reply header");
                let len = u32::from_le_bytes(header[..4].try_into().expect("reply length"));
                return memory.read(OUTPUT, u64::from(len)).expect("reply");
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("filesystem request completion")
}

async fn submit_pair(
    channel: &terra_runtime::component::DeviceChannel,
    memory: &BoundedMemory<'_>,
    first: &[u8],
    second: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    write(memory, INPUT, first);
    write(memory, SECOND_INPUT, second);
    let mut descriptors = [0; 64];
    for (offset, input, output, next) in [
        (0, INPUT, OUTPUT, 1_u16),
        (32, SECOND_INPUT, SECOND_OUTPUT, 3_u16),
    ] {
        descriptors[offset..offset + 8].copy_from_slice(&input.to_le_bytes());
        descriptors[offset + 8..offset + 12].copy_from_slice(
            &u32::try_from(if offset == 0 {
                first.len()
            } else {
                second.len()
            })
            .expect("request length")
            .to_le_bytes(),
        );
        descriptors[offset + 12..offset + 14].copy_from_slice(&1_u16.to_le_bytes());
        descriptors[offset + 14..offset + 16].copy_from_slice(&next.to_le_bytes());
        descriptors[offset + 16..offset + 24].copy_from_slice(&output.to_le_bytes());
        descriptors[offset + 24..offset + 28].copy_from_slice(&4096_u32.to_le_bytes());
        descriptors[offset + 28..offset + 30].copy_from_slice(&2_u16.to_le_bytes());
    }
    write(memory, DESC, &descriptors);
    write(memory, AVAIL + 2, &3_u16.to_le_bytes());
    write(memory, AVAIL + 4 + 2, &0_u16.to_le_bytes());
    write(memory, AVAIL + 4 + 4, &2_u16.to_le_bytes());
    channel
        .write(0x50, &REQUEST_QUEUE.to_le_bytes())
        .expect("queue bell");
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if memory.read(USED + 2, 2).expect("used index") == 3_u16.to_le_bytes() {
                let first = read_reply(memory, OUTPUT);
                let second = read_reply(memory, SECOND_OUTPUT);
                return (first, second);
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both filesystem requests complete")
}

fn read_reply(memory: &BoundedMemory<'_>, output: u64) -> Vec<u8> {
    let header = memory.read(output, 16).expect("reply header");
    let len = u32::from_le_bytes(header[..4].try_into().expect("reply length"));
    memory.read(output, u64::from(len)).expect("reply")
}

fn dirents(reply: &[u8]) -> Vec<(u64, String)> {
    let mut entries = Vec::new();
    let mut offset = 16;
    while offset < reply.len() {
        let next = u64::from_le_bytes(reply[offset + 8..offset + 16].try_into().expect("cookie"));
        let name_len = usize::try_from(u32::from_le_bytes(
            reply[offset + 16..offset + 20]
                .try_into()
                .expect("name length"),
        ))
        .expect("name length fits");
        let name = std::str::from_utf8(&reply[offset + 24..offset + 24 + name_len])
            .expect("UTF-8 fixture")
            .to_owned();
        offset += (24 + name_len).next_multiple_of(8);
        entries.push((next, name));
    }
    entries
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
#[allow(clippy::too_many_lines)]
async fn wasm_filesystem_component_serves_files_through_standard_wasi() {
    let root = tempfile::tempdir().expect("tempdir");
    std::fs::write(root.path().join("visible"), b"data").expect("fixture");
    std::os::unix::fs::symlink("visible", root.path().join("link")).expect("symlink fixture");
    let Mounted {
        channel,
        ram,
        _runtime,
    } = mount(root.path(), false).await;
    let memory = BoundedMemory::new(&ram);
    initialize(&channel, &memory).await;
    let lookup = submit(&channel, &memory, 1, &request(1, 2, 1, b"visible\0")).await;
    assert_eq!(reply_error(&lookup), 0);
    let visible = u64::from_le_bytes(lookup[16..24].try_into().expect("inode"));
    assert_ne!(visible, 0);
    let open = submit(
        &channel,
        &memory,
        2,
        &request(14, 3, visible, &0_u32.to_le_bytes()),
    )
    .await;
    assert_eq!(reply_error(&open), 0);
    let handle = u64::from_le_bytes(open[16..24].try_into().expect("handle"));
    let mut read = vec![0; 24];
    read[..8].copy_from_slice(&handle.to_le_bytes());
    read[16..20].copy_from_slice(&4_u32.to_le_bytes());
    let read = submit(&channel, &memory, 3, &request(15, 4, visible, &read)).await;
    assert_eq!(reply_error(&read), 0);
    assert_eq!(&read[16..], b"data");

    let link = submit(&channel, &memory, 4, &request(1, 5, 1, b"link\0")).await;
    assert_eq!(reply_error(&link), 0);
    let link = u64::from_le_bytes(link[16..24].try_into().expect("link inode"));
    let target = submit(&channel, &memory, 5, &request(5, 6, link, &[])).await;
    assert_eq!(reply_error(&target), 0);
    assert_eq!(&target[16..], b"visible");

    let mut create = vec![0; 16];
    create[..4].copy_from_slice(&(0o100_u32 | 2).to_le_bytes());
    create[4..8].copy_from_slice(&0o600_u32.to_le_bytes());
    create.extend_from_slice(b"written\0");
    let created = submit(&channel, &memory, 6, &request(35, 7, 1, &create)).await;
    assert_eq!(reply_error(&created), 0);
    let inode = u64::from_le_bytes(created[16..24].try_into().expect("created inode"));
    assert_eq!(
        u32::from_le_bytes(created[116..120].try_into().expect("created mode")),
        0o100_600
    );
    assert_eq!(
        std::os::unix::fs::MetadataExt::mode(
            &std::fs::metadata(root.path().join("written")).expect("created metadata")
        ),
        0o100_600
    );
    let handle = u64::from_le_bytes(created[144..152].try_into().expect("created handle"));
    let mut write = vec![0; 40];
    write[..8].copy_from_slice(&handle.to_le_bytes());
    write[16..20].copy_from_slice(&3_u32.to_le_bytes());
    write.extend_from_slice(b"new");
    let written = submit(&channel, &memory, 7, &request(16, 8, inode, &write)).await;
    assert_eq!(reply_error(&written), 0);
    assert_eq!(
        u32::from_le_bytes(written[16..20].try_into().expect("written bytes")),
        3
    );
    let mut read = vec![0; 24];
    read[..8].copy_from_slice(&handle.to_le_bytes());
    read[16..20].copy_from_slice(&3_u32.to_le_bytes());
    let read = submit(&channel, &memory, 8, &request(15, 9, inode, &read)).await;
    assert_eq!(reply_error(&read), 0);
    assert_eq!(&read[16..], b"new");
    let getattr = submit(&channel, &memory, 9, &request(3, 10, inode, &[])).await;
    assert_eq!(reply_error(&getattr), 0);
    assert_eq!(
        u32::from_le_bytes(getattr[92..96].try_into().expect("getattr mode")),
        0o100_600
    );
    let mut setattr = vec![0; 84];
    setattr[..4].copy_from_slice(&1_u32.to_le_bytes());
    setattr[68..72].copy_from_slice(&0o100_640_u32.to_le_bytes());
    let setattr = submit(&channel, &memory, 10, &request(4, 11, inode, &setattr)).await;
    assert_eq!(reply_error(&setattr), 0);
    assert_eq!(
        u32::from_le_bytes(setattr[92..96].try_into().expect("setattr mode")),
        0o100_640
    );
    let mut rename = 1_u64.to_le_bytes().to_vec();
    rename.extend_from_slice(b"written\0renamed\0");
    assert_eq!(
        reply_error(&submit(&channel, &memory, 11, &request(12, 12, 1, &rename)).await),
        0
    );
    assert_eq!(
        std::fs::read(root.path().join("renamed")).expect("renamed file"),
        b"new"
    );
    assert_eq!(
        reply_error(&submit(&channel, &memory, 12, &request(10, 13, 1, b"renamed\0")).await),
        0
    );
    let mut read = vec![0; 24];
    read[..8].copy_from_slice(&handle.to_le_bytes());
    read[16..20].copy_from_slice(&3_u32.to_le_bytes());
    let reply = submit(&channel, &memory, 13, &request(15, 14, inode, &read)).await;
    assert_eq!(reply_error(&reply), 0);
    assert_eq!(&reply[16..], b"new");
    let mut rename_link = 1_u64.to_le_bytes().to_vec();
    rename_link.extend_from_slice(b"link\0renamed-link\0");
    assert_eq!(
        reply_error(&submit(&channel, &memory, 14, &request(12, 15, 1, &rename_link)).await),
        0
    );
    let target = submit(&channel, &memory, 15, &request(5, 16, link, &[])).await;
    assert_eq!(reply_error(&target), 0);
    assert_eq!(&target[16..], b"visible");
    let statfs = submit(&channel, &memory, 16, &request(17, 17, 1, &[])).await;
    assert_eq!(reply_error(&statfs), 0);
    assert_ne!(
        u64::from_le_bytes(statfs[16..24].try_into().expect("blocks")),
        0
    );
    assert_ne!(
        u32::from_le_bytes(statfs[56..60].try_into().expect("block size")),
        0
    );
    channel.close().expect("close");
    assert!(!root.path().join("renamed").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_filesystem_component_retains_linked_nodes_after_forget() {
    let root = tempfile::tempdir().expect("tempdir");
    for name in ["linked", "spare", "replacement"] {
        std::fs::write(root.path().join(name), []).expect("fixture");
    }
    let Mounted {
        channel,
        ram,
        _runtime,
    } = mount_with_resource_capacity(root.path(), false, Some(22)).await;
    let memory = BoundedMemory::new(&ram);
    initialize(&channel, &memory).await;
    let linked = submit(&channel, &memory, 1, &request(1, 2, 1, b"linked\0")).await;
    let linked_node = u64::from_le_bytes(linked[16..24].try_into().expect("linked node"));
    let mut link = linked_node.to_le_bytes().to_vec();
    link.extend_from_slice(b"second-link\0");
    assert_eq!(
        reply_error(&submit(&channel, &memory, 2, &request(13, 3, 1, &link)).await),
        0
    );
    submit(
        &channel,
        &memory,
        3,
        &request(2, 4, linked_node, &1_u64.to_le_bytes()),
    )
    .await;
    let spare = submit(&channel, &memory, 4, &request(1, 5, 1, b"spare\0")).await;
    let spare_node = u64::from_le_bytes(spare[16..24].try_into().expect("spare node"));
    submit(
        &channel,
        &memory,
        5,
        &request(2, 6, spare_node, &1_u64.to_le_bytes()),
    )
    .await;
    assert_eq!(
        reply_error(&submit(&channel, &memory, 6, &request(1, 7, 1, b"replacement\0")).await),
        0
    );
    assert_eq!(
        reply_error(&submit(&channel, &memory, 7, &request(3, 8, linked_node, &[])).await),
        0
    );
    channel.close().expect("close");
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn wasm_filesystem_component_create_rejects_existing_fifo() {
    let root = tempfile::tempdir().expect("tempdir");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        root.path().join("fifo"),
        rustix::fs::Mode::empty(),
    )
    .expect("FIFO fixture");
    let Mounted {
        channel,
        ram,
        _runtime,
    } = mount(root.path(), false).await;
    let memory = BoundedMemory::new(&ram);
    initialize(&channel, &memory).await;
    let mut create = vec![0; 16];
    create[..4].copy_from_slice(&(0o100_u32 | 2).to_le_bytes());
    create[4..8].copy_from_slice(&0o600_u32.to_le_bytes());
    create.extend_from_slice(b"fifo\0");
    let reply = submit(&channel, &memory, 1, &request(35, 2, 1, &create)).await;
    assert_eq!(reply_error(&reply), -95);
    channel.close().expect("close");
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_filesystem_component_enforces_readonly_grant() {
    let root = tempfile::tempdir().expect("tempdir");
    let Mounted {
        channel,
        ram,
        _runtime,
    } = mount(root.path(), true).await;
    let memory = BoundedMemory::new(&ram);
    initialize(&channel, &memory).await;
    let mut create = vec![0; 16];
    create[..4].copy_from_slice(&(0o100_u32 | 2).to_le_bytes());
    create[4..8].copy_from_slice(&0o644_u32.to_le_bytes());
    create.extend_from_slice(b"denied\0");
    let reply = submit(&channel, &memory, 1, &request(35, 2, 1, &create)).await;
    assert_eq!(reply_error(&reply), -13);
    channel.close().expect("close");
    assert!(!root.path().join("denied").exists());
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn wasm_filesystem_component_refreshes_a_relooked_up_node_path() {
    let root = tempfile::tempdir().expect("tempdir");
    std::os::unix::fs::symlink("first", root.path().join("old")).expect("symlink fixture");
    std::fs::hard_link(root.path().join("old"), root.path().join("new"))
        .expect("hard link fixture");
    let Mounted {
        channel,
        ram,
        _runtime,
    } = mount(root.path(), false).await;
    let memory = BoundedMemory::new(&ram);
    initialize(&channel, &memory).await;
    let old = submit(&channel, &memory, 1, &request(1, 2, 1, b"old\0")).await;
    let node = u64::from_le_bytes(old[16..24].try_into().expect("old node"));
    let new = submit(&channel, &memory, 2, &request(1, 3, 1, b"new\0")).await;
    assert_eq!(reply_error(&new), 0);
    assert_eq!(
        u64::from_le_bytes(new[16..24].try_into().expect("new node")),
        node
    );
    assert_eq!(
        reply_error(&submit(&channel, &memory, 3, &request(10, 4, 1, b"old\0")).await),
        0
    );
    assert_eq!(
        reply_error(&submit(&channel, &memory, 4, &request(1, 5, 1, b"new\0")).await),
        0
    );
    let target = submit(&channel, &memory, 5, &request(5, 6, node, &[])).await;
    assert_eq!(reply_error(&target), 0);
    assert_eq!(&target[16..], b"first");
    channel.close().expect("close");
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn wasm_filesystem_component_clears_an_unlinked_node_path() {
    let root = tempfile::tempdir().expect("tempdir");
    std::os::unix::fs::symlink("first", root.path().join("link")).expect("symlink fixture");
    let Mounted {
        channel,
        ram,
        _runtime,
    } = mount(root.path(), false).await;
    let memory = BoundedMemory::new(&ram);
    initialize(&channel, &memory).await;
    let lookup = submit(&channel, &memory, 1, &request(1, 2, 1, b"link\0")).await;
    let node = u64::from_le_bytes(lookup[16..24].try_into().expect("link node"));
    assert_eq!(
        reply_error(&submit(&channel, &memory, 2, &request(10, 3, 1, b"link\0")).await),
        0
    );
    assert_eq!(
        reply_error(&submit(&channel, &memory, 3, &request(5, 4, node, &[])).await),
        -95
    );
    channel.close().expect("close");
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_filesystem_component_recovers_after_resource_table_exhaustion() {
    let root = tempfile::tempdir().expect("tempdir");
    for index in 0..128 {
        std::fs::write(root.path().join(format!("file-{index}")), []).expect("fixture");
    }
    let Mounted {
        channel,
        ram,
        _runtime,
    } = mount_with_resource_capacity(root.path(), false, Some(64)).await;
    let memory = BoundedMemory::new(&ram);
    initialize(&channel, &memory).await;

    let mut nodes = Vec::new();
    let mut exhausted = None;
    for index in 0..128_u16 {
        let name = format!("file-{index}\0");
        let reply = submit(
            &channel,
            &memory,
            index.wrapping_add(1),
            &request(1, u64::from(index) + 2, 1, name.as_bytes()),
        )
        .await;
        if reply_error(&reply) == 0 {
            nodes.push(u64::from_le_bytes(reply[16..24].try_into().expect("node")));
        } else {
            exhausted = Some((index, reply_error(&reply)));
            break;
        }
    }
    let (index, error) = exhausted.expect("resource table fills");
    assert_eq!(error, -24);
    let node = nodes.pop().expect("a node before exhaustion");
    submit(
        &channel,
        &memory,
        index.wrapping_add(2),
        &request(2, u64::from(index) + 130, node, &1_u64.to_le_bytes()),
    )
    .await;
    tokio::task::yield_now().await;
    let name = format!("file-{index}\0");
    let reply = submit(
        &channel,
        &memory,
        index.wrapping_add(3),
        &request(1, u64::from(index) + 131, 1, name.as_bytes()),
    )
    .await;
    assert_eq!(reply_error(&reply), 0);
    channel.close().expect("close");
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_filesystem_component_handles_directory_operations_and_deleted_entries() {
    let root = tempfile::tempdir().expect("tempdir");
    for name in ["a", "b", "c"] {
        std::fs::write(root.path().join(name), b"data").expect("fixture");
    }
    let Mounted {
        channel,
        ram,
        _runtime,
    } = mount(root.path(), false).await;
    let memory = BoundedMemory::new(&ram);
    initialize(&channel, &memory).await;

    let source = submit(&channel, &memory, 1, &request(1, 2, 1, b"a\0")).await;
    let source = u64::from_le_bytes(source[16..24].try_into().expect("source inode"));

    let mut mkdir = vec![0; 8];
    mkdir[..4].copy_from_slice(&0o755_u32.to_le_bytes());
    mkdir.extend_from_slice(b"directory\0");
    assert_eq!(
        reply_error(&submit(&channel, &memory, 2, &request(9, 3, 1, &mkdir)).await),
        0
    );

    let mut link = source.to_le_bytes().to_vec();
    link.extend_from_slice(b"linked\0");
    assert_eq!(
        reply_error(&submit(&channel, &memory, 3, &request(13, 4, 1, &link)).await),
        0
    );

    let mut truncate = vec![0; 84];
    truncate[..4].copy_from_slice(&8_u32.to_le_bytes());
    truncate[16..24].copy_from_slice(&2_u64.to_le_bytes());
    assert_eq!(
        reply_error(&submit(&channel, &memory, 4, &request(4, 5, source, &truncate)).await),
        0
    );
    assert_eq!(
        std::fs::read(root.path().join("linked")).expect("hard link"),
        b"da"
    );

    let directory = submit(&channel, &memory, 5, &request(27, 6, 1, &[])).await;
    let directory = u64::from_le_bytes(directory[16..24].try_into().expect("directory handle"));
    let mut readdir = vec![0; 24];
    readdir[..8].copy_from_slice(&directory.to_le_bytes());
    readdir[16..20].copy_from_slice(&4096_u32.to_le_bytes());
    let entries = dirents(&submit(&channel, &memory, 6, &request(28, 7, 1, &readdir)).await);
    assert!(entries.iter().any(|(_, name)| name == "directory"));
    let (deleted_index, (_, deleted_name)) = entries
        .iter()
        .enumerate()
        .find(|(index, (_, name))| *index > 0 && matches!(name.as_str(), "a" | "b" | "c"))
        .expect("a removable entry after the first");
    let deleted_name = deleted_name.clone();
    std::fs::remove_file(root.path().join(&deleted_name)).expect("remove cached entry");
    readdir[8..16].copy_from_slice(&entries[deleted_index - 1].0.to_le_bytes());
    let entries = dirents(&submit(&channel, &memory, 7, &request(28, 8, 1, &readdir)).await);
    assert!(!entries.iter().any(|(_, name)| name == &deleted_name));
    channel.close().expect("close");
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_worker_drains_a_single_doorbell_without_native_queue_scheduling() {
    let root = tempfile::tempdir().expect("tempdir");
    let Mounted {
        channel,
        ram,
        _runtime,
    } = mount(root.path(), false).await;
    let memory = BoundedMemory::new(&ram);
    initialize(&channel, &memory).await;
    let first = request(3, 2, 1, &[]);
    let second = request(3, 3, 1, &[]);
    let (first, second) = submit_pair(&channel, &memory, &first, &second).await;
    assert_eq!(reply_error(&first), 0);
    assert_eq!(reply_error(&second), 0);
    assert_eq!(
        memory.read(USED + 12, 4).expect("first used head"),
        0_u32.to_le_bytes()
    );
    assert_eq!(
        memory.read(USED + 20, 4).expect("second used head"),
        2_u32.to_le_bytes()
    );
    channel.reset().expect("reset stays live");
    assert_eq!(
        channel.read(0, 4).expect("MMIO remains live"),
        0x7472_6976_u32.to_le_bytes()
    );
    channel.close().expect("close");
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_filesystem_component_rejects_unsupported_opcodes_without_parsing() {
    let root = tempfile::tempdir().expect("tempdir");
    let Mounted {
        channel,
        ram,
        _runtime,
    } = mount(root.path(), false).await;
    let memory = BoundedMemory::new(&ram);
    initialize(&channel, &memory).await;
    for (index, opcode) in (1_u16..).zip([21, 22, 23, 24, 31, 32, 33, 43, 46, 50]) {
        let reply = submit(
            &channel,
            &memory,
            index,
            &request(opcode, u64::from(index) + 1, u64::MAX, &[]),
        )
        .await;
        assert_eq!(reply_error(&reply), -95, "opcode {opcode}");
    }
    channel.close().expect("close");
}
