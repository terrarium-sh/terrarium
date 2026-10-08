use std::path::Path;
use std::sync::Arc;

use wasmtime::error::Context as _;
use wasmtime::{Engine, Result, ensure};

use crate::TrustedArtifacts;
use crate::box_runtime::{BoxHost, BoxRuntime, BoxRuntimeHandle};
use crate::component::MmioDevice;
use crate::component::context::DeviceContext;
use crate::component::fs::{FsHost, ShareGrant};
use crate::memory::GuestRam;

use super::{configure_queue, read_memory, submit_descriptors, write_memory};

const REQUEST_QUEUE: u32 = 1;
const INPUT: u64 = 0x4000;
const OUTPUT: u64 = 0x6000;
const REPLY_CAPACITY: u32 = 4096;

#[cfg(windows)]
fn is_vm_sandbox_worker() -> bool {
    std::env::var_os("TERRA_WINDOWS_SANDBOX_ROLE").is_some_and(|role| role == "vm")
}

#[cfg(windows)]
fn is_vm_app_container() -> bool {
    is_vm_sandbox_worker()
        && std::env::var_os("TERRA_WINDOWS_SANDBOX_MODE")
            .is_some_and(|mode| mode == "app_container")
}

struct Share {
    channel: MmioDevice,
    ram: GuestRam,
    runtime: BoxRuntimeHandle,
    index: u16,
}

impl Share {
    async fn mount(
        artifacts: &TrustedArtifacts,
        engine: &Engine,
        directory: &Path,
        readonly: bool,
    ) -> Result<Self> {
        let ram = GuestRam::new(64 * 1024)
            .ok_or_else(|| wasmtime::Error::msg("filesystem self-test RAM allocation"))?;
        let component = artifacts.fs().deserialize(engine)?;
        #[cfg(windows)]
        let grant = if is_vm_sandbox_worker() {
            let name = if readonly {
                "TERRA_WINDOWS_SELF_TEST_READONLY_ID"
            } else {
                "TERRA_WINDOWS_SELF_TEST_WRITABLE_ID"
            };
            let identity = std::env::var(name)?.parse()?;
            ShareGrant::new_host_granted(directory, readonly, identity)
        } else {
            ShareGrant::new(&directory.canonicalize()?, readonly)
        };
        #[cfg(not(windows))]
        let grant = ShareGrant::new(&directory.canonicalize()?, readonly);
        let grant = grant.map_err(|error| {
            wasmtime::Error::from(error).context(format!(
                "opening filesystem self-test share {}",
                directory.display()
            ))
        })?;
        let host = FsHost::new(DeviceContext::with_ram(ram.clone()), grant);
        let mut runtime = BoxRuntime::new(engine, BoxHost::new())?;
        runtime.initialize_mmio()?;
        let channel = crate::component::fs::register_device(
            &mut runtime,
            host,
            &component,
            "self_test",
            128,
            Arc::new(|_| Ok(())),
        )?;
        let runtime = runtime.prepare().await?.start();
        configure_queue(&channel, REQUEST_QUEUE, 0)?;
        let mut share = Self {
            channel,
            ram,
            runtime,
            index: 0,
        };
        let mut init = vec![0; 20];
        init[..4].copy_from_slice(&7_u32.to_le_bytes());
        init[4..8].copy_from_slice(&40_u32.to_le_bytes());
        init[12..16].copy_from_slice(&(1_u32 << 30).to_le_bytes());
        init[16..20].copy_from_slice(&(1_u32 << 31).to_le_bytes());
        let reply = share.request(26, 1, &init, 0).await?;
        ensure!(read_u32(&reply, 48)? == 1 << 31, "file events negotiation");
        Ok(share)
    }

    async fn request(
        &mut self,
        opcode: u32,
        node: u64,
        body: &[u8],
        expected_error: i32,
    ) -> Result<Vec<u8>> {
        let unique = u64::from(self.index) + 1;
        let mut request = vec![0; 40];
        request[..4].copy_from_slice(&u32::try_from(40 + body.len())?.to_le_bytes());
        request[4..8].copy_from_slice(&opcode.to_le_bytes());
        request[8..16].copy_from_slice(&unique.to_le_bytes());
        request[16..24].copy_from_slice(&node.to_le_bytes());
        request.extend_from_slice(body);
        ensure!(
            request.len() <= 8192,
            "filesystem request exceeds input buffer"
        );
        write_memory(&self.ram, INPUT, &request)?;
        submit_descriptors(
            &self.channel,
            &self.ram,
            REQUEST_QUEUE,
            self.index,
            &[
                (INPUT, u32::try_from(request.len())?, 1),
                (OUTPUT, REPLY_CAPACITY, 2),
            ],
        )
        .await?;
        self.index = self.index.wrapping_add(1);
        let header = read_memory(&self.ram, OUTPUT, 16)?;
        let length = read_u32(&header, 0)?;
        ensure!(
            (16..=REPLY_CAPACITY).contains(&length),
            "filesystem reply length"
        );
        let reply = read_memory(&self.ram, OUTPUT, u64::from(length))?;
        let error = i32::from_le_bytes(reply[4..8].try_into()?);
        ensure!(read_u64(&reply, 8)? == unique, "filesystem reply identity");
        ensure!(
            error == expected_error,
            "filesystem opcode {opcode}: expected {expected_error}, got {error}"
        );
        Ok(reply)
    }

    async fn close(self) -> Result<()> {
        self.channel.close()?;
        self.runtime.join().await
    }
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let field = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| wasmtime::Error::msg("short filesystem u32 field"))?;
    Ok(u32::from_le_bytes(field.try_into()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64> {
    let field = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| wasmtime::Error::msg("short filesystem u64 field"))?;
    Ok(u64::from_le_bytes(field.try_into()?))
}

fn file_io_body(handle: u64, offset: u64, size: u32) -> Vec<u8> {
    let mut body = vec![0; 40];
    body[..8].copy_from_slice(&handle.to_le_bytes());
    body[8..16].copy_from_slice(&offset.to_le_bytes());
    body[16..20].copy_from_slice(&size.to_le_bytes());
    body
}

fn create_body(name: &[u8]) -> Vec<u8> {
    let mut body = vec![0; 16];
    body[..4].copy_from_slice(&2_u32.to_le_bytes());
    body[4..8].copy_from_slice(&0o600_u32.to_le_bytes());
    body.extend_from_slice(name);
    body
}

fn mkdir_body() -> Vec<u8> {
    let mut body = vec![0; 8];
    body[..4].copy_from_slice(&0o755_u32.to_le_bytes());
    body.extend_from_slice(b"directory\0");
    body
}

fn rename_body() -> Vec<u8> {
    let mut body = 1_u64.to_le_bytes().to_vec();
    body.extend_from_slice(b"file\0renamed\0");
    body
}

fn link_body(node: u64) -> Vec<u8> {
    let mut body = node.to_le_bytes().to_vec();
    body.extend_from_slice(b"linked\0");
    body
}

fn setattr_body() -> Vec<u8> {
    let mut body = vec![0; 84];
    body[..4].copy_from_slice(&9_u32.to_le_bytes());
    body[16..24].copy_from_slice(&7_u64.to_le_bytes());
    body[68..72].copy_from_slice(&0o640_u32.to_le_bytes());
    body
}

fn directory_names(reply: &[u8]) -> Result<Vec<&[u8]>> {
    let mut names = Vec::new();
    let mut offset = 16;
    while offset < reply.len() {
        let length = usize::try_from(read_u32(reply, offset + 16)?)?;
        let name = reply
            .get(offset + 24..offset + 24 + length)
            .ok_or_else(|| wasmtime::Error::msg("short filesystem directory entry"))?;
        names.push(name);
        offset += (24 + length).next_multiple_of(8);
    }
    ensure!(offset == reply.len(), "filesystem directory alignment");
    Ok(names)
}

pub(super) async fn run(
    artifacts: &TrustedArtifacts,
    engine: &Engine,
    directory: &Path,
) -> Result<()> {
    let writable = directory.join("writable");
    let readonly = directory.join("readonly");
    std::fs::create_dir_all(&writable).context("creating writable filesystem fixture")?;
    std::fs::create_dir_all(readonly.join("directory"))
        .context("creating read-only filesystem fixture")?;
    std::fs::write(readonly.join("file"), b"readonly fixture")
        .context("writing read-only filesystem fixture")?;
    run_writable(artifacts, engine, &writable)
        .await
        .context("writable filesystem fixture")?;
    run_readonly(artifacts, engine, &readonly)
        .await
        .context("read-only filesystem fixture")
}

async fn run_writable(
    artifacts: &TrustedArtifacts,
    engine: &Engine,
    directory: &Path,
) -> Result<()> {
    let mut share = Share::mount(artifacts, engine, directory, false)
        .await
        .context("mounting writable filesystem share")?;
    let (node, handle) = exercise_file_io(&mut share, directory).await?;
    share.request(12, 1, &rename_body(), 0).await?;
    ensure!(
        !directory.join("file").exists(),
        "filesystem rename removes source"
    );
    let looked_up = share.request(1, 1, b"renamed\0", 0).await?;
    ensure!(
        read_u64(&looked_up, 16)? == node,
        "filesystem rename preserves node"
    );
    share.request(13, 1, &link_body(node), 0).await?;
    ensure!(
        std::fs::read(directory.join("linked"))? == b"filesys",
        "filesystem hardlink readback"
    );
    let app_container = exercise_symlink(&mut share, directory).await?;
    share.request(9, 1, &mkdir_body(), 0).await?;
    ensure!(
        directory.join("directory").is_dir(),
        "filesystem mkdir host readback"
    );
    let opened = share.request(27, 1, &[], 0).await?;
    let directory_handle = read_u64(&opened, 16)?;
    let entries = share
        .request(28, 1, &file_io_body(directory_handle, 0, 4096), 0)
        .await?;
    let names = directory_names(&entries)?;
    let expected_names: &[&[u8]] = if app_container {
        &[b"renamed", b"linked", b"directory"]
    } else {
        &[b"renamed", b"linked", b"symlink", b"directory"]
    };
    for name in expected_names {
        ensure!(
            names.contains(name),
            "filesystem readdir misses {}",
            String::from_utf8_lossy(name)
        );
    }
    let filesystem = share.request(17, 1, &[], 0).await?;
    ensure!(
        read_u64(&filesystem, 16)? > 0 && read_u32(&filesystem, 56)? > 0,
        "filesystem statfs capacity"
    );
    let opened = share.request(14, node, &0_u32.to_le_bytes(), 0).await?;
    let read_handle = read_u64(&opened, 16)?;
    let read = share
        .request(15, node, &file_io_body(read_handle, 0, 4096), 0)
        .await?;
    ensure!(&read[16..] == b"filesys", "filesystem reopened readback");
    for released_handle in [handle, read_handle] {
        let mut release = vec![0; 24];
        release[..8].copy_from_slice(&released_handle.to_le_bytes());
        share.request(18, node, &release, 0).await?;
    }
    share
        .request(29, 1, &directory_handle.to_le_bytes(), 0)
        .await?;
    let removed_names: &[&[u8]] = if app_container {
        &[b"linked\0", b"renamed\0"]
    } else {
        &[b"symlink\0", b"linked\0", b"renamed\0"]
    };
    for name in removed_names {
        share.request(10, 1, name, 0).await?;
    }
    share.request(11, 1, b"directory\0", 0).await?;
    share.request(1, 1, b"renamed\0", -2).await?;
    ensure!(
        std::fs::read_dir(directory)?.next().is_none(),
        "filesystem unlink/rmdir host readback"
    );
    share.close().await
}

async fn exercise_symlink(share: &mut Share, directory: &Path) -> Result<bool> {
    #[cfg(windows)]
    let app_container = is_vm_app_container();
    #[cfg(not(windows))]
    let app_container = false;
    if app_container {
        share.request(6, 1, b"symlink\0renamed\0", -13).await?;
        match std::fs::symlink_metadata(directory.join("symlink")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
            Ok(_) => {
                return Err(wasmtime::Error::msg(
                    "Windows AppContainer created a symlink despite access denial",
                ));
            }
        }
        log::info!(
            "Windows AppContainer does not permit symbolic link creation; filesystem self-test verified access denial and continues"
        );
    } else {
        #[cfg(windows)]
        let symlink = share
            .request(6, 1, b"symlink\0renamed\0", 0)
            .await
            .map_err(|error| {
                error.context(
                    "Windows symlink creation failed; enable Developer Mode or grant the symlink privilege",
                )
            })?;
        #[cfg(not(windows))]
        let symlink = share.request(6, 1, b"symlink\0renamed\0", 0).await?;
        let symlink_node = read_u64(&symlink, 16)?;
        let target = share.request(5, symlink_node, &[], 0).await?;
        ensure!(&target[16..] == b"renamed", "filesystem symlink target");
        ensure!(
            std::fs::read_link(directory.join("symlink"))? == Path::new("renamed"),
            "filesystem host symlink readback"
        );
    }
    Ok(app_container)
}

async fn exercise_file_io(share: &mut Share, directory: &Path) -> Result<(u64, u64)> {
    let created = share.request(35, 1, &create_body(b"file\0"), 0).await?;
    let node = read_u64(&created, 16)?;
    let handle = read_u64(&created, 144)?;
    let payload = b"filesystem self-test writes through WASI";
    let mut write = file_io_body(handle, 0, u32::try_from(payload.len())?);
    write.extend_from_slice(payload);
    let written = share.request(16, node, &write, 0).await?;
    ensure!(
        usize::try_from(read_u32(&written, 16)?)? == payload.len(),
        "filesystem write count"
    );
    let mut sync = vec![0; 16];
    sync[..8].copy_from_slice(&handle.to_le_bytes());
    share.request(20, node, &sync, 0).await?;
    ensure!(
        std::fs::read(directory.join("file"))? == payload,
        "filesystem host write readback"
    );
    let read = share
        .request(15, node, &file_io_body(handle, 0, 4096), 0)
        .await?;
    ensure!(&read[16..] == payload, "filesystem component readback");
    let stat = share.request(3, node, &[], 0).await?;
    ensure!(
        read_u64(&stat, 40)? == u64::try_from(payload.len())?,
        "filesystem stat size"
    );
    let changed = share.request(4, node, &setattr_body(), 0).await?;
    ensure!(read_u64(&changed, 40)? == 7, "filesystem truncate stat");
    #[cfg(unix)]
    ensure!(
        read_u32(&changed, 92)? & 0o777 == 0o640,
        "filesystem mode change"
    );
    ensure!(
        std::fs::read(directory.join("file"))? == b"filesys",
        "filesystem host truncate readback"
    );
    Ok((node, handle))
}

async fn run_readonly(
    artifacts: &TrustedArtifacts,
    engine: &Engine,
    directory: &Path,
) -> Result<()> {
    let mut share = Share::mount(artifacts, engine, directory, true).await?;
    let looked_up = share.request(1, 1, b"file\0", 0).await?;
    let node = read_u64(&looked_up, 16)?;
    let opened = share.request(14, node, &0_u32.to_le_bytes(), 0).await?;
    let handle = read_u64(&opened, 16)?;
    let read = share
        .request(15, node, &file_io_body(handle, 0, 4096), 0)
        .await?;
    ensure!(
        &read[16..] == b"readonly fixture",
        "readonly filesystem read"
    );
    share.request(14, node, &2_u32.to_le_bytes(), -1).await?;
    share.request(4, node, &setattr_body(), -13).await?;
    share.request(35, 1, &create_body(b"new\0"), -1).await?;
    share.request(9, 1, &mkdir_body(), -1).await?;
    share.request(12, 1, &rename_body(), -1).await?;
    share.request(13, 1, &link_body(node), -1).await?;
    share.request(6, 1, b"symlink\0file\0", -1).await?;
    share.request(10, 1, b"file\0", -1).await?;
    share.request(11, 1, b"directory\0", -1).await?;
    let mut write = file_io_body(handle, 0, 1);
    write.push(b'x');
    share.request(16, node, &write, -9).await?;
    ensure!(
        std::fs::read(directory.join("file"))? == b"readonly fixture",
        "readonly filesystem preserves host contents"
    );
    std::fs::write(directory.join("host-event"), b"native watcher peer")?;
    let event = share.request(4096, 1, &[], 0).await?;
    ensure!(event.len() == 296, "filesystem event length");
    ensure!(read_u64(&event, 16)? == 1, "filesystem event parent");
    ensure!(
        read_u32(&event, 36)? == 10 && event.get(40..50) == Some(b"host-event"),
        "native filesystem event name"
    );
    share.close().await
}
