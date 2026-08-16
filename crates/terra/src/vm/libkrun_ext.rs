//! Safe wrappers over libkrun's C-shaped API (the vendored `vendor/libkrun`
//! crate: negated-errno returns, C-string paths).
//
// ponytail: surface kept minimal - add signatures only as features need them.

#![allow(unsafe_code)]

use anyhow::{Context, Result, bail};
use std::ffi::CString;
use std::fs::File;
use std::os::unix::net::UnixStream;
use std::path::Path;

/// No offload, MUST be 0: stock libkrun's unixstream backend never finalizes
/// the guest's partial TCP/UDP checksums and the gateway verifies them, so
/// offload drops every frame silently (ping works, everything else hangs).
const NET_FEATURES: u32 = 0;

use krun::{
    krun_add_disk, krun_add_net_unixstream, krun_add_virtio_console_default, krun_add_virtiofs3,
    krun_add_vsock, krun_add_vsock_port2, krun_create_ctx, krun_free_ctx, krun_set_kernel,
    krun_set_vm_config, krun_start_enter,
};

const KERNEL_FORMAT_ELF: u32 = 1;

/// libkrun's path-taking entry points call `CStr::to_str` internally, so a
/// non-UTF-8 path is a clear error here instead of a panic there.
fn c_path(path: &Path) -> Result<CString> {
    let text = path.to_str().with_context(|| {
        format!(
            "libkrun needs a UTF-8 path, and this is not: {}",
            path.display()
        )
    })?;
    CString::new(text).with_context(|| format!("path contains a NUL byte: {}", path.display()))
}

/// The guest console's descriptors; dropping it closes the console, so keep it
/// for the VM's lifetime.
#[must_use]
pub struct Console {
    _output: File,
    _input: File,
}

/// libkrun's error convention: a negative return is a negated errno.
fn check_krun_rc(rc: i32, what: &str) -> Result<()> {
    if rc < 0 {
        bail!(
            "{what} failed: {} ({rc})",
            std::io::Error::from_raw_os_error(-rc)
        );
    }
    Ok(())
}

/// RAII handle for a libkrun context.
pub struct Krun {
    ctx_id: u32,
}

impl Krun {
    pub fn create() -> Result<Self> {
        let ctx_id = krun_create_ctx();
        check_krun_rc(ctx_id, "krun_create_ctx")?;
        #[allow(clippy::cast_sign_loss)]
        Ok(Self {
            ctx_id: ctx_id as u32,
        })
    }

    pub fn set_vm_config(&self, vcpus: u8, ram_mib: u32) -> Result<()> {
        check_krun_rc(
            krun_set_vm_config(self.ctx_id, vcpus, ram_mib),
            "krun_set_vm_config",
        )
    }

    /// Point libkrun at the guest kernel. A path, because libkrun takes no
    /// bytes - which is why the embedded kernel is unpacked before this.
    pub fn set_kernel(&self, kernel: &Path, cmdline: &str) -> Result<()> {
        let path = c_path(kernel)?;
        let cmdline = CString::new(cmdline).context("kernel cmdline is not a valid C string")?;
        // The libkrunfw kernel is built without initrd support; the agent ships
        // on a boot *volume* instead.
        // SAFETY: both pointers are live C strings for the length of the call.
        let rc = unsafe {
            krun_set_kernel(
                self.ctx_id,
                path.as_ptr(),
                KERNEL_FORMAT_ELF,
                std::ptr::null(),
                cmdline.as_ptr(),
            )
        };
        check_krun_rc(rc, "krun_set_kernel")
    }

    pub fn add_virtiofs(&self, tag: &str, host_path: &Path, read_only: bool) -> Result<()> {
        let tag = CString::new(tag)?;
        let path = c_path(host_path)?;
        // SAFETY: both pointers are live C strings for the length of the call.
        let rc = unsafe {
            krun_add_virtiofs3(
                self.ctx_id,
                tag.as_ptr(),
                path.as_ptr(),
                1 << 29, /* 512 MiB */
                read_only,
            )
        };
        check_krun_rc(
            rc,
            &format!("krun_add_virtiofs3 for {}", host_path.display()),
        )
    }

    /// Attach a raw ext4 image as virtio-blk. The guest sees `/dev/vda`,
    /// `/dev/vdb`, … in add order, which maps each disk to its mount.
    pub fn add_disk(&self, block_id: &str, host_path: &Path, read_only: bool) -> Result<()> {
        let id = CString::new(block_id)?;
        let path = c_path(host_path)?;
        // SAFETY: both pointers are live C strings for the length of the call.
        let rc = unsafe { krun_add_disk(self.ctx_id, id.as_ptr(), path.as_ptr(), read_only) };
        check_krun_rc(rc, &format!("krun_add_disk for {}", host_path.display()))
    }

    /// Attach the guest console - libkrun 2.x creates none, so without this
    /// the guest boots mute. `input` is the console's input (the null device
    /// in every caller: interactivity goes through the agent's ports). Both
    /// guest streams land in `output`, the box's log; libkrun dups it and
    /// writes for the VM's life, so it must be `O_APPEND` (see [`crate::logs`]).
    pub fn add_console(&self, input: File, output: File) -> Result<Console> {
        use std::os::fd::AsRawFd;
        let out_fd = output.as_raw_fd();
        // SAFETY: both descriptors are owned here and outlive the call.
        let rc = unsafe {
            krun_add_virtio_console_default(self.ctx_id, input.as_raw_fd(), out_fd, out_fd)
        };
        check_krun_rc(rc, "krun_add_virtio_console_default")?;
        Ok(Console {
            _output: output,
            _input: input,
        })
    }

    /// Add a virtio-net NIC over a socketpair (libkrun's end passed in); a NIC
    /// also disables libkrun's TSI backend.
    pub fn add_net_unixstream(&self, sock: UnixStream, mac: &[u8; 6]) -> Result<()> {
        use std::os::fd::IntoRawFd;
        // SAFETY: `mac` outlives the call, and the descriptor is given away.
        let rc = unsafe {
            krun_add_net_unixstream(
                self.ctx_id,
                std::ptr::null(),
                sock.into_raw_fd(),
                mac.as_ptr(),
                NET_FEATURES,
                0,
            )
        };
        check_krun_rc(rc, "krun_add_net_unixstream")
    }

    /// Enable vsock, plain (`tsi_features = 0`, no TSI hijacking). Required
    /// before [`Self::add_vsock_port`] - it returns ENODEV without this.
    pub fn add_vsock(&self) -> Result<()> {
        check_krun_rc(krun_add_vsock(self.ctx_id, 0), "krun_add_vsock")
    }

    /// Map a vsock port to a host unix socket. `listen` - libkrun binds the
    /// path and forwards host connections to the guest (session, file, exec);
    /// `false` - the guest dials `port` and libkrun connects to the path terra
    /// listens on (the control channel).
    pub fn add_vsock_port(&self, port: u32, unix_path: &Path, listen: bool) -> Result<()> {
        let path = c_path(unix_path)?;
        // SAFETY: `path` is a live C string for the length of the call.
        let rc = unsafe { krun_add_vsock_port2(self.ctx_id, port, path.as_ptr(), listen) };
        check_krun_rc(rc, "krun_add_vsock_port2")
    }

    /// Start the VM; returns only when it exits, and libkrun then exits this
    /// process - with 0 whatever the guest did
    pub fn start_enter(&self) -> Result<()> {
        check_krun_rc(krun_start_enter(self.ctx_id), "krun_start_enter")
    }
}

impl Drop for Krun {
    fn drop(&mut self) {
        krun_free_ctx(self.ctx_id);
    }
}
