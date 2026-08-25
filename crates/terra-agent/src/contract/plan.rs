//! The guest boot plan, built host-side and read by the agent.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Path of the agent binary in the boot volume (PID 1).
pub const AGENT_GUEST_PATH: &str = "/terra-agent";

/// Path of `resize2fs`.
pub const RESIZE2FS_GUEST_PATH: &str = "/terra-resize2fs";

/// Boot volume.
pub const BOOT_DEVICE: &str = "/dev/vda";

/// Guest root filesystem.
pub const ROOT_DEVICE: &str = "/dev/vdb";

/// How many scratch volumes fit: `/dev/vd[c-z]`, the letters left once the
/// boot volume and the root have taken `a` and `b`.
pub const MAX_VOLUMES: usize = 24;

/// Block device name for the `index`-th volume; `None` past [`MAX_VOLUMES`].
#[must_use]
pub fn volume_device(index: usize) -> Option<String> {
    // The bound keeps index below 256; clippy cannot see through it.
    #[allow(clippy::cast_possible_truncation)]
    (index < MAX_VOLUMES).then(|| format!("/dev/vd{}", (b'c' + index as u8) as char))
}

/// Kernel cmdline: boot from [`BOOT_DEVICE`], init from [`AGENT_GUEST_PATH`].
/// `loglevel=3` on top of `quiet` so ext4's
/// "write access unavailable, skipping orphan cleanup" doesn't appear on the
/// terminal - the boot volume is read-only, and that message is `KERN_ERR`.
#[must_use]
pub fn kernel_cmdline() -> String {
    format!(
        "reboot=k panic=-1 panic_print=0 nomodule console=hvc0 quiet loglevel=3 no-kvmapf \
         root={BOOT_DEVICE} rootfstype=ext4 ro init={AGENT_GUEST_PATH}"
    )
}

/// Vsock port for every agent service.
pub const AGENT_VSOCK_PORT: u32 = 6000;

/// The byte naming what one connection to [`AGENT_VSOCK_PORT`] is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AgentService {
    /// The workload's shared terminal: a *viewport* onto the one PTY every
    /// client shares - no per-client process, no uid of its own.
    Session = b's',
    /// One `terra put`/`get` operation.
    Files = b'f',
    /// One `terra exec` - one connection, one PTY, one process, which is what
    /// lets it run as root while the workload stays unprivileged.
    Exec = b'e',
    /// Session management, not a viewport: one ask per connection - list
    /// the clients, or drop one. Never itself a client.
    SessionControl = b'c',
}

impl AgentService {
    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        [Self::Session, Self::Files, Self::Exec, Self::SessionControl]
            .into_iter()
            .find(|s| *s as u8 == byte)
    }
}

/// Vsock port for the boot plan and stop signal. Guest dials out.
pub const CONTROL_VSOCK_PORT: u32 = 6001;

/// Signal byte for graceful shutdown. Single byte for signal-handler use.
pub const STOP_SIGNAL: u8 = b'S';

/// The guest's last word on the control connection: what the workload exited
/// with, or what the `on_create` bake did in a Create VM.
///
/// libkrun cannot carry it: its exit-code channel is an ioctl on a *virtiofs*
/// root, and a terra guest roots on ext4, so libkrun reports 0 however the
/// guest ended.
pub fn send_exit_status(w: &mut impl std::io::Write, code: i32) -> std::io::Result<()> {
    w.write_all(&frame(&code)?)?;
    w.flush()
}

/// Read the status the guest sent; an error means the guest let go without
/// one - the VM died rather than finishing.
pub fn read_exit_status(r: &mut impl std::io::Read) -> std::io::Result<i32> {
    read_frame::<i32>(r)
}

/// The first byte the agent writes on every connection it accepts - and the
/// host's only proof that the agent is what answered.
///
/// Not `0x1b`: a session's first act after this is a screen repaint, so a
/// hello indistinguishable from the escape byte would prove nothing.
pub const AGENT_HELLO: u8 = b'T';

/// Where the agent records the baked `on_create` stamp.
pub const RECIPE_STAMP_PATH: &str = "/terra/recipe";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PlanMode {
    Run,
    Create,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Share {
    pub tag: String,
    pub guest: String,
    pub readonly: bool,
}

/// Workload user name (cosmetic, for shell prompts).
pub const WORKLOAD_USER_NAME: &str = "terri";

/// The non-root workload user's numeric identity (uid == gid). One source of
/// truth for both sides: the host's userns maps this uid to the launching
/// user, and the agent drops the workload to it.
pub const WORKLOAD_UID: u32 = 1000;
pub const WORKLOAD_GID: u32 = 1000;

/// The workload's home directory.
#[must_use]
pub fn workload_home() -> String {
    format!("/home/{WORKLOAD_USER_NAME}")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Disk {
    pub dev: String,
    pub guest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Net {
    pub guest_ip: String,
    pub prefix: u8,
    pub gateway: String,
    pub dns: String,
}

/// The full guest boot plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Plan {
    pub mode: PlanMode,
    pub workdir: Option<String>,
    pub shares: Vec<Share>,
    pub volumes: Vec<Disk>,
    /// The host uid and gid owning the shares' backing files; the agent idmaps
    /// each share so this pair reads as the workload user. `None` (a root
    /// host) mounts shares unmapped, so real ids pass through whole.
    pub share_owner: Option<(u32, u32)>,
    pub net: Net,
    pub env: BTreeMap<String, String>,
    /// Run the workload as root instead of dropping to the workload user
    /// (`--root`; also set for the `terra setup` bake).
    pub root: bool,
    pub sudo: Vec<String>,
    pub on_create: Vec<String>,
    pub on_start: Vec<String>,
    pub pre_stop: Vec<String>,
    pub workload: Vec<String>,
    pub sandbox_info: String,
    /// Broadcast the workload's terminal to the guest console as well as to
    /// the session's clients.
    pub workload_on_console: bool,
}

/// Encode any message as the one wire shape every terra channel uses: a
/// `u32` LE length prefix plus JSON.
pub fn frame<T: serde::Serialize>(v: &T) -> std::io::Result<Vec<u8>> {
    let json = serde_json::to_vec(v).map_err(std::io::Error::other)?;
    if json.len() > MAX_FRAME {
        return Err(oversized(json.len()));
    }
    // `MAX_FRAME` is far below `u32::MAX`, so the length always fits the header.
    let len = u32::try_from(json.len()).map_err(|_| oversized(json.len()))?;
    let mut out = Vec::with_capacity(4 + json.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&json);
    Ok(out)
}

fn oversized(len: usize) -> std::io::Error {
    std::io::Error::other(format!(
        "framed message of {len} bytes exceeds the {MAX_FRAME}-byte limit"
    ))
}

/// Ceiling on a frame's payload, shared with [`crate::ClientInput::read`]:
/// same hazard, same answer.
pub const MAX_FRAME: usize = 8 << 20;

/// Read one framed message (see [`frame`]).
pub fn read_frame<T: serde::de::DeserializeOwned>(
    r: &mut impl std::io::Read,
) -> std::io::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(oversized(len));
    }
    let mut json = vec![0u8; len];
    r.read_exact(&mut json)?;
    serde_json::from_slice(&json).map_err(std::io::Error::other)
}

/// A terminal's size. A struct rather than a `(u16, u16)`: the pair crosses
/// the host/guest wire, and named fields make a swapped order unspellable.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TermSize {
    pub rows: u16,
    pub cols: u16,
}

/// One `terra exec`.
///
/// `as_root` is the `--root` flag, not the identity: the agent resolves what
/// the command runs as, since it is the side that knows which the box is.
///
/// `tty: Some(size)` asks for a PTY at that size, set from whether the host's
/// own stdin is a terminal - the same call `ssh` makes.
///
/// No working directory: PID 1 has already `chdir`ed to the recipe's
/// `workdir` by the time the exec listener is accepting, and a child inherits
/// it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecRequest {
    pub argv: Vec<String>,
    pub as_root: bool,
    pub tty: Option<TermSize>,
}

/// One `terra put`/`get` operation on an absolute guest path. A put carries
/// the host file's permission bits (so scripts stay executable) and its exact
/// `size` - the agent reads that many bytes and replies on the same
/// connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileRequest {
    Get { path: String },
    Put { path: String, mode: u32, size: u64 },
}

/// The agent's answer to one [`FileRequest`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileReply {
    /// The operation failed; the text is guest-chosen and untrusted.
    Err(String),
    /// A put landed whole.
    Put,
    /// A get: the file's permission bits, and how many bytes follow.
    Get { mode: u32, size: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_round_trips_through_json() {
        let plan = Plan {
            mode: PlanMode::Create,
            workdir: Some("/work".into()),
            shares: vec![Share {
                tag: "_etc".into(),
                guest: "/etc/x".into(),
                readonly: true,
            }],
            volumes: vec![Disk {
                dev: volume_device(0).unwrap(),
                guest: "/data".into(),
            }],
            share_owner: Some((1000, 1000)),
            net: Net {
                guest_ip: "100.96.0.2".into(),
                prefix: 30,
                gateway: "100.96.0.1".into(),
                dns: "100.96.0.1".into(),
            },
            env: BTreeMap::from([("FOO".to_string(), "bar".to_string())]),
            root: false,
            sudo: vec!["apk".into()],
            on_create: vec!["apk add git".into()],
            on_start: vec!["date".into()],
            pre_stop: vec!["sync".into()],
            workload: vec!["/bin/sh".into(), "-c".into(), "make".into()],
            sandbox_info: "# Terrarium sandbox".into(),
            workload_on_console: true,
        };
        // Over the control connection, the frame must leave the stop signal
        // that follows it untouched in the stream.
        let mut stream = frame(&plan).unwrap();
        stream.push(STOP_SIGNAL);
        let mut cursor = std::io::Cursor::new(stream);
        assert_eq!(read_frame::<Plan>(&mut cursor).unwrap(), plan);
        let mut rest = Vec::new();
        std::io::Read::read_to_end(&mut cursor, &mut rest).unwrap();
        assert_eq!(rest, vec![STOP_SIGNAL]);
    }

    #[test]
    fn an_absurd_frame_length_is_refused_before_allocating() {
        // Four bytes claiming 4 GiB, and nothing behind them.
        let mut wire = u32::MAX.to_le_bytes().to_vec();
        wire.extend_from_slice(b"{}");
        let err = read_frame::<FileRequest>(&mut std::io::Cursor::new(wire)).unwrap_err();
        assert!(err.to_string().contains("exceeds"), "{err}");
    }

    #[test]
    fn volume_devices_run_from_vdc_to_vdz() {
        assert_eq!(volume_device(0).unwrap(), "/dev/vdc");
        assert_eq!(volume_device(MAX_VOLUMES - 1).unwrap(), "/dev/vdz");
        // Past the last letter is the caller's error to report, never a panic:
        // this is linked into guest PID 1.
        assert_eq!(volume_device(MAX_VOLUMES), None);
    }
}
