//! The guest boot plan, built host-side and read by the agent.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

use super::frames::TermSize;

pub const RESIZE2FS_GUEST_PATH: &str = "/terra-resize2fs";

pub const ROOT_DEVICE: &str = "/dev/vdb";

/// How many scratch volumes fit after the boot volume and root device.
pub const MAX_VOLUMES: usize = 32;

/// Block device name for the `index`-th volume; `None` past [`MAX_VOLUMES`].
#[must_use]
pub fn to_volume_device(index: usize) -> Option<String> {
    (index < MAX_VOLUMES).then(|| format!("/dev/vd{}", disk_suffix(index + 2)))
}

fn disk_suffix(mut index: usize) -> String {
    let mut suffix = String::new();
    loop {
        #[allow(clippy::cast_possible_truncation)]
        suffix.push(char::from(b'a' + (index % 26) as u8));
        if index < 26 {
            break;
        }
        index = index / 26 - 1;
    }
    suffix.chars().rev().collect()
}

/// Kernel cmdline for booting the guest agent from the boot disk.
/// `loglevel=3` keeps ext4's read-only orphan-cleanup warning off the console.
pub const KERNEL_CMDLINE: &str = "reboot=k panic=-1 panic_print=0 quiet loglevel=3 no-kvmapf \
     root=/dev/vda rootfstype=ext4 ro init=/terra-agent";

pub use crate::control::{
    AGENT_VSOCK_PORT, CLOCK_SYNC, CLOCK_SYNC_BYTES, CONTROL_VSOCK_PORT, DIAGNOSTIC_VSOCK_PORT,
    decode_clock_sync,
};

pub const MAX_FILE_BYTES: u64 = 1 << 31;
const MAX_FILE_ERROR_BYTES: usize = 4096;

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
    pub fn to_byte(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            b's' => Some(Self::Session),
            b'f' => Some(Self::Files),
            b'e' => Some(Self::Exec),
            b'c' => Some(Self::SessionControl),
            _ => None,
        }
    }
}

/// Signal byte for graceful shutdown. Single byte for signal-handler use.
pub const STOP_SIGNAL: u8 = b'S';

pub const DEFAULT_STOP_GRACE_SECS: u64 = 30;

/// Bump when a host and a running guest agent cannot safely communicate.
pub const AGENT_PROTOCOL_VERSION: u8 = 1;

/// The first bytes the agent writes on every connection it accepts - and the
/// host's only proof that the agent is what answered and speaks its protocol.
///
/// Not `0x1b`: a session's first act after this is a screen repaint, so a
/// hello indistinguishable from the escape byte would prove nothing.
pub const AGENT_HELLO: [u8; 2] = [b'V', AGENT_PROTOCOL_VERSION];

/// Where the agent records the baked `on_create` stamp.
pub const RECIPE_STAMP_PATH: &str = "/terra/recipe";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum PlanMode {
    Run,
    Create,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum LifecycleProtocol {
    #[default]
    Legacy,
    EventsV1,
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
pub const WORKLOAD_ID: u32 = 1000;

pub const WORKLOAD_HOME: &str = "/home/terri";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Disk {
    pub dev: String,
    pub guest: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Net {
    pub guest_ip: std::net::IpAddr,
    pub prefix: u8,
    pub gateway: std::net::IpAddr,
    pub dns: std::net::IpAddr,
}

/// A UTC sample captured immediately before the guest receives its boot plan.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostTime {
    pub seconds: i64,
    pub nanoseconds: u32,
}

impl<'de> Deserialize<'de> for Net {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Fields {
            guest_ip: std::net::IpAddr,
            prefix: u8,
            gateway: std::net::IpAddr,
            dns: std::net::IpAddr,
        }

        let Fields {
            guest_ip,
            prefix,
            gateway,
            dns,
        } = Fields::deserialize(deserializer)?;
        let guest_uses_ipv4 = guest_ip.is_ipv4();
        let max_prefix_bits = if guest_uses_ipv4 { 32 } else { 128 };
        if prefix > max_prefix_bits {
            return Err(D::Error::custom(format!(
                "network prefix {prefix} exceeds the {max_prefix_bits}-bit address limit"
            )));
        }
        if gateway.is_ipv4() != guest_uses_ipv4 || dns.is_ipv4() != guest_uses_ipv4 {
            return Err(D::Error::custom(
                "network gateway and DNS addresses must use the same address family as guest_ip",
            ));
        }
        Ok(Self {
            guest_ip,
            prefix,
            gateway,
            dns,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Plan {
    pub mode: PlanMode,
    pub workdir: Option<String>,
    pub shares: Vec<Share>,
    pub volumes: Vec<Disk>,
    pub net: Net,
    pub env: BTreeMap<String, String>,
    /// Run the workload as root instead of dropping to the workload user
    /// (`--root`; also set for the `terra setup` bake).
    pub root: bool,
    pub sudo: Vec<String>,
    pub on_create: Vec<String>,
    pub on_start: Vec<String>,
    pub pre_stop: Vec<String>,
    /// Background shell lines, restarted on failure until the box stops.
    #[serde(default)]
    pub daemons: Vec<String>,
    pub workload: Vec<String>,
    pub sandbox_info: String,
    /// Retained for older agents; current hosts send false and current agents ignore this field.
    pub workload_on_console: bool,
    /// Wait for the foreground host session before starting the workload.
    #[serde(default)]
    pub await_initial_session: bool,
    #[serde(default)]
    pub lifecycle_protocol: LifecycleProtocol,
    pub host_tz: Option<Vec<u8>>,
    #[serde(default)]
    pub host_time: Option<HostTime>,
    #[serde(default)]
    pub host_seed: Option<[u8; 32]>,
}

/// `as_root` is the `--root` flag, not the identity: the agent resolves what
/// the command runs as, since it is the side that knows which the box is.
/// `tty: Some(size)` asks for a PTY at that size; `None` uses pipes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecRequest {
    #[serde(deserialize_with = "deserialize_argv")]
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
    Get {
        #[serde(deserialize_with = "deserialize_abs_path")]
        path: String,
    },
    Put {
        #[serde(deserialize_with = "deserialize_abs_path")]
        path: String,
        mode: u32,
        #[serde(deserialize_with = "deserialize_file_size")]
        size: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum FileReply {
    /// The operation failed; the text is guest-chosen and untrusted.
    Err(#[serde(deserialize_with = "deserialize_file_error")] String),
    /// A put landed whole.
    Put,
    /// A get: the file's permission bits, and how many bytes follow.
    Get {
        mode: u32,
        #[serde(deserialize_with = "deserialize_file_size")]
        size: u64,
    },
}

fn deserialize_argv<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    let argv = Vec::<String>::deserialize(deserializer)?;
    if argv.is_empty() {
        return Err(D::Error::custom("exec request has no command"));
    }
    if argv.iter().any(|arg| arg.contains('\0')) {
        return Err(D::Error::custom(
            "exec request arguments cannot contain NUL bytes",
        ));
    }
    Ok(argv)
}

fn deserialize_abs_path<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let path = String::deserialize(deserializer)?;
    if path.contains('\0') {
        return Err(D::Error::custom("guest path cannot contain NUL bytes"));
    }
    if !path.starts_with('/') {
        return Err(D::Error::custom("guest path must be absolute"));
    }
    Ok(path)
}

fn deserialize_file_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let size = u64::deserialize(deserializer)?;
    if size > MAX_FILE_BYTES {
        return Err(D::Error::custom(format!(
            "file size {size} exceeds the {MAX_FILE_BYTES}-byte limit"
        )));
    }
    Ok(size)
}

fn deserialize_file_error<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let error = String::deserialize(deserializer)?;
    if error.len() > MAX_FILE_ERROR_BYTES {
        return Err(D::Error::custom(format!(
            "file error exceeds the {MAX_FILE_ERROR_BYTES}-byte limit"
        )));
    }
    Ok(error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode_frame, read_frame};

    #[test]
    fn round_trip_agent_service_bytes() {
        for service in [
            AgentService::Session,
            AgentService::Files,
            AgentService::Exec,
            AgentService::SessionControl,
        ] {
            assert_eq!(AgentService::from_byte(service.to_byte()), Some(service));
        }
    }

    #[test]
    fn agent_hello_names_the_protocol_version() {
        assert_eq!(AGENT_HELLO, [b'V', AGENT_PROTOCOL_VERSION]);
    }

    // pin WORKLOAD_USER_NAME and WORKLOAD_HOME
    #[test]
    fn match_workload_home_to_user() {
        assert_eq!(WORKLOAD_HOME, format!("/home/{WORKLOAD_USER_NAME}"));
    }

    #[test]
    fn round_trip_plan_through_json() {
        for host_tz in [None, Some(vec![1, 2, 3])] {
            let plan = Plan {
                mode: PlanMode::Create,
                workdir: Some("/work".into()),
                shares: vec![Share {
                    tag: "_etc".into(),
                    guest: "/etc/x".into(),
                    readonly: true,
                }],
                volumes: vec![Disk {
                    dev: to_volume_device(0).unwrap(),
                    guest: "/data".into(),
                }],
                net: Net {
                    guest_ip: "100.96.0.2".parse().unwrap(),
                    prefix: 30,
                    gateway: "100.96.0.1".parse().unwrap(),
                    dns: "100.96.0.1".parse().unwrap(),
                },
                env: BTreeMap::from([("FOO".to_string(), "bar".to_string())]),
                root: false,
                sudo: vec!["apk".into()],
                on_create: vec!["apk add git".into()],
                on_start: vec!["date".into()],
                pre_stop: vec!["sync".into()],
                daemons: vec!["while true; do sleep 60; done".into()],
                workload: vec!["/bin/sh".into(), "-c".into(), "make".into()],
                sandbox_info: "# Terrarium sandbox".into(),
                workload_on_console: true,
                await_initial_session: true,
                lifecycle_protocol: LifecycleProtocol::EventsV1,
                host_tz,
                host_time: Some(HostTime {
                    seconds: 1,
                    nanoseconds: 2,
                }),
                host_seed: Some([3; 32]),
            };
            // Over the control connection, the frame must leave the stop signal
            // that follows it untouched in the stream.
            let mut stream = encode_frame(&plan).unwrap();
            stream.push(STOP_SIGNAL);
            let mut cursor = std::io::Cursor::new(stream);
            assert_eq!(read_frame::<Plan>(&mut cursor).unwrap(), Some(plan));
            let mut rest = Vec::new();
            std::io::Read::read_to_end(&mut cursor, &mut rest).unwrap();
            assert_eq!(rest, vec![STOP_SIGNAL]);
        }
        // Old host without the new fields still decodes as None.
        let json_without = serde_json::json!({
            "mode": "Create",
            "workdir": "/work",
            "shares": [],
            "volumes": [],
            "net": {"guest_ip":"100.96.0.2","prefix":30,"gateway":"100.96.0.1","dns":"100.96.0.1"},
            "env": {},
            "root": false,
            "sudo": [],
            "on_create": [],
            "on_start": [],
            "pre_stop": [],
            "workload": [],
            "sandbox_info": "",
            "workload_on_console": false
        });
        let decoded: Plan = serde_json::from_value(json_without).unwrap();
        assert_eq!(decoded.host_tz, None);
        assert_eq!(decoded.lifecycle_protocol, LifecycleProtocol::Legacy);
        // …and an old host's plan, which carries no daemons, still boots a
        // new agent.
        assert!(decoded.daemons.is_empty());
    }

    #[test]
    fn run_volume_devices_continue_after_vdz() {
        assert_eq!(to_volume_device(0).unwrap(), "/dev/vdc");
        assert_eq!(to_volume_device(23).unwrap(), "/dev/vdz");
        assert_eq!(to_volume_device(24).unwrap(), "/dev/vdaa");
        assert_eq!(to_volume_device(MAX_VOLUMES - 1).unwrap(), "/dev/vdah");
        // Past the last letter is the caller's error to report, never a panic:
        // this is linked into guest PID 1.
        assert_eq!(to_volume_device(MAX_VOLUMES), None);
    }

    #[test]
    fn reject_invalid_network_and_file_requests() {
        assert!(
            serde_json::from_value::<Net>(serde_json::json!({
                "guest_ip": "192.0.2.2",
                "prefix": 33,
                "gateway": "192.0.2.1",
                "dns": "192.0.2.1"
            }))
            .is_err()
        );
        for field in ["gateway", "dns"] {
            let mut net = serde_json::json!({
                "guest_ip": "192.0.2.2",
                "prefix": 24,
                "gateway": "192.0.2.1",
                "dns": "192.0.2.1"
            });
            net[field] = serde_json::json!("2001:db8::1");
            assert!(serde_json::from_value::<Net>(net).is_err());
        }
        assert!(
            serde_json::from_value::<ExecRequest>(serde_json::json!({
                "argv": ["/bin/sh", "bad\0arg"],
                "as_root": false,
                "tty": null
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ExecRequest>(serde_json::json!({
                "argv": [],
                "as_root": false,
                "tty": null
            }))
            .is_err()
        );
        for request in [
            serde_json::json!({"Get": {"path": "relative"}}),
            serde_json::json!({"Put": {"path": "relative", "mode": 420, "size": 0}}),
            serde_json::json!({"Get": {"path": "/tmp/has\0nul"}}),
            serde_json::json!({"Put": {"path": "/tmp/has\0nul", "mode": 420, "size": 0}}),
            serde_json::json!({"Put": {"path": "/tmp/file", "mode": 420, "size": MAX_FILE_BYTES + 1}}),
        ] {
            assert!(serde_json::from_value::<FileRequest>(request).is_err());
        }
        assert!(
            serde_json::from_value::<FileReply>(serde_json::json!({
                "Get": {"mode": 420, "size": MAX_FILE_BYTES + 1}
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<FileReply>(serde_json::json!({
                "Err": "x".repeat(MAX_FILE_ERROR_BYTES + 1)
            }))
            .is_err()
        );
    }
}
