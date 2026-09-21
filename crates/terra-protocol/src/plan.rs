//! The guest boot plan, built host-side and read by the agent.

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeMap;

pub const MAX_PLAN_BYTES: usize = 1 << 20;
pub const MAX_PLAN_HOST_STATE_BYTES: usize = 1024;

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
    /// Wait for the foreground host session before starting the workload.
    #[serde(default)]
    pub await_initial_session: bool,
    pub host_tz: Option<Vec<u8>>,
    #[serde(default)]
    pub host_time: Option<HostTime>,
    #[serde(default)]
    pub host_seed: Option<[u8; 32]>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encode_frame, read_frame};

    // pin WORKLOAD_USER_NAME and WORKLOAD_HOME
    #[test]
    fn match_workload_home_to_user() {
        assert_eq!(WORKLOAD_HOME, format!("/home/{WORKLOAD_USER_NAME}"));
    }

    #[test]
    fn plan_mode_retains_its_wire_format() {
        assert_eq!(
            serde_json::to_string(&PlanMode::Create).unwrap(),
            "\"Create\""
        );
    }

    #[test]
    fn plan_limit_rejects_the_length_before_allocating() {
        let over_limit = u32::try_from(MAX_PLAN_BYTES + 1).unwrap();
        let mut reader = std::io::Cursor::new(over_limit.to_le_bytes());
        let error = crate::read_frame_with_limit::<Plan>(&mut reader, MAX_PLAN_BYTES).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(reader.position(), 4);
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
                await_initial_session: true,
                host_tz,
                host_time: Some(HostTime {
                    seconds: 1,
                    nanoseconds: 2,
                }),
                host_seed: Some([3; 32]),
            };
            let mut cursor = std::io::Cursor::new(encode_frame(&plan).unwrap());
            assert_eq!(read_frame::<Plan>(&mut cursor).unwrap(), Some(plan));
        }
        // Optional plan fields retain their defaults when absent.
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
            "sandbox_info": ""
        });
        let decoded: Plan = serde_json::from_value(json_without).unwrap();
        assert_eq!(decoded.host_tz, None);
        assert!(!decoded.await_initial_session);
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
    fn reject_invalid_network_requests() {
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
    }
}
