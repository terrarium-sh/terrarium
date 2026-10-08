//! The guest boot plan, built host-side and read by the agent.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_PLAN_BYTES: usize = 1 << 20;
pub const MAX_PLAN_HOST_STATE_BYTES: usize = 1024;
pub const MAX_PUBLISHED_PORTS: usize = 32;

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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Net {
    Tsi,
    LocalOnly,
}

/// A UTC sample captured immediately before the guest receives its boot plan.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostTime {
    pub seconds: i64,
    pub nanoseconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Plan {
    pub mode: PlanMode,
    pub workdir: Option<String>,
    pub shares: Vec<Share>,
    pub volumes: Vec<Disk>,
    pub net: Net,
    pub published_ports: Vec<u16>,
    pub published_udp_ports: Vec<u16>,
    pub env: BTreeMap<String, String>,
    /// Run the workload as root instead of dropping to the workload user
    /// (`--root`; also set for the `terra setup` bake).
    pub root: bool,
    pub sudo: Vec<String>,
    pub on_create: Vec<String>,
    pub on_start: Vec<String>,
    pub pre_stop: Vec<String>,
    /// Background shell lines, restarted on failure until the box stops.
    pub daemons: Vec<String>,
    pub workload: Vec<String>,
    pub sandbox_info: String,
    /// Wait for the foreground host session before starting the workload.
    pub await_initial_session: bool,
    #[serde(with = "serde_bytes")]
    pub host_tz: Option<Vec<u8>>,
    pub host_time: Option<HostTime>,
    pub host_seed: Option<[u8; 32]>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootPlan {
    pub agent_version: u8,
    pub socket_version: u16,
    pub plan: Plan,
}

impl BootPlan {
    #[must_use]
    pub const fn new(plan: Plan) -> Self {
        Self {
            agent_version: crate::AGENT_PROTOCOL_VERSION,
            socket_version: crate::socket::VERSION,
            plan,
        }
    }

    pub fn validate_protocol_versions(&self) -> std::io::Result<()> {
        if self.agent_version != crate::AGENT_PROTOCOL_VERSION
            || self.socket_version != crate::socket::VERSION
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "boot protocol mismatch: host agent {}/socket {}, guest agent {}/socket {}; rebuild the kernel, agent, components, and runtime together",
                    self.agent_version,
                    self.socket_version,
                    crate::AGENT_PROTOCOL_VERSION,
                    crate::socket::VERSION
                ),
            ));
        }
        Ok(())
    }
}

impl Plan {
    pub fn validate_network(&self) -> std::io::Result<()> {
        if self.published_ports.len() + self.published_udp_ports.len() > MAX_PUBLISHED_PORTS
            || [&self.published_ports, &self.published_udp_ports]
                .iter()
                .any(|ports| {
                    ports.contains(&0)
                        || ports.windows(2).any(|ports| ports[0] >= ports[1])
                        || (self.net == Net::LocalOnly && !ports.is_empty())
                })
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "published guest ports must be sorted, unique, nonzero, within the listener limit, and empty in local-only mode",
            ));
        }
        Ok(())
    }
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
        assert_eq!(&encode_frame(&PlanMode::Create).unwrap()[4..], &[1]);
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
    fn round_trip_plan() {
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
                net: Net::Tsi,
                published_ports: vec![80, 443],
                published_udp_ports: vec![53],
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
            assert!(plan.validate_network().is_ok());
            for ports in [vec![0], vec![443, 80], vec![80, 80], (1..=33).collect()] {
                let mut invalid = plan.clone();
                invalid.published_ports = ports.clone();
                assert!(invalid.validate_network().is_err());
                invalid = plan.clone();
                invalid.published_udp_ports = ports;
                assert!(invalid.validate_network().is_err());
            }
            let mut combined_limit = plan.clone();
            combined_limit.published_ports = (1..=16).collect();
            combined_limit.published_udp_ports = (1..=16).collect();
            assert!(combined_limit.validate_network().is_ok());
            combined_limit.published_udp_ports.push(17);
            assert!(combined_limit.validate_network().is_err());
            let mut local_only = plan.clone();
            local_only.net = Net::LocalOnly;
            assert!(local_only.validate_network().is_err());
            local_only.published_ports.clear();
            assert!(local_only.validate_network().is_err());
            local_only.published_udp_ports.clear();
            assert!(local_only.validate_network().is_ok());
            let mut cursor = std::io::Cursor::new(encode_frame(&plan).unwrap());
            assert_eq!(read_frame::<Plan>(&mut cursor).unwrap(), Some(plan.clone()));
            let boot = BootPlan::new(plan.clone());
            assert!(boot.validate_protocol_versions().is_ok());
            let frame = encode_frame(&boot).unwrap();
            assert_eq!(
                read_frame::<BootPlan>(&mut frame.as_slice()).unwrap(),
                Some(boot.clone())
            );
            for agent_version in [0, crate::AGENT_PROTOCOL_VERSION + 1] {
                let mut invalid = boot.clone();
                invalid.agent_version = agent_version;
                assert_eq!(
                    invalid.validate_protocol_versions().unwrap_err().kind(),
                    std::io::ErrorKind::InvalidData
                );
            }
            for socket_version in [0, crate::socket::VERSION + 1] {
                let mut invalid = boot.clone();
                invalid.socket_version = socket_version;
                assert_eq!(
                    invalid.validate_protocol_versions().unwrap_err().kind(),
                    std::io::ErrorKind::InvalidData
                );
            }
            let bare = encode_frame(&plan).unwrap();
            assert!(read_frame::<BootPlan>(&mut bare.as_slice()).is_err());
            assert!(read_frame::<Plan>(&mut frame.as_slice()).is_err());
        }
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
    fn network_modes_round_trip_by_name() {
        for (net, name) in [(Net::Tsi, "tsi"), (Net::LocalOnly, "local_only")] {
            let frame = encode_frame(&net).unwrap();
            assert_eq!(read_frame::<Net>(&mut frame.as_slice()).unwrap(), Some(net));
            let decoder = serde::de::value::StrDeserializer::<serde::de::value::Error>::new(name);
            assert_eq!(Net::deserialize(decoder).unwrap(), net);
        }
        for name in ["packet", "Tsi", "LocalOnly"] {
            let decoder = serde::de::value::StrDeserializer::<serde::de::value::Error>::new(name);
            assert!(Net::deserialize(decoder).is_err());
        }
    }
}
