//! The guest boot plan, built host-side and read by the agent.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_PLAN_BYTES: usize = 1 << 20;
pub const MAX_PUBLISHED_PORTS: usize = 32;

pub const RESIZE2FS_GUEST_PATH: &str = "/terra-resize2fs";

pub const ROOT_DEVICE: &str = "/dev/vdb";

const FIRST_VOLUME_INDEX: usize = 2;

/// Block device name for the `index`-th volume.
#[must_use]
pub fn to_volume_device(index: usize) -> String {
    block_device(FIRST_VOLUME_INDEX + index)
}

/// The guest's name for the `index`-th block device the host attaches.
fn block_device(mut index: usize) -> String {
    let mut suffix = String::new();
    loop {
        #[allow(clippy::cast_possible_truncation)]
        suffix.push(char::from(b'a' + (index % 26) as u8));
        if index < 26 {
            break;
        }
        index = index / 26 - 1;
    }
    format!("/dev/vd{}", suffix.chars().rev().collect::<String>())
}

/// Kernel cmdline for booting the guest agent from the boot disk.
/// `loglevel=3` keeps ext4's read-only orphan-cleanup warning off the console.
pub const KERNEL_CMDLINE: &str = "reboot=k panic=-1 panic_print=0 quiet loglevel=3 no-kvmapf \
     root=/dev/vda rootfstype=ext4 ro init=/terra-agent";

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VolumeMount {
    pub dev: String,
    pub guest: String,
}

/// How the agent mounts the guest root.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RootfsMount {
    Writable,
    /// The host attached the root device read-only, so the agent mounts it
    /// read-only and puts tmpfs on `/tmp` and `/var/tmp`.
    ReadOnly,
    /// The read-only root device under an overlay whose upper layer is the
    /// fresh volume on `upper_dev`, which no guest path shows.
    Overlay {
        upper_dev: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Net {
    /// Guest sockets reach the host through the network frontend and its broker.
    Brokered,
    LocalOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Plan {
    pub mode: PlanMode,
    pub hostname: String,
    pub workdir: Option<String>,
    pub shares: Vec<Share>,
    pub volumes: Vec<VolumeMount>,
    pub net: Net,
    pub published_ports: Vec<u16>,
    pub published_udp_ports: Vec<u16>,
    pub env: BTreeMap<String, String>,
    /// `--root`, and always set for setup's VM.
    pub as_root: bool,
    pub rootfs: RootfsMount,
    pub sudo: Vec<String>,
    pub on_create: Vec<String>,
    pub on_start: Vec<String>,
    pub pre_stop: Vec<String>,
    /// Background shell lines, restarted on failure until the box stops.
    pub daemons: Vec<String>,
    /// The recipe's `run` shell line; `None` runs an interactive
    /// [`RECIPE_SHELL`](crate::guest_root::RECIPE_SHELL).
    pub workload: Option<String>,
    pub sandbox_info: String,
    /// Wait for the foreground host session before starting the workload.
    pub await_initial_session: bool,
    #[serde(with = "serde_bytes")]
    pub host_tz: Option<Vec<u8>>,
}

impl crate::Message for Plan {
    const MAX_PAYLOAD_BYTES: usize = MAX_PLAN_BYTES;
}

impl Plan {
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn bare_run(workload: Option<String>) -> Self {
        Self {
            mode: PlanMode::Run,
            hostname: "terrarium".to_owned(),
            workdir: None,
            shares: Vec::new(),
            volumes: Vec::new(),
            net: Net::Brokered,
            published_ports: Vec::new(),
            published_udp_ports: Vec::new(),
            env: BTreeMap::new(),
            as_root: false,
            rootfs: RootfsMount::Writable,
            sudo: Vec::new(),
            on_create: Vec::new(),
            on_start: Vec::new(),
            pre_stop: Vec::new(),
            daemons: Vec::new(),
            workload,
            sandbox_info: String::new(),
            await_initial_session: false,
            host_tz: None,
        }
    }

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

    #[test]
    fn plan_mode_retains_its_wire_format() {
        assert_eq!(postcard::to_allocvec(&PlanMode::Create).unwrap(), [1]);
    }

    #[test]
    fn plan_limit_rejects_the_length_before_allocating() {
        let over_limit = u32::try_from(MAX_PLAN_BYTES + 1).unwrap();
        let mut reader = std::io::Cursor::new(over_limit.to_le_bytes());
        let error = read_frame::<Plan>(&mut reader).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(reader.position(), 4);
    }

    #[test]
    fn round_trip_plan() {
        for host_tz in [None, Some(vec![1, 2, 3])] {
            let plan = Plan {
                mode: PlanMode::Create,
                hostname: "dev".into(),
                workdir: Some("/work".into()),
                shares: vec![Share {
                    tag: "_etc".into(),
                    guest: "/etc/x".into(),
                    readonly: true,
                }],
                volumes: vec![VolumeMount {
                    dev: to_volume_device(0),
                    guest: "/data".into(),
                }],
                net: Net::Brokered,
                published_ports: vec![80, 443],
                published_udp_ports: vec![53],
                env: BTreeMap::from([("FOO".to_string(), "bar".to_string())]),
                as_root: false,
                rootfs: RootfsMount::Overlay {
                    upper_dev: to_volume_device(1),
                },
                sudo: vec!["apk".into()],
                on_create: vec!["apk add git".into()],
                on_start: vec!["date".into()],
                pre_stop: vec!["sync".into()],
                daemons: vec!["while true; do sleep 60; done".into()],
                workload: Some("make".into()),
                sandbox_info: "# Terrarium sandbox".into(),
                await_initial_session: true,
                host_tz,
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
        }
    }

    #[test]
    fn volume_devices_continue_after_vdz() {
        assert_eq!(to_volume_device(0), "/dev/vdc");
        assert_eq!(to_volume_device(23), "/dev/vdz");
        assert_eq!(to_volume_device(24), "/dev/vdaa");
    }

    /// The kernel boots from the first device the host attaches and the agent finds the root
    /// on the second, so volumes start at the third.
    #[test]
    fn named_devices_follow_the_attach_order() {
        assert!(KERNEL_CMDLINE.contains(&format!("root={} ", block_device(0))));
        assert_eq!(ROOT_DEVICE, block_device(1));
        assert_eq!(to_volume_device(0), block_device(2));
    }
}
