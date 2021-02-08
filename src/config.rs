use std::collections::HashMap;

use nix::sched::CloneFlags;
use serde::{Deserialize, Serialize};

use super::Result;

use crate::LibContainerError;
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    pub oci_version: String,
    pub process: Option<Process>,
    pub root: Option<Root>,
    pub hostname: Option<String>,
    pub mounts: Option<Vec<Mount>>,
    pub hooks: Option<Hooks>,
    pub annotations: Option<HashMap<String, String>>,

    pub linux: Option<Linux>,
    // TODO solaris and windows
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VMHypervisor {
    pub path: String,
    pub parameters: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VMKernel {
    pub path: String,
    pub parameters: Option<Vec<String>>,
    pub initrd: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct VMImage {
    pub path: String,
    pub format: String,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct VM {
    pub hypervisor: Option<VMHypervisor>,
    pub kernel: VMKernel,
    pub image: Option<VMImage>,
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Linux {
    pub uid_mappings: Option<Vec<LinuxIDMapping>>,
    pub gid_mappings: Option<Vec<LinuxIDMapping>>,
    pub sysctl: Option<HashMap<String, String>>,
    pub resources: Option<LinuxResuources>,
    pub cgroup_path: Option<String>,
    pub namespaces: Option<Vec<LinuxNamespace>>,
    pub devices: Option<Vec<LinuxDevice>>,
    pub seccomp: Option<LinuxSeccomp>,
    pub rootfs_propagation: Option<String>,
    pub masked_paths: Option<Vec<String>>,
    pub readonly_paths: Option<Vec<String>>,
    pub mount_label: Option<String>,
    pub intel_rdt: Option<LinuxIntelRdt>,
    pub personality: Option<LinuxPersonality>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxPersonality {
    pub domain: String,
    pub flags: Option<Vec<String>>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxIntelRdt {
    #[serde(rename = "closID")]
    pub clos_id: Option<String>,
    pub l3_cache_schema: Option<String>,
    pub mem_bw_schema: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxSyscall {
    pub names: Vec<String>,
    pub action: String,
    pub errno_ret: Option<u32>,
    pub args: Option<Vec<String>>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxSeccomp {
    #[serde(rename = "defaultAction")]
    pub default_action: String,
    pub architectures: Option<Vec<String>>,
    pub flags: Option<Vec<String>>,
    pub syscalls: Option<Vec<LinuxSyscall>>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum NamespaceType {
    Pid,
    Network,
    Ipc,
    Uts,
    Mount,
    User,
    Cgroup
}

impl NamespaceType {
    pub fn transform(&self) -> CloneFlags {
       match self {
            NamespaceType::Pid => CloneFlags::CLONE_NEWPID,
            NamespaceType::Network => CloneFlags::CLONE_NEWNS,
            NamespaceType::Ipc => CloneFlags::CLONE_NEWIPC,
            NamespaceType::Uts => CloneFlags::CLONE_NEWUTS,
            NamespaceType::Mount => CloneFlags::CLONE_NEWNS,
            NamespaceType::User => CloneFlags::CLONE_NEWUSER,
            NamespaceType::Cgroup => CloneFlags::CLONE_NEWCGROUP,
        }
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxNamespace {
    #[serde(rename = "type")]
    pub type_: NamespaceType,
    pub path: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxIDMapping {
    #[serde(rename = "containerID")]
    pub container_id: u32,
    #[serde(rename = "hostID")]
    pub host_id: u32,
    pub size: u32,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxResuources {
    pub devices: Option<Vec<LinuxDeviceCgroup>>,
    pub momory: Option<LinuxMemory>,
    pub cpu: Option<LinuxCPU>,
    pub pids: Option<LinuxPids>,
    #[serde(rename = "blockIO")]
    pub block_io: Option<LinuxBlockIO>,
    pub hugepage_limits: Option<Vec<LinuxHugePageLimit>>,
    pub network: Option<LinuxNetwork>,
    pub rdma: Option<HashMap<String, LinuxRdma>>,
    pub unified: Option<HashMap<String, String>>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxDeviceCgroup {
    pub allow: bool,
    #[serde(rename = "type")]
    pub type_: Option<String>,
    pub major: Option<i64>,
    pub minor: Option<i64>,
    pub access: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxMemory {
    pub limit: Option<i64>,
    pub reservation: Option<i64>,
    pub swap: Option<i64>,
    pub kernel: Option<i64>,
    #[serde(rename = "kernelTCP")]
    pub kernel_tcp: Option<i64>,
    pub swappiness: Option<u64>,
    #[serde(rename = "disableOOMKiller")]
    pub disable_oom_killer: Option<bool>,
    pub use_hierarchy: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxCPU {
    pub shares: Option<u64>,
    pub quota: Option<i64>,
    pub period: Option<u64>,
    pub realtime_runtime: Option<i64>,
    pub realtime_period: Option<u64>,
    pub cpus: Option<String>,
    pub mems: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxPids {
    pub limit: i64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxNetwork {
    #[serde(rename = "classID")]
    pub class_id: Option<u32>,
    pub priorities: Option<Vec<LinuxInterfacePriority>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxInterfacePriority {
    pub name: String,
    pub priority: u32,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxRdma {
    pub hca_handles: Option<u32>,
    pub hca_objects: Option<u32>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxBlockIO {
    pub weight: Option<u16>,
    pub leaf_weight: Option<u16>,
    pub weight_device: Option<Vec<LinuxWeightDevice>>,
    pub throttle_read_bps_device: Option<Vec<LinuxThrottleDevice>>,
    pub throttle_write_bps_device: Option<Vec<LinuxThrottleDevice>>,
    #[serde(rename = "throttleReadIOPSDevice")]
    pub throttle_read_iops_device: Option<Vec<LinuxThrottleDevice>>,
    #[serde(rename = "throttleWriteIOPSDevice")]
    pub throttle_write_iops_device: Option<Vec<LinuxThrottleDevice>>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxWeightDevice {
    pub major: i64,
    pub minor: i64,
    pub weight: Option<u16>,
    pub leaf_weight: Option<u16>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxThrottleDevice {
    pub major: i64,
    pub minor: i64,
    pub rate: u64,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxHugePageLimit {
    pub page_size: String,
    pub limit: u64,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxDevice {
    pub path: String,
    #[serde(rename = "type")]
    pub type_: Option<String>,
    pub major: Option<i64>,
    pub minor: Option<i64>,
    pub file_mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Hook {
    pub path: String,
    pub args: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub timeout: Option<i32>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Hooks {
    pub prestart: Option<Vec<Hook>>,
    pub create_runtime: Option<Vec<Hook>>,
    pub create_container: Option<Vec<Hook>>,
    pub start_container: Option<Vec<Hook>>,
    pub post_start: Option<Vec<Hook>>,
    pub post_stop: Option<Vec<Hook>>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Mount {
    pub destination: String,
    #[serde(rename = "type")]
    pub type_: Option<String>,
    pub source: Option<String>,
    pub options: Option<Vec<String>>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Root {
    pub path: String,
    pub readonly: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub umask: Option<u32>,
    pub additional_gids: Option<Vec<u32>>,
    pub username: Option<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Process {
    pub terminal: Option<bool>,
    pub console_size: Option<ConsoleSize>,
    pub user: User,
    pub args: Option<Vec<String>>,
    pub command_line: Option<String>,
    pub env: Option<Vec<String>>,
    pub cwd: String,
    pub capabilities: LinuxCapabilities,
    pub r_limits: Option<POSIXRlimit>,
    pub no_new_privileges: Option<bool>,
    pub apparmor_profile: Option<String>,
    pub oom_score_adj: Option<i32>,
    pub selinux_label: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct POSIXRlimit {
    #[serde(rename = "type")]
    pub type_: String,
    pub hard: usize,
    pub soft: usize,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxCapabilities {
    pub bounding: Option<Vec<String>>,
    pub effective: Option<Vec<String>>,
    pub inheritable: Option<Vec<String>>,
    pub permitted: Option<Vec<String>>,
    pub ambient: Option<Vec<String>>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ConsoleSize {
    pub height: u32,
    pub width: u32,
}

impl Config {
    pub fn read_file(file_path: &str) -> Result<Config> {
        let mut file =
            std::fs::File::open(&file_path).map_err(|err| LibContainerError::IOError(err))?;
        let mut buf = String::new();
        let _ = std::io::Read::read_to_string(&mut file, &mut buf)
            .map_err(|err| LibContainerError::IOError(err))?;
        let config = serde_json::from_str(&buf).map_err(|err| LibContainerError::SerdeError(err));
        return config;
    }
}

mod tests {

    #[test]
    fn spec_test() -> std::io::Result<()> {
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("config.json");
        let config = super::Config::read_file(path.to_str().unwrap());
        assert!(config.is_ok());
        Ok(())
    }
}
