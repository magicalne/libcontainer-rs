use std::collections::HashMap;

use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    oci_version: String,
    process: Option<Process>,
    root: Option<Root>,
    hostname: Option<String>,
    mounts: Option<Vec<Mount>>,
    hooks: Option<Hooks>,
    annotations: HashMap<String, String>,

    linux: Option<Linux>,
    // TODO solaris and windows

}

#[derive(Serialize, Deserialize, Debug)]
pub struct VMHypervisor {
    path: String,
    parameters: Option<Vec<String>>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VMKernel {
    path: String,
    parameters: Option<Vec<String>>,
    initrd: Option<String>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct VMImage {
    path: String,
    format: String
}
#[derive(Serialize, Deserialize, Debug)]
pub struct VM {
    hypervisor: Option<VMHypervisor>,
    kernel: VMKernel,
    image: Option<VMImage>
}
#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Linux {
    uid_mappings: Option<Vec<LinuxIDMapping>>,
    gid_mappings: Option<Vec<LinuxIDMapping>>,
    sysctl: Option<HashMap<String, String>>,
    resources: Option<LinuxResuources>,
    cgroup_path: Option<String>,
    namespaces: Option<Vec<LinuxNamespace>>,
    devices: Option<Vec<LinuxDevice>>,
    seccomp: Option<LinuxSeccomp>,
    rootfs_propagation: Option<String>,
    masked_paths: Option<Vec<String>>,
    readonly_paths: Option<Vec<String>>,
    mount_label: Option<String>,
    intel_rdt: Option<LinuxIntelRdt>,
    personality: Option<LinuxPersonality>
}



#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxPersonality {
    domain: String,
    flags: Option<Vec<String>>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxIntelRdt {
    #[serde(rename = "closID")] 
    clos_id: Option<String>,
    l3_cache_schema: Option<String>,
    mem_bw_schema: Option<String>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxSyscall {
    names: Vec<String>,
    action: String,
    errno_ret: Option<u32>,
    args: Option<Vec<String>>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxSeccomp {
    #[serde(rename = "defaultAction")] 
    default_action: String,
    architectures: Option<Vec<String>>,
    flags: Option<Vec<String>>,
    syscalls: Option<Vec<LinuxSyscall>>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxNamespace {
    #[serde(rename = "type")] 
    type_: String,
    path: Option<String>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxIDMapping {
    #[serde(rename = "containerID")] 
    container_id: u32,
    #[serde(rename = "hostID")] 
    host_id: u32,
    size: u32
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxResuources {
    devices: Option<Vec<LinuxDeviceCgroup>>,
    momory: Option<LinuxMemory>,
    cpu: Option<LinuxCPU>,
    pids: Option<LinuxPids>,
    #[serde(rename = "blockIO")] 
    block_io: Option<LinuxBlockIO>,
    hugepage_limits: Option<Vec<LinuxHugePageLimit>>,
    network: Option<LinuxNetwork>,
    rdma: Option<HashMap<String, LinuxRdma>>,
    unified: Option<HashMap<String, String>>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxDeviceCgroup {
    allow: bool,
    #[serde(rename = "type")] 
    type_: Option<String>,
    major: Option<i64>,
    minor: Option<i64>,
    access: Option<String>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxMemory {
    limit: Option<i64>,
    reservation: Option<i64>,
    swap: Option<i64>,
    kernel: Option<i64>,
    #[serde(rename = "kernelTCP")]
    kernel_tcp: Option<i64>,
    swappiness: Option<u64>,
    #[serde(rename = "disableOOMKiller")]
    disable_oom_killer: Option<bool>,
    use_hierarchy: Option<bool>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxCPU {
    shares: Option<u64>,
    quota: Option<i64>,
    period: Option<u64>,
    realtime_runtime: Option<i64>,
    realtime_period: Option<u64>,
    cpus: Option<String>,
    mems: Option<String>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxPids {
    limit: i64
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxNetwork {
    #[serde(rename = "classID")] 
    class_id: Option<u32>,
    priorities: Option<Vec<LinuxInterfacePriority>>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxInterfacePriority {
    name: String,
    priority: u32
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxRdma {
    hca_handles: Option<u32>,
    hca_objects: Option<u32>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxBlockIO {
    weight: Option<u16>,
    leaf_weight: Option<u16>,
    weight_device: Option<Vec<LinuxWeightDevice>>,
    throttle_read_bps_device: Option<Vec<LinuxThrottleDevice>>,
    throttle_write_bps_device: Option<Vec<LinuxThrottleDevice>>,
    #[serde(rename = "throttleReadIOPSDevice")] 
    throttle_read_iops_device: Option<Vec<LinuxThrottleDevice>>,
    #[serde(rename = "throttleWriteIOPSDevice")] 
    throttle_write_iops_device: Option<Vec<LinuxThrottleDevice>>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxWeightDevice {
    major: i64,
    minor: i64,
    weight: Option<u16>,
    leaf_weight: Option<u16>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxThrottleDevice {
    major: i64,
    minor: i64,
    rate: u64
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxHugePageLimit {
    page_size: String,
    limit: u64
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxDevice {
    path: String,
    #[serde(rename = "type")] 
    type_: Option<String>,
    major: Option<i64>,
    minor: Option<i64>,
    file_mode: Option<u32>,
    uid: Option<u32>,
    gid: Option<u32>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Hook {
    path: String,
    args: Option<Vec<String>>,
    env: Option<Vec<String>>,
    timeout: Option<i32>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Hooks {
    prestart: Option<Vec<Hook>>,
    create_runtime: Option<Vec<Hook>>,
    create_container: Option<Vec<Hook>>,
    start_container: Option<Vec<Hook>>,
    post_start: Option<Vec<Hook>>,
    post_stop: Option<Vec<Hook>>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Mount {
    destination: String,
    #[serde(rename = "type")] 
    type_: Option<String>,
    source: Option<String>,
    options: Option<Vec<String>>

}
#[derive(Serialize, Deserialize, Debug)]
pub struct Root {
    path: String,
    readonly: Option<bool>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    uid: u32,
    gid: u32,
    umask: Option<u32>,
    additional_gids: Option<Vec<u32>>,
    username: Option<String>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Process {
    terminal: Option<bool>,
    console_size: Option<ConsoleSize>,
    user: User,
    args: Option<Vec<String>>,
    command_line: Option<String>,
    env: Option<Vec<String>>,
    cwd: String,
    capabilities: LinuxCapabilities,
    r_limits: Option<POSIXRlimit>,
    no_new_privileges: Option<bool>,
    apparmor_profile: Option<String>,
    oom_score_adj: Option<i32>,
    selinux_label: Option<String>
}


#[derive(Serialize, Deserialize, Debug)]
pub struct POSIXRlimit {
    #[serde(rename = "type")] 
    type_: String,
    hard: usize,
    soft: usize
}
#[derive(Serialize, Deserialize, Debug)]
pub struct LinuxCapabilities {
    bounding: Option<Vec<String>>,
    effective: Option<Vec<String>>,
    inheritable: Option<Vec<String>>,
    permitted: Option<Vec<String>>,
    ambient: Option<Vec<String>>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct ConsoleSize {
    height: u32,
    width: u32
}

mod tests {

    #[test]
    fn spec_test() -> std::io::Result<()> {
                    
        let mut path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("config.json");
        let mut file = std::fs::File::open(&path)?;
        let mut buf = String::new();
        let _ = std::io::Read::read_to_string(&mut file, &mut buf);
        let config: super::Config  = serde_json::from_str(&buf).unwrap();
        dbg!(config);
        Ok(())
    }
}