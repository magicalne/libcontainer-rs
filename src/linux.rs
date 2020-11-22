use std::{fs, io::Read, fs::metadata, path::{Path, PathBuf}};

use nix::{mount::{mount, MsFlags}, mount::{umount2, MntFlags}, sched::{unshare, CloneFlags}, unistd::chdir, unistd::getuid, unistd::{fork, getgid, pivot_root}};

use crate::{LibContainerError, Result};

/**
Linux 3.19 made a change in the handling of setgroups(2) and the
'gid_map' file to address a security issue. The issue allowed
*unprivileged* users to employ user namespaces in order to drop
The upshot of the 3.19 changes is that in order to update the
'gid_maps' file, use of the setgroups() system call in this
user namespace must first be disabled by writing "deny" to one of
the /proc/PID/setgroups files for this namespace.  That is the
purpose of the following function.
**/
fn disable_setgroups(pid: u32) -> Result<()> {
    let path = format!("/proc/{:?}/setgroups", pid);
    let deny = "deny";
    fs::write(&path, deny)
        .map_err(|e| LibContainerError::IOError(e))
}

fn update_uid_map(pid: u32, map_uid: u32, range: u32) -> Result<()> {
    let path = format!("/proc/{:?}/uid_map", pid);
    let content = format!("{:?} {:?} {:?}\n", map_uid, 1000, range);
    fs::write(PathBuf::from(path), content)
        .map_err(|e| LibContainerError::IOError(e))?;
    Ok(())
}

fn update_gid_map(pid: u32, map_gid: u32, range: u32) -> Result<()> {
    disable_setgroups(pid)?;
    let path = format!("/proc/{:?}/gid_map", pid);
    let content = format!("{:?} {:?} {:?}\n", map_gid, 1000, range);
    fs::write(PathBuf::from(path), content)
        .map_err(|e| LibContainerError::IOError(e))?;
    Ok(())
}

pub fn prepare_root_fs(container_id: &str, rootfs: &str) -> Result<()> {
    let mut flag = CloneFlags::CLONE_NEWUSER;
    flag |= CloneFlags::CLONE_NEWPID;
    flag |= CloneFlags::CLONE_NEWNS;
    flag |= CloneFlags::CLONE_NEWNET;
    flag |= CloneFlags::CLONE_NEWIPC;
    flag |= CloneFlags::CLONE_NEWCGROUP;
    flag |= CloneFlags::CLONE_NEWUTS;
    unshare(flag).map_err(|e| LibContainerError::NixError(e))?;
    let pid = std::process::id();
    update_uid_map(pid, 0, 1)?;
    update_gid_map(pid, 0, 1)?;

    let uid = getuid().as_raw();
    let gid = getgid().as_raw();
    dbg!(uid, gid);
    let none: Option<&[u8]> = None;
    let _ = fork();
    mount(Some("none"), "/proc", Some("proc"), MsFlags::empty(), none)
        .map_err(|err| LibContainerError::NixError(err))?;
    dbg!(std::process::id());
    mount(none, "/", none, MsFlags::MS_PRIVATE, none)
        .map_err(|err| LibContainerError::NixError(err))?;
    let container_path = Path::new(container_id);
    if !container_path.exists() {
        fs::create_dir(container_path).map_err(|err| LibContainerError::IOError(err))?;
    }
    let mut rootfs_path = PathBuf::new();
    rootfs_path.push(container_id);
    rootfs_path.push(rootfs);
    if !(rootfs_path.exists()) {
        fs::create_dir(&rootfs_path).map_err(|err| LibContainerError::IOError(err))?;
    }

    mount(Some(&rootfs_path), &rootfs_path, none, MsFlags::MS_BIND, none)
        .map_err(|err| LibContainerError::NixError(err))?;

    let oldrootfs = "oldrootfs";
    let mut oldrootfs_path = PathBuf::new();
    oldrootfs_path.push(&rootfs_path);
    oldrootfs_path.push(oldrootfs);
    fs::create_dir(&oldrootfs_path).map_err(|err| LibContainerError::IOError(err))?;
    let rootfs_path = fs::canonicalize(&rootfs_path).map_err(|err| LibContainerError::IOError(err))?;
    let oldrootfs_path= fs::canonicalize(&oldrootfs_path).map_err(|err| LibContainerError::IOError(err))?;
    dbg!(&rootfs_path, &oldrootfs_path);
    pivot_root(&rootfs_path, &oldrootfs_path)
        .map_err(|err| LibContainerError::NixError(err))?;
    dbg!("debug");
    chdir("/").map_err(|err| LibContainerError::NixError(err))?;

    let mut oldrootfs_path = PathBuf::new();
    oldrootfs_path.push("/");
    oldrootfs_path.push(oldrootfs);
    umount2(&oldrootfs_path, MntFlags::MNT_DETACH).map_err(|err| LibContainerError::NixError(err))?;
    fs::remove_dir_all(oldrootfs).expect("cannot remove dir"); //.map_err(|err| LibContainerError::IOError(err))?;

    dbg!(std::env::current_dir());
    Ok(())
}

#[cfg(test)]
mod tests {
    use rusty_fork::rusty_fork_test;

    use super::prepare_root_fs;
    rusty_fork_test! {
        #[test]
        fn prepare_root_fs_test() {
            prepare_root_fs("my_container", "rootfs").unwrap();
            //std::thread::sleep(std::time::Duration::new(10, 0));
            std::process::exit(0);
        }
    }
}
