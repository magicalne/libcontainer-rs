use std::{
    ffi::CString,
    fs,
    os::unix::{
        io::{AsRawFd, FromRawFd, RawFd},
    },
    path::{Path, PathBuf},
};

use fs::{File};
use io_uring::{cqueue, opcode, squeue, IoUring};
use libc::{O_NONBLOCK, c_int};
use nix::{Error, cmsg_space, fcntl::{FcntlArg, FdFlag, OFlag, fcntl, open}, libc::{self, TIOCSCTTY}, mount::{mount, umount2, MntFlags, MsFlags}, sched::{unshare, CloneFlags}, sys::{
        socket::{
            bind, recvmsg, sendmsg, socket, AddressFamily, ControlMessage, ControlMessageOwned,
            MsgFlags, SockAddr, SockFlag, SockType::Datagram, UnixAddr,
        },
        stat::Mode,
        uio::IoVec,
    }, unistd::chdir, unistd::getuid, unistd::{
        dup3, execve, fork, getgid, pivot_root, read, setgroups, setsid, symlinkat, write,
        ForkResult::{Child, Parent},
        Gid,
    }};
use opcode::{types, PollAdd};

use crate::{
    config::Config,
    config::{LinuxIDMapping, Root},
    LibContainerError, Result,
};

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
    fs::write(&path, deny).map_err(LibContainerError::IOError)
}

fn get_setgroups(pid: u32) -> Result<String> {
    let path = format!("/proc/{:?}/setgroups", pid);
    let mut file = std::fs::File::open(&path)?;
    let mut buf = String::new();
    let _ = std::io::Read::read_to_string(&mut file, &mut buf)?;
    Ok(buf)
}

fn update_uid_map(pid: u32, map_uid: u32, range: u32) -> Result<()> {
    let path = format!("/proc/{:?}/uid_map", pid);
    let content = format!("{:?} {:?} {:?}\n", map_uid, 1000, range);
    fs::write(PathBuf::from(path), content)?;
    Ok(())
}

fn update_gid_map(pid: u32, map_gid: u32, range: u32) -> Result<()> {
    disable_setgroups(pid)?;
    let path = format!("/proc/{:?}/gid_map", pid);
    let content = format!("{:?} {:?} {:?}\n", map_gid, 1000, range);
    fs::write(PathBuf::from(path), content)?;
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
    unshare(flag)?;
    let pid = std::process::id();
    update_uid_map(pid, 0, 1)?;
    update_gid_map(pid, 0, 1)?;

    let uid = getuid().as_raw();
    let gid = getgid().as_raw();
    dbg!(uid, gid);
    let none: Option<&[u8]> = None;
    let _ = fork();
    mount(Some("none"), "/proc", Some("proc"), MsFlags::empty(), none)?;
    dbg!(std::process::id());
    mount(none, "/", none, MsFlags::MS_PRIVATE, none)?;
    let container_path = Path::new(container_id);
    if !container_path.exists() {
        fs::create_dir(container_path)?;
    }
    let mut rootfs_path = PathBuf::new();
    rootfs_path.push(container_id);
    rootfs_path.push(rootfs);
    if !(rootfs_path.exists()) {
        fs::create_dir(&rootfs_path)?;
    }

    mount(
        Some(&rootfs_path),
        &rootfs_path,
        none,
        MsFlags::MS_BIND,
        none,
    )?;

    let oldrootfs = "oldrootfs";
    let mut oldrootfs_path = PathBuf::new();
    oldrootfs_path.push(&rootfs_path);
    oldrootfs_path.push(oldrootfs);
    fs::create_dir(&oldrootfs_path)?;
    let rootfs_path = fs::canonicalize(&rootfs_path)?;
    let oldrootfs_path = fs::canonicalize(&oldrootfs_path)?;
    dbg!(&rootfs_path, &oldrootfs_path);
    pivot_root(&rootfs_path, &oldrootfs_path)?;
    dbg!("debug");
    chdir("/")?;

    let mut oldrootfs_path = PathBuf::new();
    oldrootfs_path.push("/");
    oldrootfs_path.push(oldrootfs);
    umount2(&oldrootfs_path, MntFlags::MNT_DETACH)?;
    fs::remove_dir_all(oldrootfs).expect("cannot remove dir");

    Ok(())
}

fn setup_socket(path: &Path) -> Result<RawFd> {
    let socket_fd = socket(AddressFamily::Unix, Datagram, SockFlag::empty(), None)?;
    let addr = UnixAddr::new(path)?;
    bind(socket_fd, &SockAddr::Unix(addr))?;
    Ok(socket_fd)
}

fn send_ptmx_to_socket(socket_fd: RawFd, ptmx_fd: RawFd, path: &Path) -> Result<usize> {
    let fds = [ptmx_fd];
    let cmsgs = ControlMessage::ScmRights(&fds);
    let iov = [IoVec::from_slice(b" ")];
    let addr = SockAddr::Unix(UnixAddr::new(path)?);
    Ok(sendmsg(
        socket_fd,
        &iov,
        &[cmsgs],
        MsgFlags::empty(),
        Some(&addr),
    )?)
}

fn recv_ptmx_from_socket(socket_fd: RawFd) -> Option<RawFd> {
    let mut buf = [0u8; 5];
    let iov = [IoVec::from_mut_slice(&mut buf[..])];
    let mut cmsgspace = cmsg_space!([RawFd; 1]);
    let msg = recvmsg(socket_fd, &iov, Some(&mut cmsgspace), MsgFlags::empty()).ok()?;
    for cmsg in msg.cmsgs() {
        if let ControlMessageOwned::ScmRights(fd) = cmsg {
            return Some(fd[0]);
        }
    }
    None
}

const SOCKET_SUFFIX: &str = "notify";

fn wait_ptmx_fd(socket_fd: RawFd) -> Result<RawFd> {
    loop {
        if let Some(fd) = recv_ptmx_from_socket(socket_fd) {
            return Ok(fd);
        }
    }
}

pub fn run(container_id: &str, config: &Config) -> Result<()> {
    let pid = std::process::id();
    init_namespace(config)?;
    uid_map(pid, config)?;
    gid_map(pid, config)?;

    dbg!(std::process::id());
    let mut socket_path = get_rootfs_path(container_id, config);
    socket_path.push(SOCKET_SUFFIX);
    if socket_path.exists() {
        fs::remove_file(&socket_path)?;
    }
    let socket_fd = setup_socket(&socket_path)?;
    match fork() {
        Ok(Parent { child, .. }) => {
            dbg!(std::process::id());
            dbg!(child);
            let ptmx = wait_ptmx_fd(socket_fd)?;
            dbg!(ptmx);
            let mut redirect_io = RedirectIO::new(ptmx)?;
            redirect_io.waiting()?;
        }
        Ok(Child) => {
            dbg!(std::process::id());
            let pid = setsid()?;
            dbg!(pid);
            prepare_root(container_id, config)?;
            setup_ptmx(container_id, &config.root);
            setup_symlinks(container_id, &config.root);
            let ptmx = setup_terminal()?;
            dbg!(&ptmx);
            let socket_path = Path::new(SOCKET_SUFFIX);
            send_ptmx_to_socket(socket_fd, ptmx, socket_path)?;
            exec(config);
        }
        Err(err) => {
            return Err(LibContainerError::NixError(
                err,
                std::panic::Location::caller(),
            ))
        }
    }
    Ok(())
}

fn find_exe_file(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .filter_map(|dir| {
                let full_path = dir.join(&name);
                if full_path.is_file() {
                    Some(full_path)
                } else {
                    None
                }
            })
            .next()
    })
}

fn init_namespace(config: &Config) -> Result<()> {
    if let Some(linux) = config.linux.as_ref() {
        if let Some(nss) = linux.namespaces.as_ref() {
            let mut flag = 0;
            nss.iter().for_each(|e| {
                flag |= e.type_.transform().bits();
            });
            if let Some(flag) = CloneFlags::from_bits(flag) {
                let _ = unshare(flag)?;
            }
        }
    }
    Ok(())
}

fn write_id_map(pid: u32, filename: &str, ids: &[LinuxIDMapping]) -> Result<()> {
    let path = format!("/proc/{:?}/{}", pid, filename);
    let content = ids
        .iter()
        .map(|id| format!("{:?} {:?} 1\n", id.container_id, id.host_id))
        .fold(String::new(), |mut s, nxt| {
            s.push_str(&nxt);
            s
        });
    dbg!(&path, &content);
    fs::write(&path, &content)?;
    Ok(())
}

fn uid_map(pid: u32, config: &Config) -> Result<()> {
    if let Some(linux) = config.linux.as_ref() {
        if let Some(uids) = linux.uid_mappings.as_ref() {
            write_id_map(pid, "uid_map", uids)?;
        }
    }
    Ok(())
}

fn gid_map(pid: u32, config: &Config) -> Result<()> {
    if let Some(linux) = config.linux.as_ref() {
        if let Some(gids) = linux.gid_mappings.as_ref() {
            disable_setgroups(pid)?;
            write_id_map(pid, "gid_map", gids)?;
        }
    }
    Ok(())
}

fn set_groups(config: &Config) -> Result<()> {
    let setgroups_state = get_setgroups(std::process::id())?;
    dbg!(&setgroups_state);
    if let Some(process) = config.process.as_ref() {
        if let Some(gids) = process.user.additional_gids.as_ref() {
            let mapped = gids
                .iter()
                .map(|id| Gid::from_raw(*id))
                .collect::<Vec<Gid>>();
            setgroups(&mapped).map_err(|err| {
                let gid_str = gids
                    .iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<String>>()
                    .join(", ");
                LibContainerError::SetGroupsError(gid_str, err)
            })?
        }
    }
    Ok(())
}

fn init_mount(container_id: &str, config: &Config) -> Result<()> {
    let rootfs = get_rootfs_path(container_id, config);
    if let Some(mounts) = config.mounts.as_ref() {
        for m in mounts.iter() {
            let mut flags = MsFlags::empty();
            let mut option = String::new();
            if let Some(arr) = m.options.as_ref() {
                for elem in arr.iter() {
                    match get_mount_flag_or_option(&elem) {
                        Ok(flag) => {
                            flags |= flag;
                        }
                        Err(_) => {
                            if !option.is_empty() {
                                option.push_str(",");
                            }
                            option.push_str(&elem);
                        }
                    }
                }
            }
            let option = if option.is_empty() {
                None
            } else {
                Some(option)
            };
            let mut path = PathBuf::new();
            path.push(&rootfs);
            path.push(&m.destination[1..m.destination.len()]);
            if !path.exists() {
                let dest = Path::new(&m.destination);
                if dest.is_dir() {
                    fs::create_dir_all(&path).expect("cannot create dir all");
                } else if dest.is_file() {
                    let file = File::create(&path)?;
                    drop(file);
                }
            }
            mount(
                m.source.as_deref(),
                &path,
                m.type_.as_deref(),
                flags,
                option.as_deref(),
            )?;
        }
    }

    let mut src = rootfs.clone();
    src.push("dev/pts/ptmx");
    if !&src.exists() {
        File::create(&src).expect("canont create");
    }
    let mut dest = rootfs;
    dest.push("dev/ptmx");
    let _ = fs::remove_file(&dest);
    let file = File::create(&dest).expect("cannot create ptmx");
    drop(file);
    mount::<_, _, Path, Path>(Some(&src), &dest, None, MsFlags::MS_BIND, None)
        .expect("cannot mount /dev/pts/ptmx");
    Ok(())
}

fn get_rootfs_path(container_id: &str, config: &Config) -> PathBuf {
    let mut rootfs_path = PathBuf::new();
    rootfs_path.push(container_id);
    let rootfs = match config.root.as_ref() {
        Some(root) => root.path.as_str(),
        None => "rootfs",
    };
    rootfs_path.push(rootfs);
    rootfs_path
}

fn prepare_root(container_id: &str, config: &Config) -> Result<()> {
    let none: Option<&[u8]> = None;
    let mut rootfs_path = PathBuf::new();
    rootfs_path.push(container_id);
    let rootfs = match config.root.as_ref() {
        Some(root) => root.path.as_str(),
        None => "rootfs",
    };
    rootfs_path.push(rootfs);
    mount(
        Some(&rootfs_path),
        &rootfs_path,
        none,
        MsFlags::MS_BIND,
        none,
    )?;

    init_mount(container_id, config)?;
    let oldrootfs = "oldrootfs";
    let mut oldrootfs_path = PathBuf::new();
    oldrootfs_path.push(&rootfs_path);
    oldrootfs_path.push(oldrootfs);
    fs::create_dir(&oldrootfs_path)?;
    let rootfs_path = fs::canonicalize(&rootfs_path)?;
    let oldrootfs_path = fs::canonicalize(&oldrootfs_path)?;
    pivot_root(&rootfs_path, &oldrootfs_path).expect("pivot_root error");
    //.map_err(|err| LibContainerError::NixError(err))?;
    chdir("/")?;
    let mut oldrootfs_path = PathBuf::new();
    oldrootfs_path.push("/");
    oldrootfs_path.push(oldrootfs);
    umount2(&oldrootfs_path, MntFlags::MNT_DETACH)?;
    fs::remove_dir_all(oldrootfs).expect("cannot remove dir"); //.map_err(|err| LibContainerError::IOError(err))?;
    Ok(())
}

fn get_mount_flag_or_option(data: &str) -> std::result::Result<MsFlags, ()> {
    match data {
        "rbind" => Ok(MsFlags::MS_REC | MsFlags::MS_BIND),
        "ro" => Ok(MsFlags::MS_RDONLY),
        "rw" => Ok(MsFlags::empty()),
        "suid" => Ok(MsFlags::empty()),
        "nosuid" => Ok(MsFlags::MS_NOSUID),
        "dev" => Ok(MsFlags::empty()),
        "nodev" => Ok(MsFlags::MS_NODEV),
        "exec" => Ok(MsFlags::empty()),
        "noexec" => Ok(MsFlags::MS_NOEXEC),
        "sync" => Ok(MsFlags::MS_SYNCHRONOUS),
        "async" => Ok(MsFlags::empty()),
        "dirsync" => Ok(MsFlags::MS_DIRSYNC),
        "remount" => Ok(MsFlags::MS_REMOUNT),
        "mand" => Ok(MsFlags::MS_MANDLOCK),
        "nomand" => Ok(MsFlags::empty()),
        "atime" => Ok(MsFlags::empty()),
        "noatime" => Ok(MsFlags::MS_NOATIME),
        "diratime" => Ok(MsFlags::empty()),
        "nodiratime" => Ok(MsFlags::MS_NODIRATIME),
        "relatime" => Ok(MsFlags::MS_RELATIME),
        "norelatime" => Ok(MsFlags::empty()),
        "strictatime" => Ok(MsFlags::MS_STRICTATIME),
        "nostrictatime" => Ok(MsFlags::empty()),
        "shared" => Ok(MsFlags::MS_SHARED),
        "rshared" => Ok(MsFlags::MS_REC | MsFlags::MS_SHARED),
        "slave" => Ok(MsFlags::MS_SLAVE),
        "rslave" => Ok(MsFlags::MS_REC | MsFlags::MS_SLAVE),
        "private" => Ok(MsFlags::MS_PRIVATE),
        "rprivate" => Ok(MsFlags::MS_REC | MsFlags::MS_PRIVATE),
        "unbindable" => Ok(MsFlags::MS_UNBINDABLE),
        "runbindable" => Ok(MsFlags::MS_REC | MsFlags::MS_UNBINDABLE),
        _ => Err(()),
    }
}

struct SymLink<'a> {
    source: &'a str,
    destination: &'a str,
}

const SYMLINKS: &'static [&'static SymLink] = &[
    &SymLink {
        source: "/proc/self/fd",
        destination: "/dev/fd",
    },
    &SymLink {
        source: "/proc/self/fd0",
        destination: "/dev/stdin",
    },
    &SymLink {
        source: "/proc/self/fd1",
        destination: "/dev/stdout",
    },
    &SymLink {
        source: "/proc/self/fd2",
        destination: "/dev/stderr",
    },
];

fn setup_symlinks(container_id: &str, rootfs: &Option<Root>) {
    let mut path = PathBuf::new();
    path.push(container_id);
    match rootfs.as_ref() {
        Some(root) => path.push(&root.path),
        None => path.push("rootfs"),
    }

    for e in SYMLINKS {
        let mut dest = path.clone();
        dest.push(e.destination);
        symlinkat(e.source, None, dest.as_path()).expect("symbolic link failed");
    }
}

fn setup_ptmx(container_id: &str, rootfs: &Option<Root>) {
    let mut path = PathBuf::new();
    path.push(container_id);
    match rootfs.as_ref() {
        Some(root) => path.push(&root.path),
        None => path.push("rootfs"),
    }
    path.push("dev/ptmx");
    dbg!(&path);
    let _ = fs::remove_file(&path);
    File::create(&path);
    let path = Path::new("/dev/ptmx");
    mount::<_, _, Path, Path>(Some("/dev/pts/ptmx"), path, None, MsFlags::MS_BIND, None)
        .expect("cannot mount /dev/pts/ptmx");
    // symlinkat("pts/ptmx", None, path.as_path()).expect("Failed to setup ptmx");
}

fn setup_terminal() -> Result<RawFd> {
    let master: RawFd = open(
        Path::new("/dev/ptmx"),
        OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .expect("open");
    let slave_name = ptsname_r(master).expect("Failed to create pty slave");
    dbg!(&slave_name);
    grantpt(master).expect("cannot grant");
    unlockpt(master).expect("Failed to unlock");
    let slave_fd: RawFd = open(Path::new(&slave_name), OFlag::O_RDWR, Mode::empty())
        .expect("Failed to open slave fd");
    let console = Path::new("/dev/console");
    if !console.exists() {
        File::create(console).expect("cannot create console");
    }
    mount::<_, _, str, Path>(
        Some(Path::new(&slave_name)),
        console,
        Some("bind"),
        MsFlags::MS_BIND,
        None,
    )?;
    dup3(slave_fd, 0, OFlag::O_RDONLY).expect("Failed to set stdin");
    dup3(slave_fd, 1, OFlag::O_RDONLY).expect("Failed to set stdout");
    dup3(slave_fd, 2, OFlag::O_RDONLY).expect("Failed to set stderr");
    ioctl(0)?;
    Ok(master)
}

pub fn ptsname_r(fd: RawFd) -> Result<String> {
    let mut name_buf = vec![0u8; 64];
    let name_buf_ptr = name_buf.as_mut_ptr() as *mut libc::c_char;
    if unsafe { libc::ptsname_r(fd, name_buf_ptr, name_buf.capacity()) } != 0 {
        return Err(LibContainerError::NixError(
            Error::last(),
            std::panic::Location::caller(),
        ));
    }

    // Find the first null-character terminating this string. This is guaranteed to succeed if the
    // return value of `libc::ptsname_r` is 0.
    let null_index = name_buf.iter().position(|c| *c == b'\0').unwrap();
    name_buf.truncate(null_index);

    let name = String::from_utf8(name_buf)?;
    Ok(name)
}

pub fn grantpt(fd: RawFd) -> Result<()> {
    if unsafe { libc::grantpt(fd) } < 0 {
        return Err(LibContainerError::NixError(
            Error::last(),
            std::panic::Location::caller(),
        ));
    }
    Ok(())
}

pub fn unlockpt(fd: RawFd) -> Result<()> {
    if unsafe { libc::unlockpt(fd) } < 0 {
        return Err(LibContainerError::NixError(
            Error::last(),
            std::panic::Location::caller(),
        ));
    }

    Ok(())
}

pub fn ioctl(fd: RawFd) -> Result<()> {
    unsafe {
        let res = libc::ioctl(fd, TIOCSCTTY, 0);
        if res < 0 {
            return Err(LibContainerError::NixError(
                Error::last(),
                std::panic::Location::caller(),
            ));
        }
    }
    Ok(())
}

pub fn exec(config: &Config) {
    if let Some(process) = config.process.as_ref() {
        if let Some(args) = process.args.as_ref() {
            let env = match process.env.as_ref() {
                Some(env) => env
                    .iter()
                    .map(|t| {
                        let mut sp = t.split("=");
                        let k = sp.next().expect("Not an env key");
                        let v = sp.next().expect("Not an env val");
                        std::env::set_var(k, v);
                        CString::new(t.as_bytes().as_ref()).unwrap()
                    })
                    .collect::<Vec<CString>>(),
                None => Vec::new(),
            };
            let env = env.iter().map(|t| t.as_c_str()).collect::<Vec<_>>();
            let path = find_exe_file(args.first().expect("No arg"))
                .expect("Not found")
                .into_os_string()
                .into_string()
                .expect("Not found");
            let path = CString::new(path.as_bytes().as_ref()).unwrap();
            let args: Vec<CString> = args
                .iter()
                .map(|t| {
                    CString::new(t.as_bytes().as_ref()).unwrap()
                    //let c_world: *const c_char = c_str.as_ptr() as *const c_char;
                    //unsafe { CStr::from_ptr(c_world) }
                })
                .collect();
            let args = &args.iter().map(|t| t.as_c_str()).collect::<Vec<_>>();

            execve(path.as_c_str(), args.as_slice(), env.as_slice()).expect("execve failed");
        }
    }
}

struct RedirectIO {
    ring: IoUring,
    ptmx: RawFd,
    ptmx_poll_e: squeue::Entry,
    stdin_poll_e: squeue::Entry,
}

impl RedirectIO {
    fn new(ptmx: RawFd) -> Result<Self> {
        let ptmx_poll_e = opcode::PollAdd::new(types::Fd(ptmx), libc::POLLIN as _)
            .build()
            .user_data(0);
        let stdin_poll_e = opcode::PollAdd::new(types::Fd(0), libc::POLLIN as _)
            .build()
            .user_data(1);
        let ring = IoUring::new(2)?;
        ring.submitter().register_files(&[ptmx, 0])?;
        Ok(RedirectIO {
            ring,
            ptmx,
            ptmx_poll_e,
            stdin_poll_e,
        })
    }

    fn submit_entry(&mut self, entry: squeue::Entry) {
        unsafe {
            let mut sq = self.ring.submission().available();
            sq.push(entry).ok().expect("queue is full");
        }
    }

    fn waiting(&mut self) -> Result<()> {
        self.submit_entry(self.ptmx_poll_e.clone());
        self.submit_entry(self.stdin_poll_e.clone());
        loop {
            let n = self.ring.submitter().submit_and_wait(1)?;
            self.process_response()?;
        }
        Ok(())
    }

    fn process_response(&mut self) -> Result<()> {
        let cq = self.ring.completion().available();
        let vec = cq.collect::<Vec<_>>();
        for e in vec {
            self.process_entry(e)?
        }
        Ok(())
    }

    fn process_entry(&mut self, entry: cqueue::Entry) -> Result<()> {
        let ud = entry.user_data();
        match ud {
            0 => {
                set_blocking_fd(self.ptmx, false)?;
                copy_from_fd_to_fd(self.ptmx, 1)?;
                set_blocking_fd(self.ptmx, true)?;
                self.submit_entry(self.ptmx_poll_e.clone());
            },
            1 => {
                copy_from_fd_to_fd(0, self.ptmx)?;
                self.submit_entry(self.stdin_poll_e.clone());
            },
            _ => {}
        }
        Ok(())
    }
}

fn copy_from_fd_to_fd(from: RawFd, to: RawFd) -> Result<()> {
    const SIZE: usize = 512;
    loop {
        let mut buf = [0u8; SIZE];
        let n = read(from, &mut buf)?;
        let n = write(to, &buf[0..n])?;
        if n < SIZE {
            break;
        }
    }
    Ok(())
}

fn set_blocking_fd(fd: RawFd, blocking: bool) -> Result<()> {
    let mut flag: c_int = fcntl(fd, FcntlArg::F_GETFD)?;
    if blocking {
        flag &= !O_NONBLOCK;
    } else {
        flag &= O_NONBLOCK;
    }
    let fd_flag = FdFlag::from_bits_truncate(flag);
    let ret = fcntl(fd, FcntlArg::F_SETFD(fd_flag))?;
    Ok(())
}