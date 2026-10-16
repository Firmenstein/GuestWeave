//! Virtual file descriptor table for pseudo-file emulation.
//!
//! New pseudo-file opens allocate from `VFD_BASE = 0x4000_0000` to avoid
//! colliding with native guest descriptors. `dup2`/`dup3` may deliberately
//! install the same open-file description at a requested low descriptor, so
//! table membership—not a numeric range check—is the authoritative identity.

use fmst_iib_api::context::IIBContextOps;
use fmst_iib_api::pseudo_file::{PseudoFile, PseudoFileFactory, PseudoFileOpen};
use fmst_iib_api::types::{Errno, GuestAddr, GuestReg};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

// Runtime-private envelope; not the schema of a PseudoFile's opaque bytes.
const VFD_HANDOFF_SCHEMA_VERSION: u32 = 2;

/// Encode a semantic API error for QEMU's *target* syscall return convention.
/// LibAFL's skipped syscall bypasses QEMU's host-to-target errno translation.
/// The MIPS CPU loop later sets a3 and negates this result; it does not map the
/// errno number. Keep public Errno discriminants stable (asm-generic values).
pub(crate) fn guest_errno_result(error: Errno) -> i64 {
    #[cfg(any(feature = "mips", feature = "mipsbe"))]
    {
        // Pinned QEMU linux-user/mips/target_errno_defs.h. Exhaustive over the
        // API enum so a new error requires an explicit target ABI decision.
        let number = match error {
            Errno::ENAMETOOLONG => 78,
            Errno::ENOSYS => 89,
            Errno::EOVERFLOW => 79,
            Errno::EPERM
            | Errno::ENOENT
            | Errno::EIO
            | Errno::EBADF
            | Errno::EAGAIN
            | Errno::ENOMEM
            | Errno::EACCES
            | Errno::EFAULT
            | Errno::EBUSY
            | Errno::EEXIST
            | Errno::ENODEV
            | Errno::EINVAL
            | Errno::ENOTTY
            | Errno::ENOSPC
            | Errno::ESPIPE
            | Errno::EPIPE
            | Errno::ERANGE => error as i64,
        };
        -number
    }
    #[cfg(not(any(feature = "mips", feature = "mipsbe")))]
    {
        error.as_neg_i64()
    }
}

/// Linux guest syscall numbers intercepted for pseudo-file routing.
///
/// The runtime is compiled for exactly one guest architecture by its harness.
/// Keeping the numbers here avoids accidentally treating an ARM syscall as the
/// same operation in a MIPS or x86_64 guest.
#[cfg(any(
    feature = "arm",
    not(any(
        feature = "arm",
        feature = "mips",
        feature = "mipsbe",
        feature = "x86_64"
    ))
))]
pub mod syscall_no {
    pub const READ: i32 = 3;
    pub const WRITE: i32 = 4;
    pub const OPEN: i32 = 5;
    pub const CLOSE: i32 = 6;
    pub const EXECVE: i32 = 11;
    pub const EXECVEAT: i32 = 387;
    pub const FSTAT: i32 = 108;
    pub const LSEEK: i32 = 19;
    pub const DUP: i32 = 41;
    pub const IOCTL: i32 = 54;
    pub const FCNTL: i32 = 55;
    pub const DUP2: i32 = 63;
    pub const FSYNC: i32 = 118;
    pub const FCNTL64: i32 = 221;
    pub const OPENAT: i32 = 322;
    pub const DUP3: i32 = 358;
}

#[cfg(all(not(feature = "arm"), any(feature = "mips", feature = "mipsbe")))]
pub mod syscall_no {
    pub const READ: i32 = 4003;
    pub const WRITE: i32 = 4004;
    pub const OPEN: i32 = 4005;
    pub const CLOSE: i32 = 4006;
    pub const EXECVE: i32 = 4011;
    pub const EXECVEAT: i32 = 4356;
    pub const FSTAT: i32 = 4108;
    pub const LSEEK: i32 = 4019;
    pub const DUP: i32 = 4041;
    pub const IOCTL: i32 = 4054;
    pub const FCNTL: i32 = 4055;
    pub const DUP2: i32 = 4063;
    pub const FSYNC: i32 = 4118;
    pub const FCNTL64: i32 = 4220;
    pub const OPENAT: i32 = 4288;
    pub const DUP3: i32 = 4327;
}

#[cfg(all(
    not(feature = "arm"),
    not(any(feature = "mips", feature = "mipsbe")),
    feature = "x86_64"
))]
pub mod syscall_no {
    pub const READ: i32 = 0;
    pub const WRITE: i32 = 1;
    pub const OPEN: i32 = 2;
    pub const CLOSE: i32 = 3;
    pub const EXECVE: i32 = 59;
    pub const EXECVEAT: i32 = 322;
    pub const FSTAT: i32 = 5;
    pub const LSEEK: i32 = 8;
    pub const IOCTL: i32 = 16;
    pub const DUP: i32 = 32;
    pub const DUP2: i32 = 33;
    pub const FCNTL: i32 = 72;
    pub const FSYNC: i32 = 74;
    pub const FCNTL64: i32 = -1;
    pub const OPENAT: i32 = 257;
    pub const DUP3: i32 = 292;
}

mod fcntl_cmd {
    pub const DUPFD: i64 = 0;
    pub const GETFD: i64 = 1;
    pub const SETFD: i64 = 2;
    pub const GETFL: i64 = 3;
    pub const SETFL: i64 = 4;
    pub const DUPFD_CLOEXEC: i64 = 1030;
}

const FD_CLOEXEC: i64 = 1;
const O_CLOEXEC: i64 = 0x0008_0000;
const O_ACCMODE: i64 = 0x3;

/// Result of dispatching a syscall through the VFS.
pub enum VfsResult {
    /// The VFS does not own this operation; let the native guest path handle it.
    NativeFallback,
    /// VFS handled the syscall; use this value as the guest return.
    Handled(GuestReg),
    /// The VFS owns the operation, but the guest-visible operation failed.
    /// This is deliberately distinct from [`NativeFallback`]: once a virtual
    /// descriptor has been claimed, an unsupported ioctl/read/etc. must not
    /// silently reach the native guest path.
    GuestError(Errno),
}

pub const VFD_BASE: i64 = 0x4000_0000;

enum PathFactory {
    Legacy(fn() -> Box<dyn PseudoFile>),
    PathAware(PseudoFileFactory),
}

struct RegisteredResource {
    id: String,
    implementation: String,
    factory: PathFactory,
}

struct OpenFileDescription {
    file: Box<dyn PseudoFile>,
    /// Exact guest path used to construct the description.  Keeping this on
    /// the shared OFD makes an exec handoff independent from which duplicate
    /// descriptor happens to be inspected first.
    path: String,
    resource_id: String,
    implementation: String,
    /// File status flags are shared by descriptors duplicated from one open.
    status_flags: i64,
}

#[derive(Clone)]
struct VirtualDescriptor {
    description: Arc<Mutex<OpenFileDescription>>,
    /// Descriptor flags are per-fd rather than per open-file description.
    close_on_exec: bool,
}

pub struct VirtualFdTable {
    /// path → factory that produces a fresh PseudoFile on open().
    ///
    /// The constructor receives the exact path and flags so one Unit can
    /// safely expose multiple resources without collapsing them into the
    /// first factory in the manifest.
    path_map: HashMap<String, RegisteredResource>,
    /// fd → virtual descriptor. Duplicates share one open-file description.
    open_fds: HashMap<i64, VirtualDescriptor>,
    /// Monotonic next-fd counter.
    next_fd: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct VirtualFdHandoff {
    schema_version: u32,
    scope: HandoffScope,
    descriptions: Vec<VirtualDescriptionHandoff>,
    descriptors: Vec<VirtualDescriptorHandoff>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum HandoffScope {
    NonCloexecOpenFileDescriptions,
}

#[derive(Debug, Serialize, Deserialize)]
struct VirtualDescriptionHandoff {
    id: u32,
    path: String,
    resource_id: String,
    implementation: String,
    status_flags: i64,
    state: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct VirtualDescriptorHandoff {
    fd: i64,
    description_id: u32,
    close_on_exec: bool,
}

impl VirtualFdTable {
    pub fn new() -> Self {
        Self {
            path_map: HashMap::new(),
            open_fds: HashMap::new(),
            next_fd: VFD_BASE,
        }
    }

    pub fn register_path(&mut self, path: &str, factory: fn() -> Box<dyn PseudoFile>) {
        // This convenience method remains useful for runtime unit tests and
        // simple callers.  Manifest-backed registrations use the path-aware
        // method below.
        let previous = self.path_map.insert(
            path.to_string(),
            RegisteredResource {
                id: path.to_owned(),
                implementation: "legacy".to_owned(),
                factory: PathFactory::Legacy(factory),
            },
        );
        assert!(previous.is_none(), "duplicate pseudo-file path: {path}");
    }

    pub fn register_path_with_factory(&mut self, path: &str, factory: PseudoFileFactory) {
        self.register_resource(path, "path-aware", path, factory);
    }

    /// Manifest identity is independent of the exact path used to open an OFD.
    /// Several paths may belong to one resource, but an exec restore must bind
    /// to the same resource and implementation, not merely a matching path.
    pub fn register_resource(
        &mut self,
        id: &str,
        implementation: &str,
        path: &str,
        factory: PseudoFileFactory,
    ) {
        let previous = self.path_map.insert(
            path.to_string(),
            RegisteredResource {
                id: id.to_owned(),
                implementation: implementation.to_owned(),
                factory: PathFactory::PathAware(factory),
            },
        );
        assert!(previous.is_none(), "duplicate pseudo-file path: {path}");
    }

    pub fn path_is_registered(&self, path: &str) -> bool {
        self.path_map.contains_key(path)
    }

    pub fn open(&mut self, path: &str, flags: i64) -> Option<i64> {
        self.open_result(path, flags).ok().flatten()
    }

    fn open_result(&mut self, path: &str, flags: i64) -> Result<Option<i64>, Errno> {
        let Some(description) = self.construct_description(path, flags, None)? else {
            return Ok(None);
        };
        let fd = self.allocate_vfd_at_least(VFD_BASE);
        self.open_fds.insert(
            fd,
            VirtualDescriptor {
                description,
                close_on_exec: flags & O_CLOEXEC != 0,
            },
        );
        Ok(Some(fd))
    }

    fn construct_description(
        &self,
        path: &str,
        flags: i64,
        restore_state: Option<&[u8]>,
    ) -> Result<Option<Arc<Mutex<OpenFileDescription>>>, Errno> {
        let Some(resource) = self.path_map.get(path) else {
            return Ok(None);
        };
        let file = match &resource.factory {
            PathFactory::Legacy(factory) => factory(),
            PathFactory::PathAware(factory) => match factory(path, flags) {
                PseudoFileOpen::Handled(file) => file,
                PseudoFileOpen::NativeFallback => return Ok(None),
                PseudoFileOpen::GuestError(error) => return Err(error),
            },
        };
        let description = Arc::new(Mutex::new(OpenFileDescription {
            file,
            path: path.to_owned(),
            resource_id: resource.id.clone(),
            implementation: resource.implementation.clone(),
            status_flags: flags & !O_CLOEXEC,
        }));
        if let Some(state) = restore_state {
            let result = description
                .lock()
                .expect("pseudo-file mutex poisoned")
                .file
                .exec_restore(state);
            if let Err(error) = result {
                return Err(error);
            }
        }
        Ok(Some(description))
    }

    /// Write the non-`CLOEXEC` virtual descriptor set to a mode-0600 file.
    ///
    /// The file is deliberately a Runtime-private implementation detail.  A
    /// pseudo-file must opt in through `exec_snapshot`; arbitrary trait
    /// objects are otherwise not safely reconstructible after host `execve`.
    pub(crate) fn prepare_exec_handoff(&mut self, path: &Path) -> Result<bool, String> {
        let mut descriptors = self
            .open_fds
            .iter()
            .filter(|(_, descriptor)| !descriptor.close_on_exec)
            .map(|(fd, descriptor)| (*fd, descriptor.clone()))
            .collect::<Vec<_>>();
        descriptors.sort_by_key(|(fd, _)| *fd);
        if descriptors.is_empty() {
            return Ok(false);
        }

        let mut descriptions = Vec::new();
        let mut description_ids = HashMap::<usize, u32>::new();
        let mut descriptor_records = Vec::with_capacity(descriptors.len());
        for (fd, descriptor) in descriptors {
            let identity = Arc::as_ptr(&descriptor.description) as usize;
            let description_id = if let Some(id) = description_ids.get(&identity) {
                *id
            } else {
                let mut open_description = descriptor
                    .description
                    .lock()
                    .map_err(|_| "pseudo-file mutex poisoned during exec handoff".to_owned())?;
                let state = open_description
                    .file
                    .exec_snapshot()
                    .map_err(|error| {
                        format!("{} snapshot failed with {error:?}", open_description.path)
                    })?
                    .ok_or_else(|| {
                        format!(
                            "virtual fd {fd} ({}) has no exec handoff snapshot",
                            open_description.path
                        )
                    })?;
                let id = descriptions.len() as u32;
                descriptions.push(VirtualDescriptionHandoff {
                    id,
                    path: open_description.path.clone(),
                    resource_id: open_description.resource_id.clone(),
                    implementation: open_description.implementation.clone(),
                    status_flags: open_description.status_flags,
                    state,
                });
                description_ids.insert(identity, id);
                id
            };
            descriptor_records.push(VirtualDescriptorHandoff {
                fd,
                description_id,
                close_on_exec: false,
            });
        }

        let handoff = VirtualFdHandoff {
            schema_version: VFD_HANDOFF_SCHEMA_VERSION,
            scope: HandoffScope::NonCloexecOpenFileDescriptions,
            descriptions,
            descriptors: descriptor_records,
        };
        let encoded = serde_json::to_vec_pretty(&handoff)
            .map_err(|error| format!("encode virtual fd handoff: {error}"))?;
        write_handoff_atomic(path, &encoded)?;
        Ok(true)
    }

    /// Restore a handoff created by `prepare_exec_handoff` before guest code
    /// starts.  The mode-0600 source remains after a successful decode so the
    /// transition record points to an auditable copy of the exact state that
    /// crossed the host `execve` boundary.
    pub(crate) fn restore_exec_handoff(&mut self, path: &Path) -> Result<usize, String> {
        let bytes = std::fs::read(path)
            .map_err(|error| format!("read virtual fd handoff {}: {error}", path.display()))?;
        #[derive(Deserialize)]
        struct Version {
            schema_version: u32,
        }
        let version: Version = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode virtual fd handoff {}: {error}", path.display()))?;
        if version.schema_version != VFD_HANDOFF_SCHEMA_VERSION {
            return Err(format!(
                "unsupported virtual fd handoff schema {} (expected {})",
                version.schema_version, VFD_HANDOFF_SCHEMA_VERSION
            ));
        }
        let handoff: VirtualFdHandoff = serde_json::from_slice(&bytes)
            .map_err(|error| format!("decode virtual fd handoff {}: {error}", path.display()))?;

        let mut descriptions = HashMap::<u32, Arc<Mutex<OpenFileDescription>>>::new();
        for record in &handoff.descriptions {
            if descriptions.contains_key(&record.id) {
                return Err(format!("duplicate virtual OFD id {}", record.id));
            }
            let resource = self.path_map.get(&record.path).ok_or_else(|| {
                format!(
                    "virtual OFD {} resource {:?} path {:?} is not registered in child",
                    record.id, record.resource_id, record.path
                )
            })?;
            if resource.id != record.resource_id || resource.implementation != record.implementation
            {
                return Err(format!(
                    "virtual OFD {} resource identity mismatch at {:?}: parent {:?}/{:?}, child {:?}/{:?}",
                    record.id, record.path, record.resource_id, record.implementation,
                    resource.id, resource.implementation
                ));
            }
            let Some(description) = self
                .construct_description(&record.path, record.status_flags, Some(&record.state))
                .map_err(|error| {
                    format!(
                        "restore virtual OFD {} ({}) failed with {error:?}",
                        record.id, record.path
                    )
                })?
            else {
                return Err(format!(
                    "restore virtual OFD {} path {} was not handled by the child manifest",
                    record.id, record.path
                ));
            };
            descriptions.insert(record.id, description);
        }

        // Validate the complete descriptor set before publishing any of it.
        let mut pending = HashMap::new();
        let mut next_fd = self.next_fd;
        for record in &handoff.descriptors {
            if record.fd < 0
                || record.fd >= i32::MAX as i64
                || record.close_on_exec
                || self.open_fds.contains_key(&record.fd)
                || pending.contains_key(&record.fd)
            {
                return Err(format!("cannot restore virtual fd {}", record.fd));
            }
            let description = descriptions.get(&record.description_id).ok_or_else(|| {
                format!(
                    "virtual fd {} refers to missing OFD {}",
                    record.fd, record.description_id
                )
            })?;
            pending.insert(
                record.fd,
                VirtualDescriptor {
                    description: description.clone(),
                    close_on_exec: record.close_on_exec,
                },
            );
            next_fd = next_fd.max(record.fd + 1);
        }
        let restored = pending.len();
        self.open_fds.extend(pending);
        self.next_fd = next_fd;
        Ok(restored)
    }

    pub fn is_virtual(&self, fd: i64) -> bool {
        self.open_fds.contains_key(&fd)
    }

    fn allocate_vfd_at_least(&mut self, minimum: i64) -> i64 {
        let mut candidate = self.next_fd.max(minimum).max(VFD_BASE);
        while self.open_fds.contains_key(&candidate) {
            candidate += 1;
        }
        self.next_fd = candidate + 1;
        candidate
    }

    fn duplicate_at_least(
        &mut self,
        fd: i64,
        minimum: i64,
        close_on_exec: bool,
    ) -> Result<i64, Errno> {
        if minimum < 0 {
            return Err(Errno::EINVAL);
        }
        let source = self.open_fds.get(&fd).cloned().ok_or(Errno::EBADF)?;
        let new_fd = self.allocate_vfd_at_least(minimum);
        self.open_fds.insert(
            new_fd,
            VirtualDescriptor {
                description: source.description,
                close_on_exec,
            },
        );
        Ok(new_fd)
    }

    fn duplicate_exact(&mut self, fd: i64, new_fd: i64, close_on_exec: bool) -> Result<i64, Errno> {
        if new_fd < 0 {
            return Err(Errno::EBADF);
        }
        let source = self.open_fds.get(&fd).cloned().ok_or(Errno::EBADF)?;
        if fd == new_fd {
            return Ok(new_fd);
        }
        let _ = self.close_descriptor(new_fd);
        self.open_fds.insert(
            new_fd,
            VirtualDescriptor {
                description: source.description,
                close_on_exec,
            },
        );
        Ok(new_fd)
    }

    fn close_descriptor(&mut self, fd: i64) -> Result<(), Errno> {
        let descriptor = self.open_fds.remove(&fd).ok_or(Errno::EBADF)?;
        if Arc::strong_count(&descriptor.description) == 1 {
            descriptor
                .description
                .lock()
                .expect("pseudo-file mutex poisoned")
                .file
                .close()?;
        }
        Ok(())
    }

    /// Drop descriptors marked close-on-exec. The syscall integration invokes
    /// this only at a confirmed successful exec boundary.
    pub fn close_on_exec(&mut self) {
        let fds = self
            .open_fds
            .iter()
            .filter_map(|(fd, entry)| entry.close_on_exec.then_some(*fd))
            .collect::<Vec<_>>();
        for fd in fds {
            let _ = self.close_descriptor(fd);
        }
    }

    /// Dispatch an incoming syscall through the VFS. For OPEN/OPENAT with a
    /// registered path, we allocate a new vfd. For other fd-indexed syscalls,
    /// if the fd is virtual we route to its PseudoFile; otherwise we return
    /// `NativeFallback` so the native guest path handles it.
    pub fn dispatch_syscall(
        &mut self,
        syscall_num: i32,
        a0: GuestReg,
        a1: GuestReg,
        a2: GuestReg,
        _a3: GuestReg,
        ctx: &mut dyn IIBContextOps,
    ) -> VfsResult {
        match syscall_num {
            syscall_no::OPEN => {
                let path_addr = a0 as GuestAddr;
                let path = match ctx.read_cstr(path_addr, 4096) {
                    Ok(p) => p,
                    Err(_) => return VfsResult::NativeFallback,
                };
                let path_str = match path.to_str() {
                    Ok(s) => s,
                    Err(_) => return VfsResult::NativeFallback,
                };
                if !self.path_is_registered(path_str) {
                    return VfsResult::NativeFallback;
                }
                match self.open_result(path_str, guest_reg_as_i64(a1)) {
                    Ok(Some(fd)) => VfsResult::Handled(fd as GuestReg),
                    Ok(None) => VfsResult::NativeFallback,
                    Err(error) => VfsResult::GuestError(error),
                }
            }

            syscall_no::OPENAT => {
                // dirfd = a0, path = a1, flags = a2. For our purposes we only
                // intercept absolute paths; relative paths go to host.
                let path_addr = a1 as GuestAddr;
                let path = match ctx.read_cstr(path_addr, 4096) {
                    Ok(p) => p,
                    Err(_) => return VfsResult::NativeFallback,
                };
                let path_str = match path.to_str() {
                    Ok(s) => s,
                    Err(_) => return VfsResult::NativeFallback,
                };
                if !path_str.starts_with('/') || !self.path_is_registered(path_str) {
                    return VfsResult::NativeFallback;
                }
                match self.open_result(path_str, guest_reg_as_i64(a2)) {
                    Ok(Some(fd)) => VfsResult::Handled(fd as GuestReg),
                    Ok(None) => VfsResult::NativeFallback,
                    Err(error) => VfsResult::GuestError(error),
                }
            }

            syscall_no::READ => {
                let fd = guest_reg_as_i64(a0);
                if !self.is_virtual(fd) {
                    return VfsResult::NativeFallback;
                }
                let buf = a1 as GuestAddr;
                let len = a2 as usize;
                let descriptor = self
                    .open_fds
                    .get(&fd)
                    .expect("vfd missing after is_virtual check");
                let r = descriptor
                    .description
                    .lock()
                    .expect("pseudo-file mutex poisoned")
                    .file
                    .read(buf, len, ctx);
                result_from_errno_or_value(r.map(|n| n as i64))
            }

            syscall_no::WRITE => {
                let fd = guest_reg_as_i64(a0);
                if !self.is_virtual(fd) {
                    return VfsResult::NativeFallback;
                }
                let buf = a1 as GuestAddr;
                let len = a2 as usize;
                let descriptor = self
                    .open_fds
                    .get(&fd)
                    .expect("vfd missing after is_virtual check");
                let r = descriptor
                    .description
                    .lock()
                    .expect("pseudo-file mutex poisoned")
                    .file
                    .write(buf, len, ctx);
                result_from_errno_or_value(r.map(|n| n as i64))
            }

            syscall_no::FSTAT => {
                let fd = guest_reg_as_i64(a0);
                if !self.is_virtual(fd) {
                    return VfsResult::NativeFallback;
                }
                let stat_buf = a1 as GuestAddr;
                let descriptor = self
                    .open_fds
                    .get(&fd)
                    .expect("vfd missing after is_virtual check");
                let r = descriptor
                    .description
                    .lock()
                    .expect("pseudo-file mutex poisoned")
                    .file
                    .fstat(stat_buf, ctx);
                result_from_errno_or_value(r.map(|_| 0))
            }

            syscall_no::CLOSE => {
                let fd = guest_reg_as_i64(a0);
                if !self.is_virtual(fd) {
                    return VfsResult::NativeFallback;
                }
                result_from_errno_or_value(self.close_descriptor(fd).map(|_| 0))
            }

            syscall_no::IOCTL => {
                let fd = guest_reg_as_i64(a0);
                if !self.is_virtual(fd) {
                    return VfsResult::NativeFallback;
                }
                let cmd = a1 as u32;
                let arg = a2 as GuestAddr;
                let descriptor = self
                    .open_fds
                    .get(&fd)
                    .expect("vfd missing after is_virtual check");
                let r = descriptor
                    .description
                    .lock()
                    .expect("pseudo-file mutex poisoned")
                    .file
                    .ioctl(cmd, arg, ctx);
                result_from_errno_or_value(r)
            }

            syscall_no::LSEEK => {
                let fd = guest_reg_as_i64(a0);
                if !self.is_virtual(fd) {
                    return VfsResult::NativeFallback;
                }
                let off = a1 as i64;
                let whence = a2 as i32;
                let descriptor = self
                    .open_fds
                    .get(&fd)
                    .expect("vfd missing after is_virtual check");
                let r = descriptor
                    .description
                    .lock()
                    .expect("pseudo-file mutex poisoned")
                    .file
                    .lseek(off, whence);
                result_from_errno_or_value(r)
            }

            syscall_no::FSYNC => {
                let fd = guest_reg_as_i64(a0);
                if !self.is_virtual(fd) {
                    return VfsResult::NativeFallback;
                }
                let descriptor = self
                    .open_fds
                    .get(&fd)
                    .expect("vfd missing after is_virtual check");
                let r = descriptor
                    .description
                    .lock()
                    .expect("pseudo-file mutex poisoned")
                    .file
                    .fsync();
                result_from_errno_or_value(r.map(|_| 0))
            }

            syscall_no::DUP => {
                let fd = guest_reg_as_i64(a0);
                if !self.is_virtual(fd) {
                    return VfsResult::NativeFallback;
                }
                result_from_errno_or_value(self.duplicate_at_least(fd, 0, false))
            }

            syscall_no::DUP2 => {
                let fd = guest_reg_as_i64(a0);
                if !self.is_virtual(fd) {
                    return VfsResult::NativeFallback;
                }
                let new_fd = guest_reg_as_i64(a1);
                result_from_errno_or_value(self.duplicate_exact(fd, new_fd, false))
            }

            syscall_no::DUP3 => {
                let fd = guest_reg_as_i64(a0);
                if !self.is_virtual(fd) {
                    return VfsResult::NativeFallback;
                }
                let new_fd = guest_reg_as_i64(a1);
                let flags = guest_reg_as_i64(a2);
                let result = if fd == new_fd {
                    Err(Errno::EINVAL)
                } else if flags & !O_CLOEXEC != 0 {
                    Err(Errno::EINVAL)
                } else {
                    self.duplicate_exact(fd, new_fd, flags & O_CLOEXEC != 0)
                };
                result_from_errno_or_value(result)
            }

            n if n == syscall_no::FCNTL || n == syscall_no::FCNTL64 => {
                let fd = guest_reg_as_i64(a0);
                if !self.is_virtual(fd) {
                    return VfsResult::NativeFallback;
                }
                let command = guest_reg_as_i64(a1);
                let argument = guest_reg_as_i64(a2);
                let result = match command {
                    fcntl_cmd::DUPFD => self.duplicate_at_least(fd, argument, false),
                    fcntl_cmd::DUPFD_CLOEXEC => self.duplicate_at_least(fd, argument, true),
                    fcntl_cmd::GETFD => self
                        .open_fds
                        .get(&fd)
                        .map(|entry| if entry.close_on_exec { FD_CLOEXEC } else { 0 })
                        .ok_or(Errno::EBADF),
                    fcntl_cmd::SETFD => self
                        .open_fds
                        .get_mut(&fd)
                        .map(|entry| {
                            entry.close_on_exec = argument & FD_CLOEXEC != 0;
                            0
                        })
                        .ok_or(Errno::EBADF),
                    fcntl_cmd::GETFL => self
                        .open_fds
                        .get(&fd)
                        .map(|entry| {
                            entry
                                .description
                                .lock()
                                .expect("pseudo-file mutex poisoned")
                                .status_flags
                        })
                        .ok_or(Errno::EBADF),
                    fcntl_cmd::SETFL => self
                        .open_fds
                        .get(&fd)
                        .map(|entry| {
                            let mut description = entry
                                .description
                                .lock()
                                .expect("pseudo-file mutex poisoned");
                            description.status_flags =
                                (description.status_flags & O_ACCMODE) | (argument & !O_ACCMODE);
                            0
                        })
                        .ok_or(Errno::EBADF),
                    _ => Err(Errno::EINVAL),
                };
                result_from_errno_or_value(result)
            }

            _ => VfsResult::NativeFallback,
        }
    }
}

fn guest_reg_as_i64(value: GuestReg) -> i64 {
    #[cfg(feature = "x86_64")]
    return value as i64;
    #[cfg(not(feature = "x86_64"))]
    return (value as u32 as i32) as i64;
}

fn result_from_errno_or_value(r: Result<i64, Errno>) -> VfsResult {
    match r {
        Ok(value) => VfsResult::Handled(value as GuestReg),
        Err(error) => VfsResult::GuestError(error),
    }
}

fn write_handoff_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("virtual fd handoff has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create virtual fd handoff directory: {error}"))?;
    let temporary = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("handoff"),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("create virtual fd handoff: {error}"))?;
    file.write_all(bytes)
        .map_err(|error| format!("write virtual fd handoff: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync virtual fd handoff: {error}"))?;
    drop(file);
    std::fs::rename(&temporary, path)
        .map_err(|error| format!("publish virtual fd handoff: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fmst_iib_api::types::{Errno, GuestAddr};

    #[test]
    fn semantic_errors_use_the_target_linux_syscall_abi() {
        let expected = if cfg!(any(feature = "mips", feature = "mipsbe")) {
            [-78, -89, -79]
        } else {
            [-36, -38, -75]
        };
        assert_eq!(
            [Errno::ENAMETOOLONG, Errno::ENOSYS, Errno::EOVERFLOW].map(guest_errno_result),
            expected
        );
        assert_eq!(guest_errno_result(Errno::EBADF), -9);
    }

    struct StubDev {
        ioctl_calls: std::cell::Cell<u32>,
    }

    impl PseudoFile for StubDev {
        fn fstat(
            &mut self,
            stat_buf: GuestAddr,
            ctx: &mut dyn fmst_iib_api::context::IIBContextOps,
        ) -> Result<(), Errno> {
            ctx.write_mem(stat_buf, &[0x53, 0x54, 0x41, 0x54])
        }

        fn ioctl(
            &mut self,
            _cmd: u32,
            _arg: GuestAddr,
            _ctx: &mut dyn fmst_iib_api::context::IIBContextOps,
        ) -> Result<i64, Errno> {
            self.ioctl_calls.set(self.ioctl_calls.get() + 1);
            Ok(0)
        }
        fn name(&self) -> &str {
            "stub"
        }
    }

    fn make_stub() -> Box<dyn PseudoFile> {
        Box::new(StubDev {
            ioctl_calls: std::cell::Cell::new(0),
        })
    }

    fn make_unimplemented() -> Box<dyn PseudoFile> {
        struct Unimplemented;
        impl PseudoFile for Unimplemented {}
        Box::new(Unimplemented)
    }

    #[test]
    fn open_allocates_vfd_above_base() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let fd = t.open("/dev/stub", 0).unwrap();
        assert!(fd >= VFD_BASE);
        assert!(t.is_virtual(fd));
    }

    #[test]
    fn unknown_path_returns_none() {
        let mut t = VirtualFdTable::new();
        assert!(t.open("/dev/missing", 0).is_none());
    }

    #[test]
    fn close_descriptor_removes_fd() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let fd = t.open("/dev/stub", 0).unwrap();
        assert!(t.is_virtual(fd));
        t.close_descriptor(fd).unwrap();
        assert!(!t.is_virtual(fd));
    }

    #[test]
    fn multiple_opens_get_distinct_fds() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let a = t.open("/dev/stub", 0).unwrap();
        let b = t.open("/dev/stub", 0).unwrap();
        assert_ne!(a, b);
    }

    struct TaggedFile {
        tag: &'static str,
    }

    impl PseudoFile for TaggedFile {
        fn name(&self) -> &str {
            self.tag
        }
    }

    fn partition_factory(path: &str, flags: i64) -> PseudoFileOpen {
        assert_eq!(flags, 0x2, "the VFS must pass open flags to the factory");
        let tag = match path {
            "/dev/mtd2" => "mtd2",
            "/dev/mtd3" => "mtd3",
            _ => return PseudoFileOpen::NativeFallback,
        };
        PseudoFileOpen::Handled(Box::new(TaggedFile { tag }))
    }

    fn read_only_fallback_factory(_path: &str, flags: i64) -> PseudoFileOpen {
        if flags & O_ACCMODE != 0 {
            PseudoFileOpen::Handled(Box::new(TaggedFile { tag: "virtual" }))
        } else {
            PseudoFileOpen::NativeFallback
        }
    }

    #[test]
    fn path_aware_factory_keeps_exact_paths_distinct() {
        let mut t = VirtualFdTable::new();
        t.register_path_with_factory("/dev/mtd2", partition_factory);
        t.register_path_with_factory("/dev/mtd3", partition_factory);

        let mtd2 = t.open("/dev/mtd2", 0x2).unwrap();
        let mtd3 = t.open("/dev/mtd3", 0x2).unwrap();
        let name2 = t
            .open_fds
            .get(&mtd2)
            .unwrap()
            .description
            .lock()
            .unwrap()
            .file
            .name()
            .to_string();
        let name3 = t
            .open_fds
            .get(&mtd3)
            .unwrap()
            .description
            .lock()
            .unwrap()
            .file
            .name()
            .to_string();
        assert_eq!(name2, "mtd2");
        assert_eq!(name3, "mtd3");
    }

    /// Mock context that stores guest memory in a HashMap and lets tests
    /// pre-populate c-string paths for OPEN / OPENAT dispatch tests.
    struct MockCtx {
        mem: std::cell::RefCell<std::collections::HashMap<GuestAddr, u8>>,
    }

    impl MockCtx {
        fn new() -> Self {
            Self {
                mem: std::cell::RefCell::new(std::collections::HashMap::new()),
            }
        }
        fn write_cstr(&self, addr: GuestAddr, s: &str) {
            let mut m = self.mem.borrow_mut();
            for (i, b) in s.as_bytes().iter().enumerate() {
                m.insert(addr + i as GuestAddr, *b);
            }
            m.insert(addr + s.len() as GuestAddr, 0);
        }
    }

    impl fmst_iib_api::context::IIBContextOps for MockCtx {
        fn read_arg(&self, _idx: u8) -> Result<fmst_iib_api::types::GuestReg, Errno> {
            Err(Errno::ENOSYS)
        }
        fn write_arg(&self, _idx: u8, _val: fmst_iib_api::types::GuestReg) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn set_return_value(&self, _val: fmst_iib_api::types::GuestReg) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn read_reg(&self, _name: &str) -> Result<fmst_iib_api::types::GuestReg, Errno> {
            Err(Errno::ENOSYS)
        }
        fn write_reg(&self, _name: &str, _val: fmst_iib_api::types::GuestReg) -> Result<(), Errno> {
            Err(Errno::ENOSYS)
        }
        fn current_pc(&self) -> GuestAddr {
            0
        }
        fn return_address(&self) -> Result<GuestAddr, Errno> {
            Err(Errno::ENOSYS)
        }
        fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Errno> {
            let m = self.mem.borrow();
            for (i, slot) in buf.iter_mut().enumerate() {
                *slot = *m.get(&(addr + i as GuestAddr)).ok_or(Errno::EFAULT)?;
            }
            Ok(())
        }
        fn write_mem(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), Errno> {
            let mut m = self.mem.borrow_mut();
            for (i, b) in buf.iter().enumerate() {
                m.insert(addr + i as GuestAddr, *b);
            }
            Ok(())
        }
        fn state(&self) -> &(dyn std::any::Any + Send + Sync) {
            static PLACEHOLDER: () = ();
            &PLACEHOLDER
        }
        fn native_call(
            &mut self,
            _target: GuestAddr,
            _args: &[fmst_iib_api::types::GuestReg],
        ) -> Result<fmst_iib_api::types::GuestReg, fmst_iib_api::iib_error::IibError> {
            Err(fmst_iib_api::iib_error::IibError::Errno(Errno::ENOSYS))
        }
    }

    #[test]
    fn dispatch_open_registered_path_handled() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let mut ctx = MockCtx::new();
        ctx.write_cstr(0x1000, "/dev/stub");
        let res = t.dispatch_syscall(syscall_no::OPEN, 0x1000, 0, 0, 0, &mut ctx);
        match res {
            VfsResult::Handled(fd) => {
                assert!(fd as i64 >= VFD_BASE);
            }
            VfsResult::GuestError(error) => panic!("unexpected guest error: {error:?}"),
            VfsResult::NativeFallback => panic!("expected Handled"),
        }
    }

    #[test]
    fn path_aware_enoent_falls_back_to_native_open() {
        let mut t = VirtualFdTable::new();
        t.register_path_with_factory("/dev/mtd2", read_only_fallback_factory);
        let mut ctx = MockCtx::new();
        ctx.write_cstr(0x1000, "/dev/mtd2");

        let result = t.dispatch_syscall(syscall_no::OPEN, 0x1000, 0, 0, 0, &mut ctx);
        assert!(matches!(result, VfsResult::NativeFallback));

        let result = t.dispatch_syscall(
            syscall_no::OPEN,
            0x1000,
            O_ACCMODE as GuestReg,
            0,
            0,
            &mut ctx,
        );
        assert!(matches!(result, VfsResult::Handled(_)));
    }

    #[test]
    fn dispatch_open_unregistered_path_passthrough() {
        let mut t = VirtualFdTable::new();
        let mut ctx = MockCtx::new();
        ctx.write_cstr(0x1000, "/etc/passwd");
        let res = t.dispatch_syscall(syscall_no::OPEN, 0x1000, 0, 0, 0, &mut ctx);
        assert!(matches!(res, VfsResult::NativeFallback));
    }

    #[test]
    fn dispatch_read_on_real_fd_passthrough() {
        let mut t = VirtualFdTable::new();
        let mut ctx = MockCtx::new();
        // fd=3 is a real fd (well below VFD_BASE).
        let res = t.dispatch_syscall(syscall_no::READ, 3, 0x2000, 16, 0, &mut ctx);
        assert!(matches!(res, VfsResult::NativeFallback));
    }

    #[test]
    fn dispatch_ioctl_on_virtual_fd_goes_to_pseudo_file() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let fd = t.open("/dev/stub", 0).unwrap();
        let mut ctx = MockCtx::new();
        let res = t.dispatch_syscall(syscall_no::IOCTL, fd as GuestReg, 0x1234, 0, 0, &mut ctx);
        match res {
            VfsResult::Handled(v) => assert_eq!(v, 0),
            VfsResult::GuestError(error) => panic!("unexpected guest error: {error:?}"),
            VfsResult::NativeFallback => panic!("expected Handled"),
        }
    }

    #[test]
    fn dispatch_fstat_on_virtual_fd_writes_guest_stat_buffer() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let fd = t.open("/dev/stub", 0).unwrap();
        let mut ctx = MockCtx::new();
        let result = t.dispatch_syscall(syscall_no::FSTAT, fd as GuestReg, 0x2200, 0, 0, &mut ctx);
        assert!(matches!(result, VfsResult::Handled(0)));
        let mut stat = [0_u8; 4];
        ctx.read_mem(0x2200, &mut stat).unwrap();
        assert_eq!(&stat, b"STAT");
    }

    #[test]
    fn unsupported_operation_on_virtual_fd_is_guest_error() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/unimplemented", make_unimplemented);
        let fd = t.open("/dev/unimplemented", 0).unwrap();
        let mut ctx = MockCtx::new();
        let result = t.dispatch_syscall(syscall_no::IOCTL, fd as GuestReg, 0xfeed, 0, 0, &mut ctx);
        assert!(matches!(result, VfsResult::GuestError(Errno::ENOSYS)));
    }

    #[test]
    fn dispatch_close_on_virtual_fd_releases() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let fd = t.open("/dev/stub", 0).unwrap();
        assert!(t.is_virtual(fd));
        let mut ctx = MockCtx::new();
        let res = t.dispatch_syscall(syscall_no::CLOSE, fd as GuestReg, 0, 0, 0, &mut ctx);
        assert!(matches!(res, VfsResult::Handled(0)));
        assert!(!t.is_virtual(fd));
    }

    #[test]
    fn dispatch_openat_relative_path_passthrough() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let mut ctx = MockCtx::new();
        ctx.write_cstr(0x1000, "dev/stub"); // relative
        let res = t.dispatch_syscall(syscall_no::OPENAT, 0, 0x1000, 0, 0, &mut ctx);
        assert!(matches!(res, VfsResult::NativeFallback));
    }

    fn handled_value(result: VfsResult) -> i64 {
        match result {
            VfsResult::Handled(value) => guest_reg_as_i64(value),
            VfsResult::GuestError(error) => error.as_neg_i64(),
            VfsResult::NativeFallback => panic!("expected Handled"),
        }
    }

    #[test]
    fn dup_shares_open_file_description_and_clears_cloexec() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let fd = t.open("/dev/stub", O_CLOEXEC).unwrap();
        let source = t.open_fds[&fd].description.clone();
        let mut ctx = MockCtx::new();

        let duplicate =
            handled_value(t.dispatch_syscall(syscall_no::DUP, fd as GuestReg, 0, 0, 0, &mut ctx));

        assert_ne!(duplicate, fd);
        assert!(Arc::ptr_eq(&source, &t.open_fds[&duplicate].description));
        assert!(!t.open_fds[&duplicate].close_on_exec);
        assert!(t.open_fds[&fd].close_on_exec);
    }

    #[test]
    fn dup2_routes_the_requested_low_descriptor() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let fd = t.open("/dev/stub", O_CLOEXEC).unwrap();
        let mut ctx = MockCtx::new();

        let duplicate =
            handled_value(t.dispatch_syscall(syscall_no::DUP2, fd as GuestReg, 2, 0, 0, &mut ctx));

        assert_eq!(duplicate, 2);
        assert!(t.is_virtual(2));
        assert!(!t.open_fds[&2].close_on_exec);
    }

    #[test]
    fn dup3_rejects_same_fd_and_tracks_cloexec() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let fd = t.open("/dev/stub", 0).unwrap();
        let mut ctx = MockCtx::new();

        let same = handled_value(t.dispatch_syscall(
            syscall_no::DUP3,
            fd as GuestReg,
            fd as GuestReg,
            0,
            0,
            &mut ctx,
        ));
        assert_eq!(same, Errno::EINVAL.as_neg_i64());

        let duplicate = handled_value(t.dispatch_syscall(
            syscall_no::DUP3,
            fd as GuestReg,
            9,
            O_CLOEXEC as GuestReg,
            0,
            &mut ctx,
        ));
        assert_eq!(duplicate, 9);
        assert!(t.open_fds[&9].close_on_exec);
    }

    #[test]
    fn fcntl_descriptor_and_status_flags_follow_linux_ownership() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let fd = t.open("/dev/stub", 2 | O_CLOEXEC).unwrap();
        let mut ctx = MockCtx::new();

        assert_eq!(
            handled_value(t.dispatch_syscall(
                syscall_no::FCNTL,
                fd as GuestReg,
                fcntl_cmd::GETFD as GuestReg,
                0,
                0,
                &mut ctx,
            )),
            FD_CLOEXEC,
        );
        assert_eq!(
            handled_value(t.dispatch_syscall(
                syscall_no::FCNTL,
                fd as GuestReg,
                fcntl_cmd::GETFL as GuestReg,
                0,
                0,
                &mut ctx,
            )),
            2,
        );
        assert_eq!(
            handled_value(t.dispatch_syscall(
                syscall_no::FCNTL,
                fd as GuestReg,
                fcntl_cmd::SETFD as GuestReg,
                0,
                0,
                &mut ctx,
            )),
            0,
        );
        assert!(!t.open_fds[&fd].close_on_exec);

        let duplicate = handled_value(t.dispatch_syscall(
            syscall_no::FCNTL,
            fd as GuestReg,
            fcntl_cmd::DUPFD_CLOEXEC as GuestReg,
            20,
            0,
            &mut ctx,
        ));
        assert!(duplicate >= VFD_BASE);
        assert!(t.open_fds[&duplicate].close_on_exec);

        assert_eq!(
            handled_value(t.dispatch_syscall(
                syscall_no::FCNTL,
                duplicate as GuestReg,
                fcntl_cmd::SETFL as GuestReg,
                0x1234,
                0,
                &mut ctx,
            )),
            0,
        );
        assert_eq!(
            handled_value(t.dispatch_syscall(
                syscall_no::FCNTL,
                fd as GuestReg,
                fcntl_cmd::GETFL as GuestReg,
                0,
                0,
                &mut ctx,
            )),
            0x1236,
        );
    }

    #[test]
    fn close_on_exec_only_drops_marked_descriptors() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let retained = t.open("/dev/stub", 0).unwrap();
        let dropped = t.open("/dev/stub", O_CLOEXEC).unwrap();

        t.close_on_exec();

        assert!(t.is_virtual(retained));
        assert!(!t.is_virtual(dropped));
    }

    struct HandoffFile {
        value: u8,
    }

    impl PseudoFile for HandoffFile {
        fn exec_snapshot(&mut self) -> Result<Option<Vec<u8>>, Errno> {
            self.value = 42;
            Ok(Some(vec![self.value]))
        }

        fn exec_restore(&mut self, state: &[u8]) -> Result<(), Errno> {
            let [value] = state else {
                return Err(Errno::EINVAL);
            };
            self.value = *value;
            Ok(())
        }

        fn tell(&mut self) -> Result<i64, Errno> {
            Ok(self.value as i64)
        }
    }

    fn handoff_factory(_path: &str, _flags: i64) -> PseudoFileOpen {
        PseudoFileOpen::Handled(Box::new(HandoffFile { value: 0 }))
    }

    #[test]
    fn exec_handoff_preserves_shared_ofd_and_descriptor_flags() {
        let temporary = tempfile::tempdir().unwrap();
        let handoff_path = temporary.path().join("vfd.json");
        let mut parent = VirtualFdTable::new();
        parent.register_path_with_factory("/dev/state", handoff_factory);
        let original = parent.open("/dev/state", O_CLOEXEC | 2).unwrap();
        let mut ctx = MockCtx::new();
        let retained = handled_value(parent.dispatch_syscall(
            syscall_no::DUP2,
            original as GuestReg,
            7,
            0,
            0,
            &mut ctx,
        ));
        assert_eq!(retained, 7);
        parent.duplicate_exact(original, 8, false).unwrap();

        // The trait object is intentionally opaque; the snapshot itself is
        // the contract exercised by the handoff, so no downcast is required.
        assert!(parent.prepare_exec_handoff(&handoff_path).unwrap());
        assert!(handoff_path.exists());

        let mut child = VirtualFdTable::new();
        child.register_path_with_factory("/dev/state", handoff_factory);
        assert_eq!(child.restore_exec_handoff(&handoff_path).unwrap(), 2);
        assert!(handoff_path.exists());
        assert!(!child.is_virtual(original));
        assert!(child.is_virtual(retained));
        assert!(!child.open_fds[&retained].close_on_exec);
        assert!(Arc::ptr_eq(
            &child.open_fds[&7].description,
            &child.open_fds[&8].description
        ));
        assert_eq!(
            child.open_fds[&7]
                .description
                .lock()
                .unwrap()
                .file
                .tell()
                .unwrap(),
            42
        );
        assert_eq!(
            child.open_fds[&retained]
                .description
                .lock()
                .unwrap()
                .status_flags,
            2
        );
    }

    fn state_handoff(path: &Path) -> serde_json::Value {
        let mut parent = VirtualFdTable::new();
        parent.register_resource("shared-resource", "StateV1", "/dev/state", handoff_factory);
        let fd = parent.open("/dev/state", 2).unwrap();
        parent.duplicate_exact(fd, 7, false).unwrap();
        parent.prepare_exec_handoff(path).unwrap();
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn exec_restore_rejects_same_path_with_different_resource_or_implementation() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("handoff.json");
        state_handoff(&path);
        for (id, implementation) in [
            ("other-resource", "StateV1"),
            ("shared-resource", "StateV2"),
        ] {
            let mut child = VirtualFdTable::new();
            child.register_resource(id, implementation, "/dev/state", handoff_factory);
            assert!(child
                .restore_exec_handoff(&path)
                .unwrap_err()
                .contains("resource identity mismatch"));
            assert!(child.open_fds.is_empty());
            assert!(path.exists());
        }
    }

    #[test]
    fn exec_restore_rejects_old_schema_without_identity_or_scope() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("handoff.json");
        std::fs::write(
            &path,
            br#"{"schema_version":1,"descriptions":[],"descriptors":[]}"#,
        )
        .unwrap();
        assert!(VirtualFdTable::new()
            .restore_exec_handoff(&path)
            .unwrap_err()
            .contains("unsupported virtual fd handoff schema 1"));
    }

    #[test]
    fn invalid_handoff_never_publishes_a_partial_fd_table() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("handoff.json");
        let baseline = state_handoff(&path);
        for invalid in [
            "duplicate_fd",
            "missing_ofd",
            "cloexec",
            "fd_range",
            "bad_payload",
            "duplicate_ofd",
            "wrong_scope",
            "missing_resource",
        ] {
            let mut data = baseline.clone();
            match invalid {
                "duplicate_fd" => data["descriptors"][1] = data["descriptors"][0].clone(),
                "missing_ofd" => data["descriptors"][1]["description_id"] = 99.into(),
                "cloexec" => data["descriptors"][1]["close_on_exec"] = true.into(),
                "fd_range" => data["descriptors"][1]["fd"] = i64::MAX.into(),
                "bad_payload" => data["descriptions"][0]["state"] = serde_json::json!([]),
                "duplicate_ofd" => {
                    let duplicate = data["descriptions"][0].clone();
                    data["descriptions"].as_array_mut().unwrap().push(duplicate);
                }
                "wrong_scope" => data["scope"] = "entire_intervention_heap".into(),
                "missing_resource" => data["descriptions"][0]["path"] = "/dev/absent".into(),
                _ => unreachable!(),
            }
            std::fs::write(&path, serde_json::to_vec(&data).unwrap()).unwrap();
            let mut child = VirtualFdTable::new();
            child.register_resource("shared-resource", "StateV1", "/dev/state", handoff_factory);
            let existing = child.open("/dev/state", O_CLOEXEC).unwrap();
            // Move the pre-existing fd outside the handoff range.
            let existing_description = child.open_fds.remove(&existing).unwrap();
            child.open_fds.insert(12, existing_description);
            let next = child.next_fd;
            assert!(child.restore_exec_handoff(&path).is_err(), "{invalid}");
            assert_eq!(child.open_fds.len(), 1, "{invalid}");
            assert!(child.is_virtual(12));
            assert_eq!(child.next_fd, next);
            assert!(path.exists());
        }
    }

    #[test]
    fn exec_handoff_rejects_unserializable_virtual_ofd() {
        let temporary = tempfile::tempdir().unwrap();
        let handoff_path = temporary.path().join("vfd.json");
        let mut table = VirtualFdTable::new();
        table.register_path("/dev/opaque", make_unimplemented);
        table.open("/dev/opaque", 0).unwrap();
        let error = table.prepare_exec_handoff(&handoff_path).unwrap_err();
        assert!(error.contains("no exec handoff snapshot"));
        assert!(!handoff_path.exists());
    }

    #[test]
    fn duplicated_stdio_descriptors_survive_original_close_and_exec() {
        let mut t = VirtualFdTable::new();
        t.register_path("/dev/stub", make_stub);
        let original = t.open("/dev/stub", O_CLOEXEC).unwrap();
        let mut ctx = MockCtx::new();

        assert_eq!(
            handled_value(t.dispatch_syscall(
                syscall_no::DUP2,
                original as GuestReg,
                1,
                0,
                0,
                &mut ctx,
            )),
            1,
        );
        assert_eq!(
            handled_value(t.dispatch_syscall(
                syscall_no::DUP2,
                original as GuestReg,
                2,
                0,
                0,
                &mut ctx,
            )),
            2,
        );
        assert_eq!(
            handled_value(t.dispatch_syscall(
                syscall_no::CLOSE,
                original as GuestReg,
                0,
                0,
                0,
                &mut ctx,
            )),
            0,
        );

        t.close_on_exec();

        assert!(!t.is_virtual(original));
        assert!(t.is_virtual(1));
        assert!(t.is_virtual(2));
        assert!(Arc::ptr_eq(
            &t.open_fds[&1].description,
            &t.open_fds[&2].description,
        ));
    }

    #[test]
    fn pseudo_file_close_runs_only_after_the_last_duplicate_closes() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct CloseCounter(Arc<AtomicUsize>);
        impl PseudoFile for CloseCounter {
            fn close(&mut self) -> Result<(), Errno> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let closes = Arc::new(AtomicUsize::new(0));
        let description = Arc::new(Mutex::new(OpenFileDescription {
            file: Box::new(CloseCounter(closes.clone())),
            path: "/dev/close-counter".to_owned(),
            resource_id: "legacy:/dev/close-counter".to_owned(),
            implementation: "legacy".to_owned(),
            status_flags: 0,
        }));
        let mut t = VirtualFdTable::new();
        for fd in [10, 11] {
            t.open_fds.insert(
                fd,
                VirtualDescriptor {
                    description: description.clone(),
                    close_on_exec: false,
                },
            );
        }
        drop(description);

        t.close_descriptor(10).unwrap();
        assert_eq!(closes.load(Ordering::SeqCst), 0);
        t.close_descriptor(11).unwrap();
        assert_eq!(closes.load(Ordering::SeqCst), 1);
    }
}
