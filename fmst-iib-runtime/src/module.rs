//! IIBModule: the libafl_qemu EmulatorModule that drives IIB.
//!
//! Lifecycle (see spec §7.2):
//!   1. `post_qemu_init`: alloc stack pool + trap page + scratch page,
//!      instantiate GlobalState, register pseudo-file path -> factory
//!      mappings.
//!   2. `first_exec`: ld.so has finished loading libraries; iterate
//!      Qemu::mappings() to build `basename -> load_base`, resolve all
//!      callsite/function_stub hook addresses, register instruction hooks
//!      for each resolved PC. (Task 27.)
//!   3. `pre_syscalls`: route open/read/write/ioctl/... to VFS. (Task 28.)

use crate::dispatch::{DispatchEntry, DispatchTable, HookFn};
use crate::native_call::IibState;
use crate::stack_pool::GuestStackPool;
use crate::vfs::VirtualFdTable;
use fmst_iib_api::manifest::{
    ModuleTargetStatic, StaticGlobalState, StaticManifest, CURRENT_ABI_VERSION,
};
use fmst_iib_api::types::{Arch, GuestAddr as IibGuestAddr, HookFlavor};
use libafl_qemu::modules::{EmulatorModule, EmulatorModuleTuple};
use libafl_qemu::{
    EmulatorModules, GuestAddr as QemuGuestAddr, GuestUlong, Hook, MmapPerms, Qemu,
    SyscallHookResult,
};
use serde::Serialize;
use std::any::Any;
use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Host-side information needed to replace a guest `execve` with a fresh
/// Firmenstein harness process.  QEMU linux-user normally forwards guest
/// execve to the host kernel; a foreign guest ELF then receives ENOEXEC.  The
/// trampoline keeps the process boundary and starts the same harness again,
/// so the replacement image receives the normal IIB module and rootfs.
#[derive(Clone, Debug)]
pub struct GuestExecConfig {
    pub harness_path: PathBuf,
    pub host_loader: Option<PathBuf>,
    pub host_library_path: Option<PathBuf>,
    pub intervention_so: Option<PathBuf>,
    pub trace_output: Option<PathBuf>,
    pub rootfs: PathBuf,
    /// Original application arguments for library-managed worker re-entry.
    /// None selects the historical harness CLI protocol.
    pub worker_args: Option<Vec<OsString>>,
    pub intervention_kind: String,
    pub syscall_trace: bool,
}

#[derive(Clone, Debug, Serialize)]
struct ExecRequestRecord {
    operation: String,
    dirfd: Option<i64>,
    flags: Option<u64>,
    pathname: String,
    pathname_bytes_hex: String,
    argv: Vec<String>,
    argv_bytes_hex: Vec<String>,
    environment: Vec<String>,
    environment_bytes_hex: Vec<String>,
    cwd: String,
    string_encoding: &'static str,
}

#[derive(Clone, Copy, Debug)]
enum GuestExecOperation {
    Execve,
    Execveat { dirfd: i64, flags: u64 },
}

enum GuestExecError {
    /// The Runtime could not replace the host image, so QEMU should retain
    /// its normal native error/fallback behavior.
    Fallback(String),
    /// The guest image was valid, but a user-space virtual-fd state contract
    /// was missing. Letting QEMU execute anyway would silently drop a live
    /// descriptor, so return a visible guest error instead.
    Reject(String),
}

impl From<String> for GuestExecError {
    fn from(error: String) -> Self {
        Self::Fallback(error)
    }
}

impl GuestExecOperation {
    fn operation_name(self) -> &'static str {
        match self {
            Self::Execve => "execve",
            Self::Execveat { .. } => "execveat",
        }
    }

    fn dirfd(self) -> Option<i64> {
        match self {
            Self::Execve => None,
            Self::Execveat { dirfd, .. } => Some(dirfd),
        }
    }

    fn flags(self) -> Option<u64> {
        match self {
            Self::Execve => None,
            Self::Execveat { flags, .. } => Some(flags),
        }
    }

    fn preflight_error(self, pathname: &OsStr) -> Option<String> {
        match self {
            Self::Execve => None,
            Self::Execveat { dirfd, flags }
                if flags & !(AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW) != 0
                    || (flags & AT_EMPTY_PATH != 0
                        && pathname.as_bytes().is_empty()
                        && dirfd == AT_FDCWD) =>
            {
                Some(format!(
                    "execveat dirfd {dirfd} flags {flags:#x} are unsupported; only AT_EMPTY_PATH and AT_SYMLINK_NOFOLLOW are currently portable"
                ))
            }
            Self::Execveat { .. } => None,
        }
    }
}

const AT_FDCWD: i64 = -100;
const AT_SYMLINK_NOFOLLOW: u64 = 0x100;
const AT_EMPTY_PATH: u64 = 0x1000;
// Linux's MAX_ARG_STRLEN is 32 pages, including the terminating NUL.  Keep
// the Runtime's per-entry preflight aligned with that kernel boundary while
// retaining the smaller, explicit aggregate budget below.
const GUEST_PAGE_SIZE: usize = 4096;
const MAX_GUEST_EXEC_STRING_BYTES: usize = 32 * GUEST_PAGE_SIZE;
const MAX_GUEST_EXEC_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
struct ExecTransitionRecord {
    schema_version: u32,
    transition_id: String,
    status: String,
    host_pid: u32,
    parent_trace: Option<String>,
    child_trace: Option<String>,
    request: ExecRequestRecord,
    harness_path: String,
    host_loader: Option<String>,
    rootfs: String,
    requested_unix_ns: u64,
    virtual_fd_handoff: Option<String>,
    started_unix_ns: Option<u64>,
    failed_unix_ns: Option<u64>,
    error: Option<String>,
}

// IIB reserves a small block of guest-VA for its own private data. The
// addresses must sit below 0x8000_0000 so that `target_mmap`'s return
// (abi_long=i32 for ARM32) remains positive — libafl_qemu's wrapper
// treats `<= 0` as failure.
pub const IIB_STACK_POOL_BASE: u64 = 0x7000_0000;
pub const IIB_STACK_POOL_SIZE: u64 = 0x0010_0000; // 1 MiB
pub const IIB_TRAP_ADDR: u64 = 0x7e00_0000; // single trap page
pub const IIB_TRAP_SIZE: u64 = 0x0000_1000;
pub const IIB_SCRATCH_PAGE_ADDR: u64 = 0x7f00_0000; // scratch for cstring output
pub const IIB_SCRATCH_PAGE_SIZE: u64 = 0x0000_1000;
pub const IIB_GUEST_STATE_BASE: u64 = 0x7d00_0000;
pub const IIB_GUEST_STATE_SIZE: u64 = 0x0010_0000;

/// Globally-visible pointer to the live IIBModule. Set in `post_qemu_init`
/// so that `native_call` can dispatch nested hook breakpoints without
/// having access to the full `EmulatorModules` tuple.
///
/// Written once; reads see the atomic pointer (not dereferenced without a
/// null check).
static GLOBAL_MODULE_PTR: std::sync::atomic::AtomicPtr<IIBModule> =
    std::sync::atomic::AtomicPtr::new(std::ptr::null_mut());

fn run_until_callsite_resume(qemu: Qemu, resume_pc: IibGuestAddr) -> Result<(), String> {
    loop {
        match unsafe { qemu.run() } {
            Ok(libafl_qemu::QemuExitReason::Breakpoint(stopped_pc)) => {
                let stopped_pc = stopped_pc as IibGuestAddr;
                if stopped_pc == resume_pc {
                    return Ok(());
                }
                match dispatch_breakpoint(stopped_pc)? {
                    true => continue,
                    false => {
                        return Err(format!(
                            "native call from an IIB callsite hit an unregistered breakpoint at \
                             {stopped_pc:#x} before resume {resume_pc:#x}"
                        ));
                    }
                }
            }
            Ok(other) => {
                return Err(format!(
                    "native call from an IIB callsite did not reach resume \
                     {resume_pc:#x}: {other:?}"
                ));
            }
            Err(error) => {
                return Err(format!(
                    "native call from an IIB callsite failed before resume \
                     {resume_pc:#x}: {error:?}"
                ));
            }
        }
    }
}

/// Whether a nested dispatch owns the resume breakpoint it installs.
///
/// The native-call trap is a runtime-owned breakpoint, rather than a hook
/// entry.  A function hook may fall through to that trap when it is entered
/// from `native_call`; treating the trap like a temporary resume breakpoint
/// removes the outer call's return stop and lets the guest execute the trap
/// page.  Keep this decision in one small predicate so the ARM/x86 function
/// path and the MIPS delay/call paths cannot silently diverge.
fn needs_temporary_resume_breakpoint(
    resume_pc: IibGuestAddr,
    resume_is_existing_hook: bool,
) -> bool {
    !resume_is_existing_hook && resume_pc != IIB_TRAP_ADDR
}

#[cfg(test)]
mod resume_breakpoint_tests {
    use super::{needs_temporary_resume_breakpoint, IIB_TRAP_ADDR};

    #[test]
    fn runtime_trap_remains_owned_by_the_outer_native_call() {
        assert!(!needs_temporary_resume_breakpoint(IIB_TRAP_ADDR, false));
        assert!(!needs_temporary_resume_breakpoint(IIB_TRAP_ADDR, true));
    }

    #[test]
    fn ordinary_resume_is_temporary_only_when_not_a_hook() {
        assert!(needs_temporary_resume_breakpoint(0x1234, false));
        assert!(!needs_temporary_resume_breakpoint(0x1234, true));
    }
}

fn run_native_from_current_pc(
    module: &IIBModule,
    qemu: Qemu,
    callsite_pc: IibGuestAddr,
    resume_pc: IibGuestAddr,
) -> Result<(), String> {
    let resume_is_existing_hook = module.is_hook_pc(resume_pc);
    // The outer `native_call` installs one shared trap breakpoint before it
    // transfers control into the target.  A nested function hook can
    // fall-through back to that trap (its return address is the trap address),
    // so the nested dispatch must consume the breakpoint without removing it.
    // Removing it here lets the outer loop execute the trap page and produces
    // a guest SIGSEGV after an otherwise valid nested call.
    let install_temporary_resume_breakpoint =
        needs_temporary_resume_breakpoint(resume_pc, resume_is_existing_hook);
    qemu.remove_breakpoint(callsite_pc as QemuGuestAddr);
    if install_temporary_resume_breakpoint {
        qemu.set_breakpoint(resume_pc as QemuGuestAddr);
    }
    let result = run_until_callsite_resume(qemu, resume_pc);
    if install_temporary_resume_breakpoint {
        qemu.remove_breakpoint(resume_pc as QemuGuestAddr);
    }
    qemu.set_breakpoint(callsite_pc as QemuGuestAddr);
    result
}

fn current_function_return_pc(qemu: Qemu) -> Result<IibGuestAddr, String> {
    use libafl_qemu::ArchExtras;

    let cpu = qemu
        .current_cpu()
        .ok_or_else(|| "capture function return outside CPU context".to_string())?;
    cpu.read_return_address()
        .map(|address| address as IibGuestAddr)
        .map_err(|error| format!("read intercepted function return address: {error:?}"))
}

#[cfg(any(feature = "mips", feature = "mipsbe"))]
#[derive(Debug)]
struct MipsCallTransfer {
    target: IibGuestAddr,
    link_register: Option<libafl_qemu::arch::mips::Regs>,
}

#[cfg(any(feature = "mips", feature = "mipsbe"))]
fn capture_mips_call_transfer(
    qemu: Qemu,
    callsite_pc: IibGuestAddr,
) -> Result<MipsCallTransfer, String> {
    use libafl_qemu::arch::mips::Regs;

    let cpu = qemu
        .current_cpu()
        .ok_or_else(|| "capture MIPS callsite outside CPU context".to_string())?;
    let mut bytes = [0_u8; 4];
    qemu.read_mem(callsite_pc as QemuGuestAddr, &mut bytes)
        .map_err(|error| format!("read MIPS call instruction at {callsite_pc:#x}: {error:?}"))?;
    #[cfg(feature = "mipsbe")]
    let instruction = u32::from_be_bytes(bytes);
    #[cfg(all(feature = "mips", not(feature = "mipsbe")))]
    let instruction = u32::from_le_bytes(bytes);

    let opcode = instruction >> 26;
    match opcode {
        // JAL target. The high four bits come from PC+4 per the MIPS ISA.
        0x03 => Ok(MipsCallTransfer {
            target: ((callsite_pc.wrapping_add(4)) & 0xf000_0000)
                | (((instruction & 0x03ff_ffff) as IibGuestAddr) << 2),
            link_register: Some(Regs::Ra),
        }),
        // SPECIAL/JALR rs, rd. Capture rs before executing the delay slot.
        0x00 if instruction & 0x3f == 0x09 => {
            let source_index = ((instruction >> 21) & 0x1f) as i32;
            let link_index = ((instruction >> 11) & 0x1f) as i32;
            let source_register = Regs::try_from(source_index)
                .map_err(|_| format!("invalid MIPS JALR source register {source_index}"))?;
            let target = cpu
                .read_reg(source_register)
                .map_err(|error| format!("read MIPS JALR target register: {error:?}"))?
                as IibGuestAddr;
            let link_register = if link_index == 0 {
                None
            } else {
                Some(
                    Regs::try_from(link_index)
                        .map_err(|_| format!("invalid MIPS JALR link register {link_index}"))?,
                )
            };
            Ok(MipsCallTransfer {
                target,
                link_register,
            })
        }
        _ => Err(format!(
            "unsupported MIPS call instruction {instruction:#010x} at {callsite_pc:#x}"
        )),
    }
}

#[cfg(any(feature = "mips", feature = "mipsbe"))]
fn run_mips_delay_slot(
    module: &IIBModule,
    qemu: Qemu,
    callsite_pc: IibGuestAddr,
    resume_pc: IibGuestAddr,
) -> Result<(), String> {
    use libafl_qemu::arch::mips::Regs;

    let resume_is_existing_hook = module.is_hook_pc(resume_pc);
    qemu.remove_breakpoint(callsite_pc as QemuGuestAddr);
    if needs_temporary_resume_breakpoint(resume_pc, resume_is_existing_hook) {
        qemu.set_breakpoint(resume_pc as QemuGuestAddr);
    }
    let result = (|| {
        qemu.write_reg(
            Regs::Pc,
            callsite_pc.wrapping_add(4) as libafl_qemu::GuestReg,
        )
        .map_err(|error| format!("write MIPS delay-slot PC: {error:?}"))?;
        run_until_callsite_resume(qemu, resume_pc)
    })();
    if needs_temporary_resume_breakpoint(resume_pc, resume_is_existing_hook) {
        qemu.remove_breakpoint(resume_pc as QemuGuestAddr);
    }
    qemu.set_breakpoint(callsite_pc as QemuGuestAddr);
    result
}

#[cfg(any(feature = "mips", feature = "mipsbe"))]
fn run_mips_native_call(
    module: &IIBModule,
    qemu: Qemu,
    resume_pc: IibGuestAddr,
    transfer: MipsCallTransfer,
) -> Result<(), String> {
    use libafl_qemu::arch::mips::Regs;

    let cpu = qemu
        .current_cpu()
        .ok_or_else(|| "resume MIPS native call outside CPU context".to_string())?;
    if let Some(link_register) = transfer.link_register {
        cpu.write_reg(link_register, resume_pc as libafl_qemu::GuestReg)
            .map_err(|error| format!("write MIPS call link register: {error:?}"))?;
    }
    cpu.write_reg(Regs::Pc, transfer.target as libafl_qemu::GuestReg)
        .map_err(|error| format!("write MIPS native call target PC: {error:?}"))?;

    let resume_is_existing_hook = module.is_hook_pc(resume_pc);
    if needs_temporary_resume_breakpoint(resume_pc, resume_is_existing_hook) {
        qemu.set_breakpoint(resume_pc as QemuGuestAddr);
    }
    let result = run_until_callsite_resume(qemu, resume_pc);
    if needs_temporary_resume_breakpoint(resume_pc, resume_is_existing_hook) {
        qemu.remove_breakpoint(resume_pc as QemuGuestAddr);
    }
    result
}

/// Dispatch one breakpoint using the correct function-entry or callsite
/// semantics. This is shared by the outer harness and nested `native_call`
/// loops so they cannot drift.
pub fn dispatch_breakpoint(pc: IibGuestAddr) -> Result<bool, String> {
    use std::sync::atomic::Ordering;
    let ptr = GLOBAL_MODULE_PTR.load(Ordering::Acquire);
    if ptr.is_null() {
        return Err(format!(
            "dispatch_breakpoint({pc:#x}) before module ptr installed"
        ));
    }
    let qemu = unsafe { Qemu::get_unchecked() };
    if unsafe { (*ptr).pending_entry_pc } == Some(pc) {
        let module = unsafe { &mut *ptr };
        // Install bindings outside translated guest code. Installing a
        // breakpoint from an instruction callback is too late for another
        // instruction in that same translated block on its first execution.
        module.pending_entry_pc = None;
        qemu.remove_breakpoint(pc as QemuGuestAddr);
        deferred_register_hooks(qemu, module);
        if !module.is_hook_pc(pc) {
            return Ok(true);
        }
        // A user hook may itself target the entry. Dispatch it on this stop.
    }
    let module = unsafe { &*ptr };
    if !module.is_hook_pc(pc) {
        return Ok(false);
    }
    let resume_pc = module.callsite_resume_pc(pc);
    let function_return_pc = if resume_pc.is_none() {
        Some(current_function_return_pc(qemu)?)
    } else {
        None
    };

    #[cfg(any(feature = "mips", feature = "mipsbe"))]
    let mips_transfer = if let Some(resume_pc) = resume_pc {
        let transfer = capture_mips_call_transfer(qemu, pc)?;
        run_mips_delay_slot(module, qemu, pc, resume_pc)?;
        Some(transfer)
    } else {
        None
    };

    // SAFETY: ptr is installed from the pinned EmulatorModule and remains
    // live for the Emulator lifetime. Dispatch only reads the immutable
    // table and leaked state.
    let hook_handled = unsafe { (*ptr).dispatch_hooks_at(pc) };

    if let Some(resume_pc) = resume_pc {
        if hook_handled {
            #[cfg(feature = "arm")]
            qemu.write_reg(
                libafl_qemu::arch::arm::Regs::Pc,
                resume_pc as libafl_qemu::GuestReg,
            )
            .map_err(|error| format!("restore ARM callsite resume PC: {error:?}"))?;
            #[cfg(any(feature = "mips", feature = "mipsbe"))]
            qemu.write_reg(
                libafl_qemu::arch::mips::Regs::Pc,
                resume_pc as libafl_qemu::GuestReg,
            )
            .map_err(|error| format!("restore MIPS callsite resume PC: {error:?}"))?;
            #[cfg(feature = "x86_64")]
            qemu.write_reg(
                libafl_qemu::arch::x86_64::Regs::Rip,
                resume_pc as libafl_qemu::GuestReg,
            )
            .map_err(|error| format!("restore x86_64 callsite resume PC: {error:?}"))?;
        } else {
            crate::runtime_trace::record_runtime_state_event_at(
                "iib_callsite_native_fallthrough",
                format!("{pc:#x}->{resume_pc:#x}"),
                Some(pc),
            );
            #[cfg(any(feature = "arm", feature = "x86_64"))]
            run_native_from_current_pc(module, qemu, pc, resume_pc)?;
            #[cfg(any(feature = "mips", feature = "mipsbe"))]
            run_mips_native_call(
                module,
                qemu,
                resume_pc,
                mips_transfer.expect("MIPS callsite transfer captured before dispatch"),
            )?;
        }
    } else if !hook_handled {
        let return_pc = function_return_pc.expect("function return captured before dispatch");
        crate::runtime_trace::record_runtime_state_event_at(
            "iib_function_native_fallthrough",
            format!("{pc:#x}->{return_pc:#x}"),
            Some(pc),
        );
        run_native_from_current_pc(module, qemu, pc, return_pc)?;
    }
    Ok(true)
}

/// Nested native calls use the same breakpoint path as the outer harness.
pub fn dispatch_nested_hook(pc: IibGuestAddr) -> Result<bool, String> {
    dispatch_breakpoint(pc)
}

pub struct IIBModule {
    pub(crate) manifest: &'static StaticManifest,
    main_binary_path: PathBuf,
    // Populated in post_qemu_init:
    pub(crate) iib_state: Option<&'static IibState>,
    pub(crate) dispatch: DispatchTable,
    pub(crate) vfs: VirtualFdTable,
    // GlobalState instance - leaked to give 'static lifetime.
    pub(crate) global_state: Option<&'static (dyn Any + Send + Sync)>,
    // Load-base map populated in first_exec (Task 27).
    pub(crate) load_map: crate::load_map::LoadMap,
    pub(crate) guest_exec: Option<GuestExecConfig>,
    reject_unmanaged_exec: bool,
    pending_entry_pc: Option<IibGuestAddr>,
}

impl IIBModule {
    pub fn new(manifest: &'static StaticManifest, main_binary_path: PathBuf) -> Self {
        Self {
            manifest,
            main_binary_path,
            iib_state: None,
            dispatch: DispatchTable::new(),
            vfs: VirtualFdTable::new(),
            global_state: None,
            load_map: HashMap::new(),
            guest_exec: None,
            reject_unmanaged_exec: false,
            pending_entry_pc: None,
        }
    }

    /// Enable the generic guest-exec trampoline.  This is a Runtime feature,
    /// not a target-specific intervention: the new harness receives the same
    /// intervention publication and rootfs while replacing the guest image.
    pub fn with_guest_exec(mut self, config: GuestExecConfig) -> Self {
        self.guest_exec = Some(config);
        self.reject_unmanaged_exec = false;
        self
    }

    /// Keep execution inside this runtime when no replacement-image launcher
    /// is configured. The high-level library entry uses this by default.
    pub fn with_exec_disabled(mut self) -> Self {
        self.guest_exec = None;
        self.reject_unmanaged_exec = true;
        self
    }

    /// Return the runtime capability contract used by generated interventions.
    /// The manifest is derived from the concrete compiled harness architecture
    /// rather than from a Unit's requested behavior.
    pub fn runtime_capabilities(&self) -> fmst_iib_api::capability::RuntimeCapabilityManifest {
        crate::capabilities::current(self.manifest.arch)
    }

    /// Construct an empty IIB owner for a support process. The process still
    /// runs under the same official LibAFL QEMU harness and shares the target
    /// container namespace, but it cannot accidentally receive target hooks.
    pub fn trace_only(arch: Arch, main_binary_path: PathBuf) -> Self {
        fn empty_state() -> Box<dyn Any + Send + Sync> {
            Box::new(())
        }
        let manifest = Box::leak(Box::new(StaticManifest {
            abi_version: CURRENT_ABI_VERSION,
            arch,
            global_state: StaticGlobalState {
                type_name: "()",
                init_fn: empty_state,
            },
            callsite_hooks: &[],
            function_stubs: &[],
            pseudo_files: &[],
        }));
        Self::new(manifest, main_binary_path)
    }

    #[allow(dead_code)]
    pub(crate) fn main_binary_path(&self) -> &std::path::Path {
        &self.main_binary_path
    }

    /// Return true iff `pc` is a registered hook entry point. Used by the
    /// harness main loop to tell our hook breakpoints from other trap
    /// addresses (e.g. native_call's IIB_TRAP_ADDR).
    pub fn is_hook_pc(&self, pc: IibGuestAddr) -> bool {
        self.dispatch.get(pc).is_some()
    }

    /// Return the unique callsite resume PC registered at a hook address.
    /// Function-entry stubs return None. Mixing entry stubs and callsite hooks
    /// at one PC, or assigning different resumes to one PC, is invalid.
    pub fn callsite_resume_pc(&self, pc: IibGuestAddr) -> Option<IibGuestAddr> {
        let entries = self.dispatch.get(pc)?;
        let mut resume = None;
        for entry in entries {
            match (resume, entry.callsite_resume_pc) {
                (None, Some(candidate)) => resume = Some(candidate),
                (Some(existing), Some(candidate)) if existing == candidate => {}
                (Some(existing), Some(candidate)) => panic!(
                    "IIB callsite hooks at {pc:#x} disagree on resume PC: \
                     {existing:#x} vs {candidate:#x}"
                ),
                (Some(_), None) => {
                    panic!("IIB cannot mix a function stub and callsite hook at {pc:#x}")
                }
                (None, None) => {}
            }
        }
        if resume.is_some()
            && entries
                .iter()
                .any(|entry| entry.callsite_resume_pc.is_none())
        {
            panic!("IIB cannot mix a function stub and callsite hook at {pc:#x}");
        }
        resume
    }

    /// Fire all dispatch entries registered for `pc`. Assumes the caller is
    /// inside qemu's execution context (so `current_cpu` is valid).
    pub fn dispatch_hooks_at(&self, pc: IibGuestAddr) -> bool {
        let global_state = match self.global_state {
            Some(gs) => gs,
            None => {
                log::error!("IIB dispatch_hooks_at: global_state not initialised");
                return false;
            }
        };
        let iib_state = match self.iib_state {
            Some(st) => st,
            None => {
                log::error!("IIB dispatch_hooks_at: iib_state not initialised");
                return false;
            }
        };
        let entries = match self.dispatch.get(pc) {
            Some(slice) => slice.to_vec(),
            None => return false,
        };
        let mut hook_handled = false;
        for entry in entries {
            log::info!("IIB dispatch: firing hook '{}' at pc={:#x}", entry.id, pc);
            crate::runtime_trace::record_runtime_state_event_at(
                "iib_hook",
                format!("{}@{pc:#x}", entry.id),
                Some(pc),
            );
            if let Some(resume_pc) = entry.callsite_resume_pc {
                let mut ctx = crate::context_impl::IIBContextImpl::new_callsite(
                    global_state,
                    iib_state,
                    resume_pc,
                );
                (entry.entry_fn)(&mut ctx);
                hook_handled |= ctx.return_value_set();
            } else {
                let mut ctx = crate::context_impl::IIBContextImpl::new(global_state, iib_state);
                (entry.entry_fn)(&mut ctx);
                hook_handled |= ctx.return_value_set();
            }
        }
        hook_handled
    }
}

impl<I, S> EmulatorModule<I, S> for IIBModule
where
    I: Unpin + 'static,
    S: Unpin + 'static,
{
    fn post_qemu_init<ET>(&mut self, qemu: Qemu, emulator_modules: &mut EmulatorModules<ET, I, S>)
    where
        ET: EmulatorModuleTuple<I, S>,
    {
        log::info!("IIBModule::post_qemu_init starting");

        // Publish our address so native_call can dispatch nested hooks.
        // SAFETY: EmulatorModules owns this module via Pin<Box<...>>; the
        // address is stable for the whole process lifetime.
        GLOBAL_MODULE_PTR.store(self as *mut _, std::sync::atomic::Ordering::Release);

        // 1. Allocate IIB stack pool (guest-visible region).
        qemu.map_fixed(
            IIB_STACK_POOL_BASE as QemuGuestAddr,
            IIB_STACK_POOL_SIZE as usize,
            MmapPerms::ReadWrite,
        )
        .expect("IIB init failed: stack pool mmap");

        // 2. Allocate trap page. Executable so the CPU can "enter" it when
        //    native_call redirects LR there; a breakpoint pre-registered at
        //    IIB_TRAP_ADDR stops execution and signals native_call to return.
        qemu.map_fixed(
            IIB_TRAP_ADDR as QemuGuestAddr,
            IIB_TRAP_SIZE as usize,
            MmapPerms::ReadExecute,
        )
        .expect("IIB init failed: trap page mmap");

        // 3. Allocate scratch page for pseudo-file / hook writes into guest VA.
        qemu.map_fixed(
            IIB_SCRATCH_PAGE_ADDR as QemuGuestAddr,
            IIB_SCRATCH_PAGE_SIZE as usize,
            MmapPerms::ReadWrite,
        )
        .expect("IIB init failed: scratch page mmap");

        // Session-lifetime guest-visible storage for intervention state. The
        // allocator only hands out addresses inside this mapped region.
        qemu.map_fixed(
            IIB_GUEST_STATE_BASE as QemuGuestAddr,
            IIB_GUEST_STATE_SIZE as usize,
            MmapPerms::ReadWrite,
        )
        .expect("IIB init failed: guest state mmap");

        // 4. Register a guest-side breakpoint at the trap address so that
        //    `Qemu::run()` inside native_call exits with Breakpoint(trap_addr).
        qemu.set_breakpoint(IIB_TRAP_ADDR as QemuGuestAddr);

        // 5. Instantiate IibState and leak.
        let stack_pool = GuestStackPool::new(IIB_STACK_POOL_BASE, IIB_STACK_POOL_SIZE);
        let iib_state: &'static IibState = Box::leak(Box::new(IibState::new(
            IIB_TRAP_ADDR,
            stack_pool,
            crate::guest_memory::GuestMemoryPool::new(
                IIB_GUEST_STATE_BASE,
                IIB_GUEST_STATE_SIZE as usize,
            ),
        )));
        self.iib_state = Some(iib_state);

        // 6. Instantiate GlobalState and leak.
        let gs: Box<dyn Any + Send + Sync> = (self.manifest.global_state.init_fn)();
        let global_state: &'static (dyn Any + Send + Sync) = Box::leak(gs);
        self.global_state = Some(global_state);

        // 7. Register pseudo-file path -> factory mappings in VFS.
        for pf_desc in self.manifest.pseudo_files {
            for path in pf_desc.paths {
                self.vfs
                    .register_resource(pf_desc.id, pf_desc.impl_name, path, pf_desc.factory);
                log::info!("registered pseudo_file {} at {}", pf_desc.impl_name, path);
            }
        }

        // A host-harness exec cannot keep Rust trait objects alive.  Restore
        // the explicit virtual-fd handoff after the child manifest is loaded,
        // before the guest's first instruction can issue a syscall.
        if let Some(path) = std::env::var_os("FMST_EXEC_HANDOFF") {
            let path = PathBuf::from(path);
            std::env::remove_var("FMST_EXEC_HANDOFF");
            match self.vfs.restore_exec_handoff(&path) {
                Ok(count) => {
                    crate::runtime_trace::record_runtime_state_event(
                        "virtual_fd_exec_handoff_restored",
                        format!("descriptors={count}; file={}", path.display()),
                    );
                }
                Err(error) => {
                    // Preserve the failed handoff as evidence of the exact
                    // state the child rejected.
                    if let Some(transition) = std::env::var_os("FMST_EXEC_TRANSITION") {
                        let transition = PathBuf::from(transition);
                        fail_guest_exec_transition(
                            Some(&transition),
                            "child-virtual-fd-handoff",
                            format!("child restore failed: {error}"),
                        );
                    }
                    crate::runtime_trace::record_runtime_state_event(
                        "virtual_fd_exec_handoff_failed",
                        format!("file={}; error={error}", path.display()),
                    );
                    panic!("virtual fd exec handoff failed: {error}");
                }
            }
        }

        // 8. Install pre_syscalls hook that routes file syscalls through VFS.
        emulator_modules.pre_syscalls(Hook::Closure(Box::new(
            move |_qemu,
                  mods,
                  _state,
                  sys_num,
                  a0,
                  a1,
                  a2,
                  a3,
                  a4,
                  _a5,
                  _a6,
                  _a7|
                  -> SyscallHookResult {
                dispatch_syscall_via_vfs(mods, sys_num, a0, a1, a2, a3, a4)
            },
        )));

        // A successful exec closes virtual descriptors carrying FD_CLOEXEC.
        // This belongs in the post hook: a failed exec must leave the table
        // unchanged so the guest can inspect errno and continue.
        emulator_modules.post_syscalls(Hook::Closure(Box::new(
            move |_qemu,
                  mods,
                  _state,
                  result,
                  sys_num,
                  _a0,
                  _a1,
                  _a2,
                  _a3,
                  _a4,
                  _a5,
                  _a6,
                  _a7|
                  -> GuestUlong { complete_syscall_via_vfs(mods, result, sys_num) },
        )));

        // 9. Compute the guest binary's own `_start` entry (NOT the ld.so
        //    entry reported by `qemu.image_info().entry`, which is the
        //    interpreter's entry for dynamically-linked binaries). We parse
        //    the ELF off-disk for `e_entry` and either use it verbatim
        //    (EXEC/non-PIE) or add `qemu.load_addr()` (DYN/PIE).
        let entry_pc = compute_main_entry_pc(&self.main_binary_path, qemu.load_addr() as u64)
            .expect("IIB init failed: cannot parse guest binary for entry PC");
        let entry_pc = entry_pc as QemuGuestAddr;
        log::info!(
            "IIB registering deferred-setup breakpoint at main-binary entry PC = {:#x} \
             (ld.so entry was {:#x}, load_addr = {:#x})",
            entry_pc,
            qemu.image_info().entry,
            qemu.load_addr()
        );
        self.pending_entry_pc = Some(entry_pc as IibGuestAddr);
        qemu.set_breakpoint(entry_pc);

        log::info!("IIBModule::post_qemu_init completed");
    }
}

/// Read `/proc/self/maps` directly when the QEMU mapping iterator is unsafe
/// for this host/guest layout or comes back empty. qemu-user mmap's each guest page into the host's
/// own virtual address space, offset by `guest_base`. So any /proc/self/maps
/// line whose host range falls inside `[guest_base, guest_base + 2^32)` is
/// a guest mapping, and its guest address is `host_addr - guest_base`.
fn read_host_maps_as_guest() -> Vec<crate::load_map::MapEntry> {
    let gb = unsafe { libafl_qemu::sys::guest_base as u64 };
    // ARM32 guest VA ceiling; safe overestimate for this helper.
    let guest_va_span: u64 = 0x1_0000_0000;
    let host_lo = gb;
    let host_hi = gb.saturating_add(guest_va_span);
    let maps = match std::fs::read_to_string("/proc/self/maps") {
        Ok(s) => s,
        Err(e) => {
            log::error!("failed to read /proc/self/maps: {e}");
            return Vec::new();
        }
    };
    let mut out: Vec<crate::load_map::MapEntry> = Vec::new();
    for line in maps.lines() {
        // Format: "start-end perms offset dev inode       path"
        //   fields are space-separated but the path is preceded by many
        //   spaces for column alignment. `split_whitespace` collapses all
        //   runs of whitespace, giving us exactly the 5 or 6 fields we want.
        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() < 5 {
            continue;
        }
        let range = tokens[0];
        // perms field (tokens[1]) is the host's view of the mapping and is
        // always "r--p" for guest pages — qemu-user doesn't PROT_EXEC them
        // on the host because guest code is interpreted, not run directly.
        // We deduce executability below from the path (any file-backed
        // mapping in guest VA range is a candidate binary segment).
        let path = if tokens.len() >= 6 {
            tokens[5].to_string()
        } else {
            String::new()
        };

        let (lo_s, hi_s) = match range.split_once('-') {
            Some(t) => t,
            None => continue,
        };
        let lo = match u64::from_str_radix(lo_s, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let hi = match u64::from_str_radix(hi_s, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };

        if lo < host_lo || hi > host_hi {
            continue;
        }
        let g_start = lo - gb;
        let g_end = hi - gb;
        // Treat every file-backed mapping in the guest VA range as
        // executable for `build_load_map`'s purposes: it only cares that
        // some segment of the binary is mapped so it can find the load
        // base. The real executable permission lives in qemu's pageflags
        // tree but that's not reachable here.
        let is_exec = !path.is_empty();
        out.push(crate::load_map::MapEntry {
            start: g_start,
            end: g_end,
            path,
            is_executable: is_exec,
        });
    }
    log::debug!(
        "read_host_maps_as_guest: {} entries in guest VA range",
        out.len()
    );
    for e in &out {
        log::debug!(
            "  entry: {:#x}-{:#x} exec={} path={:?}",
            e.start,
            e.end,
            e.is_executable,
            e.path
        );
    }
    out
}

/// Parse the guest ELF's `e_type` + `e_entry` to return the absolute VA
/// at which the binary's own `_start` will execute under qemu-user.
///
/// - `ET_EXEC` (non-PIE): entry = `e_entry` (absolute VA in the ELF).
/// - `ET_DYN` (PIE): entry = `load_base + e_entry` (e_entry is a file
///   offset when LOAD p_vaddr is 0).
fn compute_main_entry_pc(binary_path: &std::path::Path, load_base: u64) -> Result<u64, String> {
    use goblin::elf::header::{ET_DYN, ET_EXEC};
    let bytes = std::fs::read(binary_path).map_err(|e| format!("read {binary_path:?}: {e}"))?;
    let elf = goblin::elf::Elf::parse(&bytes).map_err(|e| format!("parse {binary_path:?}: {e}"))?;
    let entry = match elf.header.e_type {
        ET_EXEC => elf.header.e_entry,
        ET_DYN => load_base.wrapping_add(elf.header.e_entry),
        other => {
            return Err(format!(
                "unexpected e_type {other}; only ET_EXEC/ET_DYN supported"
            ))
        }
    };
    Ok(entry)
}

/// One-shot setup while stopped before the guest's first instruction, after
/// the loader has mapped dependencies. Never runs inside a translated block.
fn deferred_register_hooks(qemu: Qemu, module: &mut IIBModule) {
    if !module.load_map.is_empty() {
        // Defensive: the entry breakpoint fires at most once, but guard against
        // accidental re-entry if the manifest is augmented at runtime.
        return;
    }
    log::info!("IIB deferred setup: entry reached, building load_map");

    // 1. Build load_map from Qemu::mappings().  The LibAFL-QEMU bridge's
    // legacy iterator assumes guest VA == host VA while walking page flags;
    // on linux-user targets without a reserved address range (currently
    // x86_64) that assumption can dereference a missing host VMA and crash the
    // harness before a map is returned.  Use the same host-map translation as
    // the fallback for x86_64 and whenever guest_base is non-zero, keeping
    // this workaround in Firmenstein rather than requiring a private QEMU
    // checkout patch.
    let guest_base = unsafe { libafl_qemu::sys::guest_base as u64 };
    let use_host_maps = cfg!(feature = "x86_64") || guest_base != 0;
    let mut entries: Vec<crate::load_map::MapEntry> = if use_host_maps {
        log::debug!(
            "IIB deferred setup: guest_base={guest_base:#x}; using /proc/self/maps translation"
        );
        read_host_maps_as_guest()
    } else {
        Vec::new()
    };
    if entries.is_empty() && !use_host_maps {
        for m in qemu.mappings() {
            let perms = m.flags();
            let is_exec = perms.executable();
            let path = m.path().cloned().unwrap_or_default();
            log::debug!(
                "IIB mapping (qemu-iterator): {:#x}-{:#x} exec={} r={} w={} path={:?}",
                m.start(),
                m.end(),
                is_exec,
                perms.readable(),
                perms.writable(),
                path
            );
            entries.push(crate::load_map::MapEntry {
                start: m.start() as IibGuestAddr,
                end: m.end() as IibGuestAddr,
                path,
                is_executable: is_exec,
            });
        }
    }
    if entries.is_empty() {
        // Qemu::mappings() can return 0 rows in libafl_qemu 0.16 because
        // its `libafl_maps_next` iterator calls `h2g_valid()` on guest-VA
        // values — which only succeeds when guest_base == 0. Fall back to
        // parsing the host's /proc/self/maps directly.
        log::debug!("Qemu::mappings() returned 0 rows; falling back to /proc/self/maps");
        entries = read_host_maps_as_guest();
    }
    let load_map = crate::load_map::build_load_map(&entries);
    log::info!(
        "IIB load_map resolved {} binaries: {:?}",
        load_map.len(),
        load_map.keys().collect::<Vec<_>>()
    );
    let mut loaded_images: Vec<_> = load_map.iter().collect();
    loaded_images.sort_by_key(|(name, _)| *name);
    for (name, base) in loaded_images {
        match base {
            Ok(base) => crate::runtime_trace::record_runtime_event(
                "image_load",
                format!("{name}@{base:#x}"),
            ),
            Err(error) => crate::runtime_trace::record_runtime_state_event(
                "image_load_ambiguous",
                error.to_string(),
            ),
        }
    }
    let mut focus_images: HashSet<String> = HashSet::new();
    if let Some(name) = module
        .main_binary_path
        .file_name()
        .and_then(|value| value.to_str())
    {
        focus_images.insert(name.to_owned());
    }
    focus_images.extend(
        module
            .manifest
            .callsite_hooks
            .iter()
            .map(|descriptor| descriptor.target.binary.to_owned()),
    );
    focus_images.extend(
        module
            .manifest
            .function_stubs
            .iter()
            .map(|descriptor| descriptor.target.binary.to_owned()),
    );
    let mut focus_image_names: Vec<String> = focus_images.iter().cloned().collect();
    focus_image_names.sort();
    let focus_ranges = entries
        .iter()
        .filter(|entry| {
            entry.is_executable
                && std::path::Path::new(&entry.path)
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|name| focus_images.contains(name))
        })
        .map(|entry| (entry.start, entry.end))
        .collect();
    crate::runtime_trace::set_runtime_focus_ranges(focus_image_names, focus_ranges);
    module.load_map = load_map;

    // 2. Resolve callsite hooks + function stubs into DispatchTable.  The
    // manifest is required for the initial image; after a host-harness exec,
    // the same intervention may legitimately contain hooks for a different
    // image, which are recorded as non-applicable instead of hiding an
    // initial publication error.
    let image_kind = current_image_execution_kind();
    for desc in module.manifest.callsite_hooks {
        if let Err(error) = register_one(
            desc.id,
            &desc.target,
            desc.flavor,
            desc.entry_fn,
            Some(desc.resume_offset),
            &module.load_map,
            &mut module.dispatch,
            image_kind,
        ) {
            fatal_deferred_setup(error);
        }
    }
    for desc in module.manifest.function_stubs {
        if let Err(error) = register_one(
            desc.id,
            &desc.target,
            desc.flavor,
            desc.entry_fn,
            None,
            &module.load_map,
            &mut module.dispatch,
            image_kind,
        ) {
            fatal_deferred_setup(error);
        }
    }

    // 3. Install a guest-side breakpoint at each unique hook PC. The main
    //    run loop catches `Breakpoint(addr)` exits, dispatches our hook for
    //    `addr`, and re-enters qemu.run(). Using breakpoints instead of TCG
    //    instruction hooks is critical: an instruction hook runs as part of
    //    the translated TB, so even after it modifies PC the TB keeps
    //    executing the original function body. A breakpoint uses
    //    cpu_loop_exit to unwind OUT of cpu_exec's setjmp — which is safe
    //    Rust-side because qemu.run() returns control to us entirely.
    let unique_pcs: Vec<IibGuestAddr> = module.dispatch.unique_pcs().collect();
    log::info!(
        "IIB installing {} unique hook breakpoint PC(s)",
        unique_pcs.len()
    );
    let _ = module; // release borrow before using `qemu`
    for pc in unique_pcs {
        qemu.set_breakpoint(pc as QemuGuestAddr);
    }

    log::info!("IIB deferred setup completed");
}

/// Required initial bindings versus inherited post-exec applicability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImageExecutionKind {
    Initial,
    PostExec { depth: u32 },
}

fn current_image_execution_kind() -> ImageExecutionKind {
    match std::env::var("FMST_EXEC_DEPTH")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
    {
        Some(depth) if depth > 0 => ImageExecutionKind::PostExec { depth },
        _ => ImageExecutionKind::Initial,
    }
}

fn fatal_deferred_setup(reason: String) -> ! {
    crate::runtime_trace::record_runtime_state_event("iib_setup_failed", reason.clone());
    log::error!("IIB deferred setup failed: {reason}");
    crate::runtime_trace::flush_runtime_trace();
    std::process::exit(2)
}

fn resolve_hook_target(
    target: &ModuleTargetStatic,
    load_map: &crate::load_map::LoadMap,
    image_kind: ImageExecutionKind,
) -> Result<Option<IibGuestAddr>, String> {
    let Some(base) = load_map.get(target.binary) else {
        return match image_kind {
            ImageExecutionKind::Initial => Err(format!(
                "IIB-MISSING-BINARY: initial image does not contain required target binary {:?}",
                target.binary
            )),
            ImageExecutionKind::PostExec { depth } => {
                crate::runtime_trace::record_runtime_state_event(
                    "iib_hook_skipped_missing_binary",
                    format!("binary={};image=post_exec;depth={depth}", target.binary),
                );
                Ok(None)
            }
        };
    };
    let base = base
        .as_ref()
        .map_err(|error| format!("IIB-AMBIGUOUS-BINARY: {error}"))?;
    let final_pc = base.checked_add(target.offset).ok_or_else(|| {
        format!(
            "IIB-HOOK-ADDRESS-OVERFLOW: binary {:?} base={base:#x} offset={:#x}",
            target.binary, target.offset
        )
    })?;
    Ok(Some(final_pc))
}

fn register_one(
    id: &'static str,
    target: &ModuleTargetStatic,
    flavor: HookFlavor,
    entry_fn: HookFn,
    resume_offset: Option<IibGuestAddr>,
    load_map: &crate::load_map::LoadMap,
    dispatch: &mut DispatchTable,
    image_kind: ImageExecutionKind,
) -> Result<(), String> {
    if flavor == HookFlavor::Exit {
        log::error!("IIB-FLAVOR-EXIT: hook '{id}' requests Exit flavor, not supported in v1");
        return Ok(());
    }
    let Some(final_pc) = resolve_hook_target(target, load_map, image_kind)? else {
        log::info!(
            "hook {id}: binary={} is not applicable to this exec image",
            target.binary
        );
        return Ok(());
    };
    let base = final_pc - target.offset;
    let callsite_resume_pc = resume_offset
        .map(|offset| {
            base.checked_add(offset).ok_or_else(|| {
                format!(
                    "IIB-HOOK-ADDRESS-OVERFLOW: hook {id} resume base={base:#x} offset={offset:#x}"
                )
            })
        })
        .transpose()?;
    log::info!(
        "hook {id}: binary={} base={:#x} offset={:#x} -> pc={:#x}",
        target.binary,
        base,
        target.offset,
        final_pc
    );
    dispatch.register(
        final_pc,
        DispatchEntry {
            flavor,
            entry_fn,
            id,
            callsite_resume_pc,
        },
    );
    Ok(())
}

/// Route a syscall through the IIBModule's VirtualFdTable. Called from
/// the libafl_qemu pre_syscalls closure. Returns `SyscallHookResult::Skip(v)`
/// when VFS handled it, else `SyscallHookResult::Run` to let the host kernel
/// execute the syscall.
fn dispatch_syscall_via_vfs<ET, I, S>(
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    sys_num: i32,
    a0: GuestUlong,
    a1: GuestUlong,
    a2: GuestUlong,
    a3: GuestUlong,
    a4: GuestUlong,
) -> SyscallHookResult
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin + 'static,
    S: Unpin + 'static,
{
    let module = match emulator_modules.get_mut::<IIBModule>() {
        Some(m) => m,
        None => return SyscallHookResult::Run,
    };
    let global_state = match module.global_state {
        Some(gs) => gs,
        None => return SyscallHookResult::Run,
    };
    let iib_state = match module.iib_state {
        Some(st) => st,
        None => return SyscallHookResult::Run,
    };

    // SAFETY: IIBContextImpl holds a reference to iib_state and global_state,
    // and `&mut module.vfs` is disjoint from those fields. We need a split
    // borrow to pass `&mut vfs` and `&mut ctx` simultaneously. Since the ctx
    // only reads `global_state`/`iib_state`, we separately build it first,
    // then dispatch through vfs.
    let mut ctx = crate::context_impl::IIBContextImpl::new(global_state, iib_state);

    // A foreign guest ELF cannot be handed directly to the host kernel.  If
    // the harness was started with the generic exec configuration, replace the
    // current host process with a fresh harness before QEMU's native fallback
    // sees the syscall.  On failure we deliberately fall through to QEMU so
    // its normal errno (including scripts, non-ELF files, and unsupported
    // execveat forms) remains visible.
    if sys_num == crate::vfs::syscall_no::EXECVE || sys_num == crate::vfs::syscall_no::EXECVEAT {
        if module.reject_unmanaged_exec {
            crate::runtime_trace::record_runtime_state_event(
                "guest_exec_disabled",
                "no exec launcher configured; returning ENOSYS",
            );
            return SyscallHookResult::Skip(crate::vfs::guest_errno_result(
                fmst_iib_api::types::Errno::ENOSYS,
            ) as GuestUlong);
        }
        let config = module.guest_exec.clone();
        if let Some(config) = config {
            let word_bits = match module.manifest.arch {
                Arch::X86_64 => 64,
                Arch::Arm | Arch::Mips => 32,
            };
            let (operation, pathname, argv, envp) = if sys_num == crate::vfs::syscall_no::EXECVE {
                (GuestExecOperation::Execve, a0, a1, a2)
            } else {
                (
                    GuestExecOperation::Execveat {
                        dirfd: guest_exec_arg_as_i64(a0),
                        flags: a4 as u64,
                    },
                    a1,
                    a2,
                    a3,
                )
            };
            if let Err(error) = trampoline_guest_exec(
                &mut ctx,
                &mut module.vfs,
                pathname as fmst_iib_api::types::GuestAddr,
                argv as fmst_iib_api::types::GuestAddr,
                envp as fmst_iib_api::types::GuestAddr,
                word_bits,
                &config,
                operation,
                module.manifest.arch,
            ) {
                match error {
                    GuestExecError::Fallback(error) => {
                        log::debug!("guest exec trampoline unavailable: {error}");
                    }
                    GuestExecError::Reject(error) => {
                        log::warn!("guest exec rejected at virtual-fd boundary: {error}");
                        return SyscallHookResult::Skip(crate::vfs::guest_errno_result(
                            fmst_iib_api::types::Errno::ENOSYS,
                        ) as GuestUlong);
                    }
                }
            }
        }
    }

    match module.vfs.dispatch_syscall(
        sys_num,
        a0 as fmst_iib_api::types::GuestReg,
        a1 as fmst_iib_api::types::GuestReg,
        a2 as fmst_iib_api::types::GuestReg,
        a3 as fmst_iib_api::types::GuestReg,
        &mut ctx,
    ) {
        crate::vfs::VfsResult::NativeFallback => SyscallHookResult::Run,
        crate::vfs::VfsResult::Handled(v) => SyscallHookResult::Skip(v as GuestUlong),
        crate::vfs::VfsResult::GuestError(error) => {
            SyscallHookResult::Skip(crate::vfs::guest_errno_result(error) as GuestUlong)
        }
    }
}

fn guest_exec_arg_as_i64(value: GuestUlong) -> i64 {
    #[cfg(feature = "x86_64")]
    return value as i64;
    #[cfg(not(feature = "x86_64"))]
    return (value as u32 as i32) as i64;
}

fn read_guest_vector(
    ctx: &dyn fmst_iib_api::context::IIBContextOps,
    vector: fmst_iib_api::types::GuestAddr,
    word_bits: u8,
    bytes_read: &mut usize,
) -> Result<Vec<CString>, String> {
    if vector == 0 {
        return Ok(Vec::new());
    }
    let word_bytes = usize::from(word_bits / 8);
    let mut values = Vec::new();
    for index in 0..4096usize {
        let slot = vector
            .checked_add((index * word_bytes) as u64)
            .ok_or_else(|| "guest vector address overflow".to_owned())?;
        let address = if word_bits == 64 {
            ctx.read_u64(slot)
                .map_err(|error| format!("read guest vector: {error:?}"))?
        } else {
            ctx.read_u32(slot)
                .map_err(|error| format!("read guest vector: {error:?}"))? as u64
        };
        if address == 0 {
            return Ok(values);
        }
        let value = ctx
            .read_cstr(address, MAX_GUEST_EXEC_STRING_BYTES)
            .map_err(|error| format!("read guest string: {error:?}"))?;
        let entry_bytes = value.as_bytes().len().saturating_add(1);
        account_guest_exec_bytes(bytes_read, entry_bytes)?;
        values.push(value);
    }
    Err("guest argument/environment vector exceeds 4096 entries".to_owned())
}

fn unix_time_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .min(u64::MAX as u128) as u64
}

fn bytes_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn account_guest_exec_bytes(bytes_read: &mut usize, entry_bytes: usize) -> Result<(), String> {
    *bytes_read = (*bytes_read)
        .checked_add(entry_bytes)
        .ok_or_else(|| "guest argument/environment byte budget overflow".to_owned())?;
    if *bytes_read > MAX_GUEST_EXEC_BYTES {
        return Err(format!(
            "guest argument/environment bytes exceed {MAX_GUEST_EXEC_BYTES}"
        ));
    }
    Ok(())
}

fn trace_root_stem(trace: &Path) -> String {
    let stem = trace
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("runtime_trace");
    let Some(separator) = stem.rfind(".exec-") else {
        return stem.to_owned();
    };
    let suffix = &stem[separator + ".exec-".len()..];
    let depth = suffix
        .split_once(".pid-")
        .map_or(suffix, |(depth, _)| depth);
    if !depth.is_empty() && depth.bytes().all(|byte| byte.is_ascii_digit()) {
        stem[..separator].to_owned()
    } else {
        stem.to_owned()
    }
}

fn trace_process_suffix(trace: &Path) -> Option<String> {
    let stem = trace.file_stem().and_then(|value| value.to_str())?;
    let marker = stem.rfind(".pid-")?;
    let pid = &stem[marker + ".pid-".len()..];
    (!pid.is_empty() && pid.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| format!(".pid-{pid}"))
}

fn exec_artifact_path_for_pid(
    trace: &Path,
    depth: u32,
    suffix: &str,
    process_pid: Option<u32>,
) -> PathBuf {
    let stem = trace_root_stem(trace);
    let extension = trace
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{value}"))
        .unwrap_or_default();
    let process_suffix = process_pid
        .map(|pid| format!(".pid-{pid}"))
        .or_else(|| trace_process_suffix(trace))
        .unwrap_or_default();
    trace.with_file_name(format!(
        "{stem}.exec-{depth}{process_suffix}{suffix}{extension}"
    ))
}

fn trace_transition_path_for_pid(trace: &Path, depth: u32, process_pid: Option<u32>) -> PathBuf {
    exec_artifact_path_for_pid(trace, depth, ".transition", process_pid)
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("transition path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| format!("create transition directory: {error}"))?;
    let temporary = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name().unwrap().to_string_lossy()
    ));
    let encoded = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("encode transition record: {error}"))?;
    std::fs::write(&temporary, encoded)
        .map_err(|error| format!("write transition record: {error}"))?;
    std::fs::rename(&temporary, path).map_err(|error| format!("publish transition record: {error}"))
}

fn update_transition_record(
    path: &Path,
    status: &str,
    error: Option<String>,
    started: bool,
    failed: bool,
) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read transition record: {error}"))?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode transition record: {error}"))?;
    value["status"] = serde_json::Value::String(status.to_owned());
    value["host_pid"] = serde_json::Value::from(std::process::id());
    if started {
        value["started_unix_ns"] = serde_json::Value::from(unix_time_ns());
    }
    if failed {
        value["failed_unix_ns"] = serde_json::Value::from(unix_time_ns());
    }
    value["error"] = error.map_or(serde_json::Value::Null, serde_json::Value::String);
    write_json_atomic(path, &value)
}

fn update_transition_virtual_fd_handoff(path: &Path, handoff: &Path) -> Result<(), String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read transition record: {error}"))?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode transition record: {error}"))?;
    value["virtual_fd_handoff"] = serde_json::Value::String(handoff.to_string_lossy().into_owned());
    write_json_atomic(path, &value)
}

fn fail_guest_exec_transition(path: Option<&Path>, transition_id: &str, error: String) {
    if let Some(path) = path {
        if let Err(update_error) =
            update_transition_record(path, "failed", Some(error.clone()), false, true)
        {
            log::warn!("failed to persist guest exec transition failure: {update_error}");
        }
        crate::runtime_trace::record_runtime_state_event(
            "exec_transition_failed",
            format!("{transition_id}; error={error}"),
        );
        crate::runtime_trace::flush_runtime_trace();
    }
}

fn resolve_guest_exec_path(rootfs: &Path, guest_path: &OsStr) -> Result<PathBuf, String> {
    let candidate = guest_exec_candidate(rootfs, guest_path)?;
    let resolved = candidate
        .canonicalize()
        .map_err(|error| format!("resolve guest executable {guest_path:?}: {error}"))?;
    let root = rootfs
        .canonicalize()
        .map_err(|error| format!("canonicalize guest rootfs {}: {error}", rootfs.display()))?;
    if resolved != root && !resolved.starts_with(&root) {
        return Err(format!(
            "guest executable resolves outside rootfs: {guest_path:?}"
        ));
    }
    Ok(resolved)
}

fn guest_exec_candidate(rootfs: &Path, guest_path: &OsStr) -> Result<PathBuf, String> {
    let root = rootfs
        .canonicalize()
        .map_err(|error| format!("canonicalize guest rootfs {}: {error}", rootfs.display()))?;
    Ok(if guest_path.as_bytes().first() == Some(&b'/') {
        // Path::join treats a component beginning with `/` as a host
        // absolute path. Collapse all guest-root separators before
        // joining so `//x` and `///x` stay inside the staged rootfs.
        let bytes = guest_path.as_bytes();
        let first_non_separator = bytes
            .iter()
            .position(|byte| *byte != b'/')
            .unwrap_or(bytes.len());
        let relative = &bytes[first_non_separator..];
        root.join(OsStr::from_bytes(relative))
    } else {
        // QEMU keeps the guest cwd as the host process cwd.  Translate that
        // path back into the staged rootfs before resolving a relative
        // pathname; joining it directly to the host cwd is wrong when the
        // runtime is used outside a container whose rootfs is `/`.
        let cwd = std::env::current_dir()
            .map_err(|error| format!("read guest cwd for relative exec path: {error}"))?;
        let guest_cwd = cwd
            .strip_prefix(&root)
            .or_else(|_| cwd.strip_prefix("/"))
            .unwrap_or(cwd.as_path());
        root.join(guest_cwd).join(Path::new(guest_path))
    })
}

fn reject_final_symlink(rootfs: &Path, guest_path: &OsStr) -> Result<(), String> {
    let candidate = guest_exec_candidate(rootfs, guest_path)?;
    let metadata = std::fs::symlink_metadata(&candidate).map_err(|error| {
        format!("inspect guest executable {guest_path:?} for AT_SYMLINK_NOFOLLOW: {error}")
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "guest executable final path component is a symbolic link: {guest_path:?}"
        ));
    }
    Ok(())
}

fn guest_path_from_host_path(rootfs: &Path, host_path: &Path) -> Result<OsString, String> {
    let root = rootfs
        .canonicalize()
        .map_err(|error| format!("canonicalize guest rootfs {}: {error}", rootfs.display()))?;
    let path = host_path.canonicalize().map_err(|error| {
        format!(
            "resolve execveat descriptor {}: {error}",
            host_path.display()
        )
    })?;
    let relative = path
        .strip_prefix(&root)
        .or_else(|_| path.strip_prefix("/"))
        .map_err(|_| {
            format!(
                "execveat descriptor resolves outside guest rootfs: {}",
                path.display()
            )
        })?;
    let mut guest_path = OsString::from("/");
    guest_path.push(relative.as_os_str());
    Ok(guest_path)
}

fn resolve_guest_exec_target(
    rootfs: &Path,
    operation: GuestExecOperation,
    guest_path: &OsStr,
) -> Result<OsString, String> {
    match operation {
        GuestExecOperation::Execve => Ok(guest_path.to_os_string()),
        GuestExecOperation::Execveat { dirfd, flags }
            if flags & AT_EMPTY_PATH != 0 && guest_path.as_bytes().is_empty() =>
        {
            let descriptor = PathBuf::from(format!("/proc/self/fd/{dirfd}"));
            let target = std::fs::read_link(&descriptor).map_err(|error| {
                format!("read execveat AT_EMPTY_PATH descriptor {dirfd}: {error}")
            })?;
            guest_path_from_host_path(rootfs, &target)
        }
        GuestExecOperation::Execveat { .. } if guest_path.as_bytes().starts_with(b"/") => {
            // Linux ignores dirfd for an absolute pathname, even when the
            // descriptor is invalid.  Do not touch /proc/self/fd in this
            // case; doing so would turn a valid absolute exec into a false
            // preflight failure.
            Ok(guest_path.to_os_string())
        }
        GuestExecOperation::Execveat { dirfd, .. } if dirfd != AT_FDCWD => {
            // Native guest descriptors are backed by host descriptors in
            // QEMU linux-user, so /proc/self/fd gives us the directory that
            // the guest kernel would use for a relative pathname.  Virtual
            // pseudo-fds have no host entry and intentionally fall back.
            let descriptor = PathBuf::from(format!("/proc/self/fd/{dirfd}"));
            let target = std::fs::read_link(&descriptor)
                .map_err(|error| format!("read execveat dirfd {dirfd}: {error}"))?;
            let directory = guest_path_from_host_path(rootfs, &target)?;
            Ok(Path::new(&directory)
                .join(Path::new(guest_path))
                .into_os_string())
        }
        GuestExecOperation::Execveat { .. } => Ok(guest_path.to_os_string()),
    }
}

#[derive(Clone, Debug)]
struct GuestExecLoadPlan {
    /// Guest pathname passed to the new QEMU image.  For a shebang script
    /// this is the guest interpreter, because QEMU's initial image loader
    /// does not reliably implement the foreign-kernel script fallback.
    binary_path: OsString,
    /// Guest argv for that image.  A script receives the kernel-equivalent
    /// `[interpreter, optional-arg, script, original-argv[1..]]` vector.
    argv: Vec<CString>,
}

/// Linux permits a script interpreter to be another script, but bounds the
/// recursion so a chain cannot consume unbounded loader state.  Keep the same
/// bound in the host preflight that prepares the child QEMU image.
const MAX_GUEST_SHEBANG_RECURSION: usize = 4;

fn validate_guest_elf_header(
    class: u8,
    data: u8,
    machine: u16,
    guest_arch: Arch,
    guest_path: &OsStr,
) -> Result<(), String> {
    use goblin::elf::header::{
        ELFCLASS32, ELFCLASS64, ELFDATA2LSB, EM_ARM, EM_MIPS, EM_MIPS_RS3_LE, EM_X86_64,
    };

    let (expected_class, expected_machine, expected_data) = match guest_arch {
        Arch::Arm => (ELFCLASS32, EM_ARM, ELFDATA2LSB),
        Arch::X86_64 => (ELFCLASS64, EM_X86_64, ELFDATA2LSB),
        Arch::Mips => {
            #[cfg(feature = "mipsbe")]
            {
                (ELFCLASS32, EM_MIPS, 2)
            }
            #[cfg(not(feature = "mipsbe"))]
            {
                (ELFCLASS32, EM_MIPS, ELFDATA2LSB)
            }
        }
    };
    let machine_matches = machine == expected_machine
        || (matches!(guest_arch, Arch::Mips)
            && expected_data == ELFDATA2LSB
            && machine == EM_MIPS_RS3_LE);
    if class != expected_class || data != expected_data || !machine_matches {
        return Err(format!(
            "guest executable ELF identity does not match {guest_arch:?}: class={} data={} machine={:#x}, expected class={} data={} machine={:#x} at {guest_path:?}",
            class,
            data,
            machine,
            expected_class,
            expected_data,
            expected_machine,
        ));
    }
    Ok(())
}

fn validate_guest_elf_for_arch(
    rootfs: &Path,
    guest_path: &OsStr,
    guest_arch: Option<Arch>,
) -> Result<(), String> {
    // Host re-exec is only safe after the guest kernel's basic exec checks
    // have passed.  Otherwise an absent/non-ELF image would replace the
    // current harness and fail later, instead of returning errno to the
    // calling guest image as execve requires.
    let resolved = resolve_guest_exec_path(rootfs, guest_path)?;
    let metadata = std::fs::metadata(&resolved)
        .map_err(|error| format!("stat guest executable {guest_path:?}: {error}"))?;
    if !metadata.is_file() {
        return Err(format!(
            "guest executable is not a regular file: {guest_path:?}"
        ));
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!(
            "guest executable has no execute permission: {guest_path:?}"
        ));
    }
    let bytes = std::fs::read(&resolved)
        .map_err(|error| format!("read guest executable {guest_path:?}: {error}"))?;
    let elf = goblin::elf::Elf::parse(&bytes)
        .map_err(|error| format!("guest executable is not a supported ELF: {error}"))?;
    if let Some(guest_arch) = guest_arch {
        validate_guest_elf_header(
            elf.header.e_ident[goblin::elf::header::EI_CLASS],
            elf.header.e_ident[goblin::elf::header::EI_DATA],
            elf.header.e_machine,
            guest_arch,
            guest_path,
        )?;
    }
    if let Some(interpreter) = elf.interpreter {
        let interpreter_path = resolve_guest_exec_path(rootfs, OsStr::new(interpreter))?;
        let interpreter_metadata = std::fs::metadata(&interpreter_path)
            .map_err(|error| format!("stat guest ELF interpreter {interpreter:?}: {error}"))?;
        if !interpreter_metadata.is_file() {
            return Err(format!(
                "guest ELF interpreter is not a regular file: {interpreter:?}"
            ));
        }
        if interpreter_metadata.permissions().mode() & 0o111 == 0 {
            return Err(format!(
                "guest ELF interpreter has no execute permission: {interpreter:?}"
            ));
        }
        let interpreter_bytes = std::fs::read(&interpreter_path)
            .map_err(|error| format!("read guest ELF interpreter {interpreter:?}: {error}"))?;
        let interpreter_elf = goblin::elf::Elf::parse(&interpreter_bytes)
            .map_err(|error| format!("guest ELF interpreter is not a supported ELF: {error}"))?;
        if let Some(guest_arch) = guest_arch {
            validate_guest_elf_header(
                interpreter_elf.header.e_ident[goblin::elf::header::EI_CLASS],
                interpreter_elf.header.e_ident[goblin::elf::header::EI_DATA],
                interpreter_elf.header.e_machine,
                guest_arch,
                OsStr::new(interpreter),
            )?;
        }
    }
    Ok(())
}

fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !byte.is_ascii_whitespace())
        .map(|index| index + 1)
        .unwrap_or(start);
    &bytes[start..end]
}

fn parse_guest_shebang(bytes: &[u8]) -> Result<Option<(OsString, Option<OsString>)>, String> {
    if !bytes.starts_with(b"#!") {
        return Ok(None);
    }
    let line_end = bytes[2..]
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|offset| offset + 2)
        .unwrap_or(bytes.len());
    let line = bytes[2..line_end]
        .strip_suffix(b"\r")
        .unwrap_or(&bytes[2..line_end]);
    let line = trim_ascii_whitespace(line);
    let split = line
        .iter()
        .position(|byte| byte.is_ascii_whitespace())
        .unwrap_or(line.len());
    let interpreter = &line[..split];
    if interpreter.is_empty() {
        return Err("guest shebang has no interpreter".to_owned());
    }
    if !interpreter.starts_with(b"/") {
        return Err(format!(
            "guest shebang interpreter is not an absolute path: {:?}",
            String::from_utf8_lossy(interpreter)
        ));
    }
    let optional_arg = trim_ascii_whitespace(&line[split..]);
    let optional_arg =
        (!optional_arg.is_empty()).then(|| OsString::from_vec(optional_arg.to_vec()));
    Ok(Some((
        OsString::from_vec(interpreter.to_vec()),
        optional_arg,
    )))
}

fn prepend_guest_shebang_argv(
    interpreter: &OsStr,
    optional_arg: Option<&OsStr>,
    script_path: &OsStr,
    guest_argv: &[CString],
) -> Result<Vec<CString>, String> {
    let mut argv = Vec::with_capacity(3 + guest_argv.len());
    argv.push(
        CString::new(interpreter.as_bytes())
            .map_err(|_| "guest shebang interpreter contains NUL".to_owned())?,
    );
    if let Some(optional_arg) = optional_arg {
        argv.push(
            CString::new(optional_arg.as_bytes())
                .map_err(|_| "guest shebang argument contains NUL".to_owned())?,
        );
    }
    argv.push(
        CString::new(script_path.as_bytes())
            .map_err(|_| "guest script path contains NUL".to_owned())?,
    );
    argv.extend(guest_argv.iter().skip(1).cloned());
    Ok(argv)
}

fn build_guest_exec_plan(
    rootfs: &Path,
    guest_path: &OsStr,
    guest_argv: &[CString],
    shebang_depth: usize,
    guest_arch: Option<Arch>,
) -> Result<GuestExecLoadPlan, String> {
    let resolved = resolve_guest_exec_path(rootfs, guest_path)?;
    let metadata = std::fs::metadata(&resolved)
        .map_err(|error| format!("stat guest executable {guest_path:?}: {error}"))?;
    if !metadata.is_file() {
        return Err(format!(
            "guest executable is not a regular file: {guest_path:?}"
        ));
    }
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!(
            "guest executable has no execute permission: {guest_path:?}"
        ));
    }
    let bytes = std::fs::read(&resolved)
        .map_err(|error| format!("read guest executable {guest_path:?}: {error}"))?;
    match goblin::elf::Elf::parse(&bytes) {
        Ok(_) => {
            validate_guest_elf_for_arch(rootfs, guest_path, guest_arch)?;
            Ok(GuestExecLoadPlan {
                binary_path: guest_path.to_os_string(),
                argv: guest_argv.to_vec(),
            })
        }
        Err(elf_error) => {
            let Some((interpreter, optional_arg)) = parse_guest_shebang(&bytes)? else {
                return Err(format!(
                    "guest executable is not a supported ELF or shebang script: {elf_error}"
                ));
            };
            if shebang_depth >= MAX_GUEST_SHEBANG_RECURSION {
                return Err(format!(
                    "guest shebang recursion exceeds {MAX_GUEST_SHEBANG_RECURSION} levels at {guest_path:?}"
                ));
            }
            let argv = prepend_guest_shebang_argv(
                &interpreter,
                optional_arg.as_deref(),
                guest_path,
                guest_argv,
            )?;
            build_guest_exec_plan(rootfs, &interpreter, &argv, shebang_depth + 1, guest_arch)
                .map_err(|error| {
                    format!("guest shebang interpreter {interpreter:?} is unavailable: {error}")
                })
        }
    }
}

fn validate_guest_exec(
    rootfs: &Path,
    operation: GuestExecOperation,
    guest_path: &OsStr,
    guest_argv: &[CString],
    guest_arch: Arch,
) -> Result<GuestExecLoadPlan, String> {
    let target_path = resolve_guest_exec_target(rootfs, operation, guest_path)?;
    if matches!(operation, GuestExecOperation::Execveat { flags, .. } if flags & AT_SYMLINK_NOFOLLOW != 0)
        && !guest_path.as_bytes().is_empty()
    {
        reject_final_symlink(rootfs, &target_path)?;
    }
    build_guest_exec_plan(rootfs, &target_path, guest_argv, 0, Some(guest_arch))
}

/// Mark a host-harness re-exec as having reached the child harness.
///
/// The parent writes a `requested` transition before calling host `execve`.
/// This marker is deliberately separate from QEMU startup: a parser/loader
/// failure remains `requested`, while a child that reaches `main` is visible
/// as `started` even if guest loading fails afterwards.
pub fn mark_guest_exec_transition_started() {
    let Some(path) = std::env::var_os("FMST_EXEC_TRANSITION") else {
        return;
    };
    let path = PathBuf::from(path);
    if let Err(error) = update_transition_record(&path, "started", None, true, false) {
        log::warn!("failed to mark guest exec transition started: {error}");
    }
}

/// A replacement harness must not send host startup errors to its inherited
/// guest stderr (which can already be a response pipe).
pub fn mark_guest_exec_diagnostics_failed(error: &str) {
    if let Some(path) = std::env::var_os("FMST_EXEC_TRANSITION") {
        fail_guest_exec_transition(
            Some(Path::new(&path)),
            "diagnostic-startup",
            error.to_owned(),
        );
    } else {
        eprintln!("cannot initialize harness diagnostics: {error}");
    }
}

fn trampoline_guest_exec(
    ctx: &mut dyn fmst_iib_api::context::IIBContextOps,
    vfs: &mut VirtualFdTable,
    pathname: fmst_iib_api::types::GuestAddr,
    argv: fmst_iib_api::types::GuestAddr,
    envp: fmst_iib_api::types::GuestAddr,
    word_bits: u8,
    config: &GuestExecConfig,
    operation: GuestExecOperation,
    guest_arch: Arch,
) -> Result<(), GuestExecError> {
    let depth = std::env::var("FMST_EXEC_DEPTH")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0)
        .saturating_add(1);
    let fork_pid = crate::runtime_trace::trace_origin_pid()
        .filter(|origin_pid| *origin_pid != std::process::id())
        .map(|_| std::process::id());
    let child_trace_path = config
        .trace_output
        .as_ref()
        .map(|trace| exec_artifact_path_for_pid(trace, depth, "", fork_pid));
    let transition_path = config
        .trace_output
        .as_ref()
        .map(|trace| trace_transition_path_for_pid(trace, depth, fork_pid));
    let transition_id = format!("exec-{}-{depth}", std::process::id());
    let handoff_candidate = config
        .trace_output
        .as_ref()
        .map(|trace| exec_artifact_path_for_pid(trace, depth, ".vfd-handoff", fork_pid))
        .unwrap_or_else(|| {
            std::env::temp_dir().join(format!(
                "fmst-iib-vfd-handoff-{}-{depth}.json",
                std::process::id()
            ))
        });
    // Persist a transition even when the guest supplied an unreadable path,
    // argv vector, or environment vector.  These failures are useful runtime
    // evidence and must not disappear before the normal preflight record is
    // created.
    let guest_path_result = ctx
        .read_cstr(pathname, 4096)
        .map_err(|error| format!("read exec path: {error:?}"));
    let mut guest_string_bytes = 0usize;
    let guest_argv_result = if argv == 0 {
        Err("exec argument vector pointer is NULL".to_owned())
    } else {
        read_guest_vector(ctx, argv, word_bits, &mut guest_string_bytes)
    };
    // A NULL envp is valid execve input and means an empty environment.  Keep
    // this bit separate from an envp vector containing only its terminating
    // NULL so the child harness can explicitly unset its inherited host env.
    let guest_env_is_null = envp == 0;
    let guest_env_result = read_guest_vector(ctx, envp, word_bits, &mut guest_string_bytes);
    let request = ExecRequestRecord {
        operation: operation.operation_name().to_owned(),
        dirfd: operation.dirfd(),
        flags: operation.flags(),
        pathname: guest_path_result
            .as_ref()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "<unreadable>".to_owned()),
        pathname_bytes_hex: guest_path_result
            .as_ref()
            .map(|value| bytes_hex(value.as_bytes()))
            .unwrap_or_default(),
        argv: guest_argv_result
            .as_ref()
            .map(|values| {
                values
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default(),
        argv_bytes_hex: guest_argv_result
            .as_ref()
            .map(|values| {
                values
                    .iter()
                    .map(|value| bytes_hex(value.as_bytes()))
                    .collect()
            })
            .unwrap_or_default(),
        environment: guest_env_result
            .as_ref()
            .map(|values| {
                values
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default(),
        environment_bytes_hex: guest_env_result
            .as_ref()
            .map(|values| {
                values
                    .iter()
                    .map(|value| bytes_hex(value.as_bytes()))
                    .collect()
            })
            .unwrap_or_default(),
        cwd: std::env::current_dir()
            .map(|value| value.to_string_lossy().into_owned())
            .unwrap_or_else(|error| format!("<unavailable: {error}>")),
        string_encoding: "lossy_utf8_with_raw_bytes_hex",
    };
    let input_error = guest_path_result
        .as_ref()
        .err()
        .cloned()
        .or_else(|| guest_argv_result.as_ref().err().cloned())
        .or_else(|| guest_env_result.as_ref().err().cloned());
    if let Some(path) = &transition_path {
        let record = ExecTransitionRecord {
            schema_version: 3,
            transition_id: transition_id.clone(),
            status: "requested".to_owned(),
            host_pid: std::process::id(),
            parent_trace: config
                .trace_output
                .as_ref()
                .map(|value| value.to_string_lossy().into_owned()),
            child_trace: child_trace_path
                .as_ref()
                .map(|value| value.to_string_lossy().into_owned()),
            request,
            harness_path: config.harness_path.to_string_lossy().into_owned(),
            host_loader: config
                .host_loader
                .as_ref()
                .map(|value| value.to_string_lossy().into_owned()),
            rootfs: config.rootfs.to_string_lossy().into_owned(),
            requested_unix_ns: unix_time_ns(),
            virtual_fd_handoff: None,
            started_unix_ns: None,
            failed_unix_ns: None,
            error: None,
        };
        if let Err(error) = write_json_atomic(path, &record) {
            log::warn!("failed to persist guest exec transition: {error}");
        } else {
            crate::runtime_trace::record_runtime_state_event(
                "exec_transition_requested",
                format!("{transition_id}; record={}", path.display()),
            );
        }
    }
    if let Some(error) = input_error {
        fail_guest_exec_transition(transition_path.as_deref(), &transition_id, error.clone());
        return Err(GuestExecError::Fallback(error));
    }
    let guest_path = guest_path_result.expect("guest path result checked above");
    let guest_path = OsString::from_vec(guest_path.as_bytes().to_vec());
    let guest_argv = guest_argv_result.expect("guest argv result checked above");
    let guest_env = guest_env_result.expect("guest env result checked above");
    // Linux pathnames are arbitrary non-NUL byte strings.  Keep the original
    // bytes for host Path operations and only use lossy text in diagnostics.
    let load_plan = if let Some(error) = operation.preflight_error(&guest_path) {
        Err(error)
    } else {
        validate_guest_exec(
            &config.rootfs,
            operation,
            &guest_path,
            &guest_argv,
            guest_arch,
        )
    };

    let load_plan = match load_plan {
        Ok(plan) => plan,
        Err(error) => {
            let error = format!("guest exec preflight failed: {error}");
            fail_guest_exec_transition(transition_path.as_deref(), &transition_id, error.clone());
            return Err(GuestExecError::Fallback(error));
        }
    };
    // Validate before persisting either launch parameters or OFD state.
    let mut guest_env_names = std::collections::HashSet::new();
    for value in &guest_env {
        let bytes = value.as_bytes();
        let Some(separator) = bytes.iter().position(|byte| *byte == b'=') else {
            let error = "guest environment entry has no '='".to_owned();
            fail_guest_exec_transition(transition_path.as_deref(), &transition_id, error.clone());
            return Err(GuestExecError::Fallback(error));
        };
        let name = &bytes[..separator];
        if name.is_empty() || !guest_env_names.insert(name.to_vec()) {
            let error = "guest environment contains an empty or duplicate name".to_owned();
            fail_guest_exec_transition(transition_path.as_deref(), &transition_id, error.clone());
            return Err(GuestExecError::Fallback(error));
        }
    }
    let guest_unset = std::env::vars_os()
        .map(|(name, _)| name)
        .filter(|name| guest_env_is_null || !guest_env_names.contains(name.as_bytes()))
        .collect::<Vec<_>>();
    let mut harness_args = vec![config.harness_path.as_os_str().as_bytes().to_vec()];
    if let Some(worker_args) = &config.worker_args {
        harness_args.extend(worker_args.iter().map(|s| s.as_bytes().to_vec()));
    } else {
        // Only this compatibility adapter knows the historical CLI options.
        if let Some(intervention) = &config.intervention_so {
            harness_args.push(b"--intervention-so".to_vec());
            harness_args.push(intervention.as_os_str().as_bytes().to_vec());
        } else {
            harness_args.push(b"--trace-only".to_vec());
        }
        if let Some(loader) = &config.host_loader {
            harness_args.push(b"--host-loader".to_vec());
            harness_args.push(loader.as_os_str().as_bytes().to_vec());
        }
        harness_args.push(b"--harness-path".to_vec());
        harness_args.push(config.harness_path.as_os_str().as_bytes().to_vec());
        harness_args.push(b"--binary".to_vec());
        harness_args.push(load_plan.binary_path.as_bytes().to_vec());
        harness_args.push(b"--rootfs".to_vec());
        harness_args.push(config.rootfs.as_os_str().as_bytes().to_vec());
        if let Some(path) = &child_trace_path {
            harness_args.push(b"--trace-output".to_vec());
            harness_args.push(path.as_os_str().as_bytes().to_vec());
        }
        for value in &guest_env {
            harness_args.push(b"--guest-env".to_vec());
            harness_args.push(value.as_bytes().to_vec());
        }
        for name in &guest_unset {
            harness_args.push(b"--guest-unset".to_vec());
            harness_args.push(name.as_bytes().to_vec());
        }
        if let Some(argv0) = load_plan.argv.first() {
            let mut option = b"--guest-argv0=".to_vec();
            option.extend_from_slice(argv0.as_bytes());
            harness_args.push(option);
        }
        harness_args.push(b"--".to_vec());
        harness_args.extend(load_plan.argv.iter().skip(1).map(|s| s.as_bytes().to_vec()));
    }
    // Prepare the virtual-fd handoff only after all guest arguments and
    // environment entries have passed validation.  A fallback before this
    // point must not leave an orphaned handoff artifact behind.
    let handoff_path = match vfs.prepare_exec_handoff(&handoff_candidate) {
        Ok(true) => {
            if let Some(path) = &transition_path {
                if let Err(error) = update_transition_virtual_fd_handoff(path, &handoff_candidate) {
                    let message = format!("persist virtual fd handoff reference: {error}");
                    fail_guest_exec_transition(Some(path), &transition_id, message.clone());
                    let _ = std::fs::remove_file(&handoff_candidate);
                    return Err(GuestExecError::Reject(message));
                }
            }
            Some(handoff_candidate)
        }
        Ok(false) => None,
        Err(error) => {
            let message = format!("virtual fd exec handoff unavailable: {error}");
            fail_guest_exec_transition(transition_path.as_deref(), &transition_id, message.clone());
            let _ = std::fs::remove_file(&handoff_candidate);
            return Err(GuestExecError::Reject(message));
        }
    };
    let launch_handoff = if config.worker_args.is_some() {
        // Retain failed launch inputs without colliding with a later retry
        // of exec at the same process/depth.
        let stamp = unix_time_ns();
        let path = config
            .trace_output
            .as_ref()
            .map(|trace| {
                exec_artifact_path_for_pid(trace, depth, &format!(".run-handoff-{stamp}"), fork_pid)
            })
            .unwrap_or_else(|| {
                std::env::temp_dir().join(format!(
                    "guestweave-run-handoff-{}-{depth}-{stamp}.json",
                    std::process::id()
                ))
            });
        let resume = crate::exec_resume::Resume::new(
            config,
            &load_plan.binary_path,
            &load_plan.argv,
            &guest_env,
            &guest_unset,
            child_trace_path.as_deref(),
        );
        let result = resume.write(&path).and_then(|()| {
            if let Some(transition) = &transition_path {
                let bytes = std::fs::read(transition).map_err(|e| e.to_string())?;
                let mut value: serde_json::Value =
                    serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
                value["worker_launch_handoff"] =
                    serde_json::Value::String(path.to_string_lossy().into_owned());
                write_json_atomic(transition, &value)?;
            }
            Ok(())
        });
        if let Err(error) = result {
            fail_guest_exec_transition(transition_path.as_deref(), &transition_id, error.clone());
            return Err(GuestExecError::Reject(error));
        }
        Some(path)
    } else {
        None
    };
    // The outer Docker command uses the explicit loader because the staged
    // firmware rootfs has no host interpreter.  Once inside the harness,
    // invoking that loader as the *program* would make glibc reject the
    // nested image with "loader cannot load itself".  The sandbox therefore
    // mounts the same loader at the host ELF's PT_INTERP path and exports its
    // library directory; a direct execve of the harness lets the kernel load
    // that interpreter normally and preserves the process boundary.
    let argv = harness_args;
    let executable = CString::new(argv.first().cloned().unwrap_or_default())
        .map_err(|_| "host exec path contains NUL".to_owned())?;
    let argv_c = argv
        .iter()
        .map(|value| {
            CString::new(value.as_slice()).map_err(|_| "host argv contains NUL".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv_p = argv_c
        .iter()
        .map(|value| value.as_ptr())
        .collect::<Vec<_>>();
    argv_p.push(std::ptr::null());

    let depth = std::env::var("FMST_EXEC_DEPTH")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0)
        .saturating_add(1)
        .to_string();
    let mut env_c = std::env::vars_os()
        .filter_map(|(key, value)| {
            if key == "FMST_EXEC_DEPTH"
                || key == "FMST_EXEC_TRANSITION"
                || key == "FMST_EXEC_HANDOFF"
                || key == crate::exec_resume::ENV
                || (config.host_library_path.is_some() && key == "LD_LIBRARY_PATH")
            {
                None
            } else {
                let mut bytes = key.as_os_str().as_bytes().to_vec();
                bytes.push(b'=');
                bytes.extend_from_slice(value.as_os_str().as_bytes());
                Some(CString::new(bytes).ok())
            }
        })
        .flatten()
        .collect::<Vec<_>>();
    if let Some(library_path) = &config.host_library_path {
        env_c.push(
            CString::new({
                let mut bytes = b"LD_LIBRARY_PATH=".to_vec();
                bytes.extend_from_slice(library_path.as_os_str().as_bytes());
                bytes
            })
            .map_err(|_| "host library path contains NUL".to_owned())?,
        );
    }
    env_c.push(CString::new(format!("FMST_EXEC_DEPTH={depth}")).unwrap());
    if let Some(path) = &transition_path {
        env_c.push(
            CString::new({
                let mut bytes = b"FMST_EXEC_TRANSITION=".to_vec();
                bytes.extend_from_slice(path.as_os_str().as_bytes());
                bytes
            })
            .map_err(|_| "transition path contains NUL".to_owned())?,
        );
    }
    if let Some(path) = &handoff_path {
        env_c.push(
            CString::new({
                let mut bytes = b"FMST_EXEC_HANDOFF=".to_vec();
                bytes.extend_from_slice(path.as_os_str().as_bytes());
                bytes
            })
            .map_err(|_| "virtual fd handoff path contains NUL".to_owned())?,
        );
    }
    if let Some(path) = &launch_handoff {
        let mut bytes = format!("{}=", crate::exec_resume::ENV).into_bytes();
        bytes.extend_from_slice(path.as_os_str().as_bytes());
        env_c.push(CString::new(bytes).map_err(|_| "worker launch path contains NUL".to_owned())?);
    }
    let mut env_p = env_c.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
    env_p.push(std::ptr::null());

    // A successful host exec never returns or runs destructors. Preserve the
    // parent image's events even when it executes before the next checkpoint.
    crate::runtime_trace::flush_runtime_trace();
    let result = unsafe { libc::execve(executable.as_ptr(), argv_p.as_ptr(), env_p.as_ptr()) };
    debug_assert_eq!(result, -1);
    let error = std::io::Error::last_os_error().to_string();
    // The failed transition still references the prepared OFD state; retain
    // it for diagnosis instead of leaving a dangling evidence pointer.
    fail_guest_exec_transition(transition_path.as_deref(), &transition_id, error.clone());
    Err(GuestExecError::Fallback(error))
}

/// Apply VFS state changes that are valid only after a host syscall succeeds.
fn complete_syscall_via_vfs<ET, I, S>(
    emulator_modules: &mut EmulatorModules<ET, I, S>,
    result: GuestUlong,
    sys_num: i32,
) -> GuestUlong
where
    ET: EmulatorModuleTuple<I, S>,
    I: Unpin + 'static,
    S: Unpin + 'static,
{
    if (sys_num == crate::vfs::syscall_no::EXECVE || sys_num == crate::vfs::syscall_no::EXECVEAT)
        && syscall_result_succeeded(result)
    {
        if let Some(module) = emulator_modules.get_mut::<IIBModule>() {
            module.vfs.close_on_exec();
        }
    }
    result
}

fn syscall_result_succeeded(result: GuestUlong) -> bool {
    #[cfg(feature = "x86_64")]
    return (result as i64) >= 0;
    #[cfg(not(feature = "x86_64"))]
    return (result as u32 as i32) >= 0;
}

#[cfg(test)]
mod exec_artifact_tests {
    use super::*;

    #[test]
    fn exec_request_raw_bytes_use_stable_hex() {
        assert_eq!(bytes_hex(b"A\xffB"), "41ff42");
    }

    #[test]
    fn guest_exec_byte_budget_is_checked_before_handoff() {
        let mut used = MAX_GUEST_EXEC_BYTES - 1;
        assert!(account_guest_exec_bytes(&mut used, 1).is_ok());
        assert!(account_guest_exec_bytes(&mut used, 1).is_err());
    }

    #[test]
    fn guest_exec_string_budget_matches_linux_max_arg_strlen() {
        assert_eq!(MAX_GUEST_EXEC_STRING_BYTES, 32 * 4096);
        assert!(MAX_GUEST_EXEC_STRING_BYTES < MAX_GUEST_EXEC_BYTES);
    }

    #[test]
    fn repeated_exec_artifacts_keep_a_flat_name() {
        let root = Path::new("/tmp/runtime/trace.json");
        let first = exec_artifact_path_for_pid(root, 1, "", None);
        let second = exec_artifact_path_for_pid(&first, 2, "", None);
        let transition = exec_artifact_path_for_pid(&second, 3, ".transition", None);
        let handoff = exec_artifact_path_for_pid(&second, 3, ".vfd-handoff", None);

        assert_eq!(first, Path::new("/tmp/runtime/trace.exec-1.json"));
        assert_eq!(second, Path::new("/tmp/runtime/trace.exec-2.json"));
        assert_eq!(
            transition,
            Path::new("/tmp/runtime/trace.exec-3.transition.json")
        );
        assert_eq!(
            handoff,
            Path::new("/tmp/runtime/trace.exec-3.vfd-handoff.json")
        );
    }

    #[test]
    fn forked_exec_artifacts_keep_pid_lineage_without_colliding() {
        let root = Path::new("/tmp/runtime/trace.json");
        let first = exec_artifact_path_for_pid(root, 1, "", Some(4242));
        assert_eq!(first, Path::new("/tmp/runtime/trace.exec-1.pid-4242.json"));

        let second = exec_artifact_path_for_pid(&first, 2, "", None);
        assert_eq!(second, Path::new("/tmp/runtime/trace.exec-2.pid-4242.json"));
        let transition = trace_transition_path_for_pid(&first, 3, None);
        assert_eq!(
            transition,
            Path::new("/tmp/runtime/trace.exec-3.pid-4242.transition.json")
        );
    }

    #[test]
    fn non_numeric_exec_suffix_is_not_stripped() {
        let path =
            exec_artifact_path_for_pid(Path::new("/tmp/trace.exec-custom.json"), 2, "", None);
        assert_eq!(path, Path::new("/tmp/trace.exec-custom.exec-2.json"));
    }

    #[test]
    fn missing_hook_target_is_fatal_only_for_initial_image() {
        let target = ModuleTargetStatic {
            binary: "child-only",
            offset: 0x10,
            symbol_hint: None,
        };
        let map = std::collections::HashMap::new();

        let initial = resolve_hook_target(&target, &map, ImageExecutionKind::Initial);
        assert!(initial
            .unwrap_err()
            .contains("initial image does not contain required target binary"));

        let post_exec =
            resolve_hook_target(&target, &map, ImageExecutionKind::PostExec { depth: 1 }).unwrap();
        assert_eq!(post_exec, None);
    }

    #[test]
    fn hook_and_resume_offsets_use_checked_guest_address_arithmetic() {
        let target = ModuleTargetStatic {
            binary: "service",
            offset: u64::MAX,
            symbol_hint: None,
        };
        let map = std::collections::HashMap::from([(String::from("service"), Ok(1_u64))]);
        let error = resolve_hook_target(&target, &map, ImageExecutionKind::Initial).unwrap_err();
        assert!(error.contains("IIB-HOOK-ADDRESS-OVERFLOW"));

        let target = ModuleTargetStatic {
            offset: 0x20,
            ..target
        };
        let mut dispatch = DispatchTable::new();
        let error = register_one(
            "resume",
            &target,
            HookFlavor::Call,
            |_| {},
            Some(u64::MAX),
            &map,
            &mut dispatch,
            ImageExecutionKind::Initial,
        )
        .unwrap_err();
        assert!(error.contains("resume base="));
        assert!(dispatch.unique_pcs().next().is_none());
    }

    #[test]
    fn each_image_resolves_its_own_address_and_ambiguity_is_never_a_skip() {
        let target = ModuleTargetStatic {
            binary: "library.so",
            offset: 0x20,
            symbol_hint: None,
        };
        for (kind, base) in [
            (ImageExecutionKind::Initial, 0x1000),
            (ImageExecutionKind::PostExec { depth: 1 }, 0x9000),
        ] {
            let map = HashMap::from([("library.so".to_owned(), Ok(base))]);
            assert_eq!(
                resolve_hook_target(&target, &map, kind).unwrap(),
                Some(base + 0x20)
            );
            let map = HashMap::from([(
                "library.so".to_owned(),
                Err(crate::load_map::LoadMapError::AmbiguousBasename {
                    basename: "library.so".to_owned(),
                    paths: vec!["/a/library.so".to_owned(), "/b/library.so".to_owned()],
                }),
            )]);
            assert!(resolve_hook_target(&target, &map, kind)
                .unwrap_err()
                .contains("IIB-AMBIGUOUS-BINARY"));
        }
    }

    #[test]
    fn execveat_nonempty_path_may_use_at_empty_path_flag() {
        let operation = GuestExecOperation::Execveat {
            dirfd: AT_FDCWD,
            flags: AT_EMPTY_PATH,
        };
        assert!(operation.preflight_error(OsStr::new("/bin/true")).is_none());
        assert!(operation.preflight_error(OsStr::new("bin/true")).is_none());
        assert!(operation.preflight_error(OsStr::new("")).is_some());
    }

    #[test]
    fn execveat_absolute_path_ignores_invalid_dirfd() {
        let operation = GuestExecOperation::Execveat {
            dirfd: 9999,
            flags: 0,
        };
        assert_eq!(
            resolve_guest_exec_target(Path::new("/"), operation, OsStr::new("/bin/true")).unwrap(),
            OsStr::new("/bin/true")
        );
    }

    #[test]
    fn execveat_no_follow_distinguishes_final_symlink_from_regular_file() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("target"), b"fixture").unwrap();
        std::os::unix::fs::symlink("target", root.path().join("link")).unwrap();

        assert!(reject_final_symlink(root.path(), OsStr::new("/target")).is_ok());
        let error = reject_final_symlink(root.path(), OsStr::new("/link")).unwrap_err();
        assert!(error.contains("symbolic link"));
    }

    #[test]
    fn nested_shebang_prepends_each_interpreter_without_losing_original_args() {
        let initial = vec![
            CString::new("/outer").unwrap(),
            CString::new("--request").unwrap(),
            CString::new("value").unwrap(),
        ];
        let inner = prepend_guest_shebang_argv(
            OsStr::new("/inner"),
            Some(OsStr::new("-c")),
            OsStr::new("/outer"),
            &initial,
        )
        .unwrap();
        let final_argv = prepend_guest_shebang_argv(
            OsStr::new("/bin/busybox"),
            None,
            OsStr::new("/inner"),
            &inner,
        )
        .unwrap();
        let values = final_argv
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            values,
            [
                "/bin/busybox",
                "/inner",
                "-c",
                "/outer",
                "--request",
                "value"
            ]
        );
    }

    #[test]
    fn shebang_optional_argument_keeps_internal_whitespace() {
        let parsed = parse_guest_shebang(b"#!/bin/interpreter -x  --flag\n").unwrap();
        assert_eq!(
            parsed,
            Some((
                OsString::from("/bin/interpreter"),
                Some(OsString::from("-x  --flag")),
            ))
        );
    }

    #[test]
    fn non_utf8_guest_path_is_preserved_for_host_preflight() {
        let root = tempfile::tempdir().unwrap();
        let path = OsString::from_vec(b"/bin/target-\xff".to_vec());
        let candidate = root.path().join(OsStr::from_bytes(b"bin/target-\xff"));
        std::fs::create_dir_all(candidate.parent().unwrap()).unwrap();
        std::fs::write(&candidate, b"fixture").unwrap();

        let resolved = resolve_guest_exec_path(root.path(), &path).unwrap();
        assert_eq!(resolved, candidate.canonicalize().unwrap());
        assert_eq!(path.as_bytes(), b"/bin/target-\xff");
    }

    #[test]
    fn repeated_guest_root_separators_stay_inside_rootfs() {
        let root = tempfile::tempdir().unwrap();
        let candidate = root.path().join("bin/target");
        std::fs::create_dir_all(candidate.parent().unwrap()).unwrap();
        std::fs::write(&candidate, b"fixture").unwrap();

        let resolved = resolve_guest_exec_path(root.path(), OsStr::new("///bin/target")).unwrap();
        assert_eq!(resolved, candidate.canonicalize().unwrap());
    }

    #[test]
    fn guest_elf_header_rejects_a_different_qemu_architecture() {
        use goblin::elf::header::{ELFCLASS32, ELFCLASS64, ELFDATA2LSB, EM_ARM, EM_X86_64};

        assert!(validate_guest_elf_header(
            ELFCLASS64,
            ELFDATA2LSB,
            EM_X86_64,
            Arch::X86_64,
            OsStr::new("/program"),
        )
        .is_ok());

        let error = validate_guest_elf_header(
            ELFCLASS32,
            ELFDATA2LSB,
            EM_ARM,
            Arch::X86_64,
            OsStr::new("/program"),
        )
        .unwrap_err();
        assert!(error.contains("does not match X86_64"));
    }

    #[test]
    fn non_utf8_shebang_path_and_optional_argument_keep_raw_bytes() {
        let parsed = parse_guest_shebang(b"#!/bin/interp-\xff -x\xff  --flag\xff\n").unwrap();
        assert_eq!(
            parsed,
            Some((
                OsString::from_vec(b"/bin/interp-\xff".to_vec()),
                Some(OsString::from_vec(b"-x\xff  --flag\xff".to_vec())),
            ))
        );
    }

    #[test]
    fn nested_shebang_chain_has_a_bounded_preflight() {
        let root = tempfile::tempdir().unwrap();
        for index in 0..=MAX_GUEST_SHEBANG_RECURSION {
            let next = index + 1;
            let path = root.path().join(format!("s{index}"));
            std::fs::write(&path, format!("#!/s{next}\n")).unwrap();
            let mut permissions = std::fs::metadata(&path).unwrap().permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&path, permissions).unwrap();
        }
        let argv = vec![CString::new("/s0").unwrap()];
        let error =
            build_guest_exec_plan(root.path(), OsStr::new("/s0"), &argv, 0, None).unwrap_err();
        assert!(error.contains("recursion exceeds 4 levels"));
    }

    #[test]
    fn guest_elf_preflight_rejects_a_non_elf_interpreter() {
        let root = tempfile::tempdir().unwrap();
        let source = std::env::current_exe().unwrap();
        let source_bytes = std::fs::read(&source).unwrap();
        let elf = goblin::elf::Elf::parse(&source_bytes).unwrap();
        let Some(interpreter) = elf.interpreter else {
            return;
        };
        let program = root.path().join("program");
        std::fs::copy(&source, &program).unwrap();
        let mut program_permissions = std::fs::metadata(&program).unwrap().permissions();
        program_permissions.set_mode(0o755);
        std::fs::set_permissions(&program, program_permissions).unwrap();
        let interpreter_path = root
            .path()
            .join(interpreter.strip_prefix('/').unwrap_or(interpreter));
        std::fs::create_dir_all(interpreter_path.parent().unwrap()).unwrap();
        std::fs::write(&interpreter_path, b"not an ELF").unwrap();
        let mut interpreter_permissions =
            std::fs::metadata(&interpreter_path).unwrap().permissions();
        interpreter_permissions.set_mode(0o755);
        std::fs::set_permissions(&interpreter_path, interpreter_permissions).unwrap();

        let error =
            validate_guest_elf_for_arch(root.path(), OsStr::new("/program"), None).unwrap_err();
        assert!(error.contains("guest ELF interpreter is not a supported ELF"));
    }
}

impl std::fmt::Debug for IIBModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IIBModule")
            .field("arch", &self.manifest.arch)
            .field("hook_count", &self.manifest.callsite_hooks.len())
            .field("stub_count", &self.manifest.function_stubs.len())
            .field("pseudo_file_count", &self.manifest.pseudo_files.len())
            .field("load_map_size", &self.load_map.len())
            .finish()
    }
}
