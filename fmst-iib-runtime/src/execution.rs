//! Run an intervention without depending on LibAFL's emulator type plumbing.
//!
//! This backend owns process-global QEMU, signal, environment and diagnostic
//! state. Call [`run`] once, from a dedicated worker process before starting
//! other threads. Guest exit/exec may terminate/replace that process rather
//! than return to Rust. The caller supervises and cancels the worker process.

use crate::guest_environment::prepare_guest_environment;
use crate::manifest_load::{load_and_leak, validate_manifest, LoadError};
use crate::module::{GuestExecConfig, IIBModule};
use crate::runtime_trace::{flush_runtime_trace, record_runtime_state_event, RuntimeTraceModule};
use fmst_iib_api::{manifest::StaticManifest, Arch};
use libafl::{inputs::BytesInput, state::NopState};
use libafl_bolts::tuples::tuple_list;
use libafl_qemu::command::NopCommandManager;
use libafl_qemu::{Emulator, NopEmulatorDriver, NopSnapshotManager, QemuExitReason};
use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use thiserror::Error;

/// How the caller supplies behavior and its image/resource bindings.
/// Static composition needs neither a JSON manifest nor a dynamic library.
pub enum Intervention {
    None,
    Static(&'static StaticManifest),
    /// Versioned plugin packaging; the library stays loaded until exit.
    SharedObject(PathBuf),
}

/// A worker to restart when the guest replaces its image.
/// Use [`Self::current_process`] for direct library consumers, or
/// [`Self::harness`] for the historical harness argument protocol.
#[derive(Clone, Debug)]
pub struct ExecLauncher {
    pub program: PathBuf,
    pub host_loader: Option<PathBuf>,
    pub host_library_path: Option<PathBuf>,
    pub(crate) worker_args: Option<Vec<OsString>>,
}

impl ExecLauncher {
    /// Re-enter this executable with its original worker arguments. Its main
    /// function must register the same Intervention and call `run` again.
    /// The library restores the replacement guest's configuration internally.
    /// Startup code runs again; arbitrary Rust heap state does not survive.
    pub fn current_process() -> std::io::Result<Self> {
        Ok(Self {
            program: std::env::current_exe()?,
            host_loader: None,
            host_library_path: None,
            worker_args: Some(std::env::args_os().skip(1).collect()),
        })
    }

    /// Compatibility adapter. The program must parse the existing harness
    /// options; this mode cannot reconstruct a static Intervention.
    pub fn harness(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            host_loader: None,
            host_library_path: None,
            worker_args: None,
        }
    }
}

/// Configuration for one process-owned guest execution.
pub struct RunConfig {
    pub binary: PathBuf,
    /// QEMU's guest loader prefix, not a chroot or a filesystem sandbox.
    pub rootfs: PathBuf,
    pub intervention: Intervention,
    pub args: Vec<OsString>,
    /// Non-empty entries replace the inherited guest environment. Empty keeps
    /// the worker's baseline, as in the existing harness handoff protocol.
    pub env: Vec<OsString>,
    pub unset_env: Vec<OsString>,
    pub argv0: Option<OsString>,
    /// Bounded raw trace/load-map output. Does not imply scenario success.
    pub trace_output: Option<PathBuf>,
    pub syscall_trace: bool,
    /// Without a launcher, execve/execveat return ENOSYS with an evidence event;
    /// they must not replace the worker with an uninstrumented host program.
    pub exec: Option<ExecLauncher>,
}

impl RunConfig {
    pub fn new(binary: impl Into<PathBuf>, rootfs: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            rootfs: rootfs.into(),
            intervention: Intervention::None,
            args: Vec::new(),
            env: Vec::new(),
            unset_env: Vec::new(),
            argv0: None,
            trace_output: None,
            syscall_trace: false,
            exec: None,
        }
    }

    fn validate(&self) -> Result<(), RunError> {
        // Unlike argv supplied by the OS, a Rust caller can construct an
        // OsString containing NUL. Reject it before native conversion or
        // process-environment staging, without logging environment contents.
        let mut values = vec![self.binary.as_os_str(), self.rootfs.as_os_str()];
        values.extend(self.args.iter().map(|s| s.as_os_str()));
        values.extend(self.env.iter().map(|s| s.as_os_str()));
        values.extend(self.unset_env.iter().map(|s| s.as_os_str()));
        values.extend(self.argv0.iter().map(|s| s.as_os_str()));
        values.extend(self.trace_output.iter().map(|s| s.as_os_str()));
        if let Intervention::SharedObject(path) = &self.intervention {
            values.push(path.as_os_str());
        }
        if let Some(launcher) = &self.exec {
            values.push(launcher.program.as_os_str());
            values.extend(launcher.host_loader.iter().map(|s| s.as_os_str()));
            values.extend(launcher.host_library_path.iter().map(|s| s.as_os_str()));
            if let Some(args) = &launcher.worker_args {
                values.extend(args.iter().map(|s| s.as_os_str()));
            }
        }
        if values.iter().any(|value| value.as_bytes().contains(&0)) {
            return Err(RunError::Configuration(
                "path, argument or environment contains NUL".into(),
            ));
        }
        if let Intervention::Static(manifest) = &self.intervention {
            validate_manifest(manifest, compiled_arch())?;
            if self
                .exec
                .as_ref()
                .is_some_and(|exec| exec.worker_args.is_none())
            {
                return Err(RunError::Configuration(
                    "the exec launcher cannot reconstruct a statically linked intervention".into(),
                ));
            }
        }
        Ok(())
    }
}

/// A backend shutdown returned control to Rust. This is not a guest exit code
/// or a successful application scenario; ordinary Linux exit may never return.
#[derive(Debug)]
pub struct RunOutcome {
    pub shutdown_cause: String,
}

#[derive(Debug, Error)]
pub enum RunError {
    #[error("invalid run configuration: {0}")]
    Configuration(String),
    #[error(transparent)]
    Manifest(#[from] LoadError),
    #[error("runtime already started in this process; use a new worker process")]
    AlreadyStarted,
    #[error("diagnostic initialization failed: {0}")]
    Diagnostics(#[source] std::io::Error),
    #[error("guest environment cannot be staged: {0}")]
    Environment(String),
    #[error("emulator initialization failed: {0}")]
    Initialization(String),
    #[error("hook dispatch failed: {0}")]
    Dispatch(String),
    #[error("guest execution failed: {0}")]
    Execution(String),
    #[error("unhandled backend stop: {0}")]
    UnhandledStop(String),
}

static STARTED: AtomicBool = AtomicBool::new(false);

/// The architecture selected at compile time (MIPS endianness is a feature).
pub fn compiled_arch() -> Arch {
    #[cfg(feature = "arm")]
    return Arch::Arm;
    #[cfg(any(feature = "mips", feature = "mipsbe"))]
    return Arch::Mips;
    #[cfg(feature = "x86_64")]
    return Arch::X86_64;
}

fn exit_syscalls(arch: Arch) -> &'static [i32] {
    match arch {
        Arch::Arm => &[1, 248],
        Arch::Mips => &[4001, 4246],
        Arch::X86_64 => &[60, 231],
    }
}

fn qemu_arguments(
    config: &RunConfig,
    arch: Arch,
    unset: &[OsString],
    guest_log_filename: Option<Vec<u8>>,
) -> Vec<Vec<u8>> {
    let mut args = vec![b"guestweave".to_vec()];
    match arch {
        Arch::Arm => args.extend([b"-R".to_vec(), b"4G".to_vec()]),
        Arch::Mips => args.extend([b"-R".to_vec(), b"2G".to_vec()]),
        Arch::X86_64 => {}
    }
    if config.syscall_trace {
        args.push(b"-strace".to_vec());
    }
    args.extend([
        b"-L".to_vec(),
        config.rootfs.as_os_str().as_bytes().to_vec(),
    ]);
    for name in unset {
        args.extend([b"-U".to_vec(), name.as_bytes().to_vec()]);
    }
    // These host transport keys can first appear in the replacement worker,
    // after the parent computed guest_unset. Never leak them into a NULL or
    // empty guest envp on the first exec.
    for name in [
        "FMST_EXEC_HANDOFF",
        "FMST_EXEC_DEPTH",
        "FMST_EXEC_TRANSITION",
        crate::exec_resume::ENV,
    ] {
        args.extend([b"-U".to_vec(), name.as_bytes().to_vec()]);
    }
    if let Some(value) = guest_log_filename {
        args.extend([b"-E".to_vec(), value]);
    }
    if let Some(value) = &config.argv0 {
        args.extend([b"-0".to_vec(), value.as_bytes().to_vec()]);
    }
    args.push(config.binary.as_os_str().as_bytes().to_vec());
    args.extend(config.args.iter().map(|s| s.as_bytes().to_vec()));
    args
}

/// Initialize the backend, install bindings and drive guest execution.
///
/// No CLI parser, Agent, Docker or Firmenstein dependency is involved. Errors
/// discovered here are returned, but the current backend also has fatal native
/// startup/guest exit paths. Always supervise the worker process externally.
pub fn run(mut config: RunConfig) -> Result<RunOutcome, RunError> {
    if let Err(error) = crate::exec_resume::restore(&mut config) {
        crate::module::mark_guest_exec_diagnostics_failed(&error);
        return Err(RunError::Configuration(error));
    }
    config.validate()?;
    if config
        .exec
        .as_ref()
        .is_some_and(|e| e.worker_args.is_some())
    {
        // Guest chdir must not relocate the worker's resources or evidence.
        // Keep the guest binary/argv spelling, but pin host-owned paths now.
        let absolute = |path: &PathBuf| {
            std::path::absolute(path)
                .map_err(|e| RunError::Configuration(format!("resolve worker path: {e}")))
        };
        config.rootfs = absolute(&config.rootfs)?;
        if let Some(trace) = &mut config.trace_output {
            *trace = absolute(trace)?;
        }
        if let Intervention::SharedObject(path) = &mut config.intervention {
            *path = absolute(path)?;
        }
    }
    STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|_| RunError::AlreadyStarted)?;

    if let Err(error) = crate::diagnostics::install(&config.binary, config.trace_output.as_deref())
    {
        crate::module::mark_guest_exec_diagnostics_failed(&error.to_string());
        return Err(RunError::Diagnostics(error));
    }
    crate::module::mark_guest_exec_transition_started();
    let arch = compiled_arch();
    let mut module = match &config.intervention {
        Intervention::None => IIBModule::trace_only(arch, config.binary.clone()),
        Intervention::Static(manifest) => IIBModule::new(manifest, config.binary.clone()),
        Intervention::SharedObject(path) => {
            IIBModule::new(load_and_leak(path, arch)?, config.binary.clone())
        }
    };
    if let Some(launcher) = &config.exec {
        module = module.with_guest_exec(GuestExecConfig {
            harness_path: launcher.program.clone(),
            host_loader: launcher.host_loader.clone(),
            host_library_path: launcher.host_library_path.clone(),
            intervention_so: match &config.intervention {
                Intervention::SharedObject(path) => Some(path.clone()),
                _ => None,
            },
            trace_output: config.trace_output.clone(),
            rootfs: config.rootfs.clone(),
            worker_args: launcher.worker_args.clone(),
            intervention_kind: crate::exec_resume::intervention_kind(&config.intervention),
            syscall_trace: config.syscall_trace,
        });
    } else {
        module = module.with_exec_disabled();
    }

    let (environment_guard, unset) =
        prepare_guest_environment(&config.env, &config.unset_env).map_err(RunError::Environment)?;
    let log_filename = crate::diagnostics::guest_filename_argument(config.env.is_empty(), &unset);
    let args = qemu_arguments(&config, arch, &unset, log_filename);
    let trace = config
        .trace_output
        .map(RuntimeTraceModule::new)
        .map(|trace| trace.with_exit_syscalls(exit_syscalls(arch)))
        .unwrap_or_else(RuntimeTraceModule::disabled);
    let emulator = Emulator::<
        (),
        NopCommandManager,
        NopEmulatorDriver,
        (),
        BytesInput,
        NopState<BytesInput>,
        NopSnapshotManager,
    >::empty()
    .qemu_parameters(libafl_qemu::qemu::QemuCliBytes(args))
    // Trace must be live before module startup restores OFDs or reports a
    // failed restore. Both modules are already pinned by the builder here.
    .modules(tuple_list!(trace, module))
    .build();
    drop(environment_guard);
    let emulator = emulator.map_err(|e| RunError::Initialization(format!("{e:?}")))?;
    // QEMU and global hook/trace pointers remain installed even when run
    // returns. Keep their owners alive until worker exit, and reject reuse.
    let emulator = Box::leak(Box::new(emulator));
    let qemu = emulator.qemu();
    loop {
        match unsafe { qemu.run() } {
            Ok(QemuExitReason::End(cause)) => {
                let cause = format!("{cause:?}");
                record_runtime_state_event("qemu_end", &cause);
                flush_runtime_trace();
                return Ok(RunOutcome {
                    shutdown_cause: cause,
                });
            }
            Ok(QemuExitReason::Breakpoint(addr)) => {
                match crate::module::dispatch_breakpoint(addr as u64) {
                    Ok(true) => {}
                    Ok(false) => {
                        let error = format!("unregistered breakpoint at {addr:#x}");
                        record_runtime_state_event("qemu_error", &error);
                        flush_runtime_trace();
                        return Err(RunError::UnhandledStop(error));
                    }
                    Err(error) => {
                        record_runtime_state_event("iib_callsite_error", &error);
                        flush_runtime_trace();
                        return Err(RunError::Dispatch(error));
                    }
                }
            }
            Ok(other) => {
                let error = format!("{other:?}");
                record_runtime_state_event("qemu_error", &error);
                flush_runtime_trace();
                return Err(RunError::UnhandledStop(error));
            }
            Err(error) => {
                let error = format!("{error:?}");
                record_runtime_state_event("qemu_error", &error);
                flush_runtime_trace();
                return Err(RunError::Execution(error));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fmst_iib_api::manifest::{StaticGlobalState, CURRENT_ABI_VERSION};
    use std::os::unix::ffi::OsStringExt;

    fn manifest(arch: Arch, abi_version: u32) -> &'static StaticManifest {
        Box::leak(Box::new(StaticManifest {
            abi_version,
            arch,
            global_state: StaticGlobalState {
                type_name: "()",
                init_fn: || Box::new(()),
            },
            callsite_hooks: &[],
            function_stubs: &[],
            pseudo_files: &[],
        }))
    }

    #[test]
    fn linked_manifests_cannot_bypass_abi_or_architecture_checks() {
        let mut config = RunConfig::new("/guest", "/");
        config.intervention =
            Intervention::Static(manifest(compiled_arch(), CURRENT_ABI_VERSION - 1));
        assert!(matches!(
            run(config),
            Err(RunError::Manifest(LoadError::AbiVersion { .. }))
        ));
        let other_arch = if compiled_arch() == Arch::Arm {
            Arch::X86_64
        } else {
            Arch::Arm
        };
        let mut config = RunConfig::new("/guest", "/");
        config.intervention = Intervention::Static(manifest(other_arch, CURRENT_ABI_VERSION));
        assert!(matches!(
            run(config),
            Err(RunError::Manifest(LoadError::ArchMismatch { .. }))
        ));
    }

    #[test]
    fn nul_in_rust_supplied_bytes_is_rejected_before_environment_mutation() {
        let mut config = RunConfig::new("/guest", "/");
        config.env.push(OsString::from_vec(b"KEY=a\0b".to_vec()));
        assert!(matches!(run(config), Err(RunError::Configuration(_))));
    }

    #[test]
    fn argument_bytes_and_architecture_limits_are_preserved() {
        let mut config = RunConfig::new("/guest", "/rootfs");
        config.argv0 = Some(OsString::from_vec(b"name,\xff".to_vec()));
        config.args = vec![OsString::from_vec(b"arg,\xfe".to_vec())];
        for (arch, reservation) in [
            (Arch::Arm, Some(b"4G")),
            (Arch::Mips, Some(b"2G")),
            (Arch::X86_64, None),
        ] {
            let args = qemu_arguments(&config, arch, &["REMOVE".into()], None);
            assert_eq!(
                args.iter()
                    .position(|s| s == b"-R")
                    .map(|i| args[i + 1].as_slice()),
                reservation.map(|s| s.as_slice())
            );
            assert_eq!(
                &args[args.len() - 4..],
                &[
                    b"-0".to_vec(),
                    b"name,\xff".to_vec(),
                    b"/guest".to_vec(),
                    b"arg,\xfe".to_vec()
                ]
            );
            for name in [
                "FMST_EXEC_HANDOFF",
                "FMST_EXEC_DEPTH",
                "FMST_EXEC_TRANSITION",
                crate::exec_resume::ENV,
            ] {
                assert!(args
                    .windows(2)
                    .any(|p| p == [b"-U".to_vec(), name.as_bytes().to_vec()]));
            }
        }
    }

    #[test]
    fn static_exec_is_rejected_before_global_initialization() {
        let mut config = RunConfig::new("/guest", "/");
        config.intervention = Intervention::Static(manifest(compiled_arch(), CURRENT_ABI_VERSION));
        config.exec = Some(ExecLauncher::harness("/launcher"));
        assert!(matches!(run(config), Err(RunError::Configuration(_))));
    }

    #[test]
    fn linked_worker_can_reenter_with_the_same_manifest() {
        let mut config = RunConfig::new("/guest", "/");
        config.intervention = Intervention::Static(manifest(compiled_arch(), CURRENT_ABI_VERSION));
        config.exec = Some(ExecLauncher::current_process().unwrap());
        config.validate().unwrap();
    }
}
