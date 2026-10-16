//! GuestWeave public facade.
//!
//! Intervention authors use [`api`]. Applications select one architecture
//! feature and use `run`, `RunConfig` and `Intervention` to execute a guest in
//! a dedicated worker process. LibAFL types and a command-line parser are not
//! required. The historical crates and optional plugin ABI remain compatible.

pub use fmst_iib_api as api;

#[cfg(any(
    feature = "arm",
    feature = "mips",
    feature = "mipsbe",
    feature = "x86_64"
))]
pub use fmst_iib_runtime as runtime;

/// Process-owned execution without LibAFL types in the caller's code.
#[cfg(any(
    feature = "arm",
    feature = "mips",
    feature = "mipsbe",
    feature = "x86_64"
))]
pub use fmst_iib_runtime::execution::{
    run, ExecLauncher, Intervention, RunConfig, RunError, RunOutcome,
};
