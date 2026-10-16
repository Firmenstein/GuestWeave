//! Stable contract between fmst-iib-runtime (harness side) and intervention crates.
//!
//! This crate MUST NOT depend on libafl_qemu. Intervention crates only ever see
//! types declared here.

pub mod capability;
pub mod context;
pub mod iib_error;
pub mod known_apis;
pub mod manifest;
pub mod pseudo_file;
pub mod types;

#[cfg(feature = "mock")]
pub mod mock;

pub use capability::{IIBCapability, RuntimeCapabilityManifest};
pub use context::{state_of, IIBContextOps};
pub use iib_error::IibError;
pub use manifest::{
    CallsiteHookDesc, CallsiteHookStatic, FunctionStubDesc, FunctionStubStatic, GlobalStateDesc,
    Manifest, ModuleTarget, ModuleTargetStatic, PseudoFileDesc, PseudoFileStatic,
    StaticGlobalState, StaticManifest, CURRENT_ABI_VERSION,
};
pub use pseudo_file::{PseudoFile, PseudoFileFactory, PseudoFileOpen};
pub use types::{Arch, Errno, GuestAddr, GuestReg, HookFlavor};
