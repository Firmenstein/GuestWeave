//! fmst-iib-runtime — LibAFL QEMU-backed implementation of IIBContextOps
//! + IIBModule + VFS + native_call.

pub mod capabilities;
pub mod context_impl;
pub mod cpu_snapshot;
pub mod diagnostics;
pub mod dispatch;
mod exec_resume;
pub mod execution;
pub mod guest_environment;
pub mod guest_memory;
pub mod load_map;
pub mod manifest_load;
pub mod module;
pub mod native_call;
pub mod runtime_trace;
pub mod stack_pool;
pub mod vfs;

pub use module::IIBModule;
