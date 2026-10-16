//! Runtime capability declaration.

use fmst_iib_api::capability::{IIBCapability, RuntimeCapabilityManifest};
use fmst_iib_api::manifest::CURRENT_ABI_VERSION;
use fmst_iib_api::types::Arch;

/// Capabilities exercised by the current runtime implementation and its
/// conformance tests. Keep this list honest: add a capability only with a
/// corresponding real runtime test.
pub fn current(arch: Arch) -> RuntimeCapabilityManifest {
    RuntimeCapabilityManifest {
        schema_version: 1,
        iib_abi_version: CURRENT_ABI_VERSION,
        arch,
        capabilities: vec![
            IIBCapability::InvocationNativeCall,
            IIBCapability::InvocationNestedHook,
            IIBCapability::GuestMemoryReadWrite,
            IIBCapability::GuestMemorySessionAlloc,
            IIBCapability::GuestStackReadWrite,
            IIBCapability::CoreRegisterReadWrite,
            IIBCapability::AbiArgumentWords,
            IIBCapability::AbiArgumentBytes,
            IIBCapability::AbiReturnBytes,
            IIBCapability::PathAwareOpen,
            IIBCapability::PerPathFactory,
            IIBCapability::SharedOpenFileDescription,
            IIBCapability::FdDuplication,
            IIBCapability::FdCloseOnExec,
            IIBCapability::VirtualFdExecHandoff,
            IIBCapability::NativeFallbackOpen,
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_manifest_is_explicit_and_serializable() {
        let manifest = current(Arch::Arm);
        assert!(manifest.supports(IIBCapability::NativeFallbackOpen));
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(json.contains("path_aware_open"));
        assert!(json.contains("native_fallback_open"));
    }
}
