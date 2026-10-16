//! Machine-readable capabilities exposed by an IIB runtime.

use crate::types::Arch;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IIBCapability {
    InvocationNativeCall,
    InvocationNestedHook,
    GuestMemoryReadWrite,
    GuestMemorySessionAlloc,
    GuestStackReadWrite,
    CoreRegisterReadWrite,
    AbiArgumentWords,
    AbiArgumentBytes,
    AbiReturnBytes,
    PathAwareOpen,
    PerPathFactory,
    SharedOpenFileDescription,
    FdDuplication,
    FdCloseOnExec,
    VirtualFdExecHandoff,
    NativeFallbackOpen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapabilityManifest {
    pub schema_version: u32,
    pub iib_abi_version: u32,
    pub arch: Arch,
    pub capabilities: Vec<IIBCapability>,
}

impl RuntimeCapabilityManifest {
    pub fn supports(&self, capability: IIBCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn require_all<I>(&self, required: I) -> Result<(), Vec<IIBCapability>>
    where
        I: IntoIterator<Item = IIBCapability>,
    {
        let missing = required
            .into_iter()
            .filter(|capability| !self.supports(*capability))
            .collect::<Vec<_>>();
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_manifest_roundtrips_and_reports_missing() {
        let manifest = RuntimeCapabilityManifest {
            schema_version: 1,
            iib_abi_version: crate::manifest::CURRENT_ABI_VERSION,
            arch: Arch::Arm,
            capabilities: vec![
                IIBCapability::PathAwareOpen,
                IIBCapability::NativeFallbackOpen,
            ],
        };
        let encoded = serde_json::to_string(&manifest).unwrap();
        let decoded: RuntimeCapabilityManifest = serde_json::from_str(&encoded).unwrap();
        assert!(decoded.supports(IIBCapability::PathAwareOpen));
        assert_eq!(
            decoded.require_all([IIBCapability::PathAwareOpen, IIBCapability::FdDuplication,]),
            Err(vec![IIBCapability::FdDuplication])
        );
    }
}
