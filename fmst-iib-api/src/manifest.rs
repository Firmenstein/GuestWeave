//! JSON schema for intervention manifest files.
//!
//! Two views on the same data:
//! - [`Manifest`]: serde-deserialized from manifest.json at build/analysis time
//! - [`StaticManifest`]: static-lifetime Rust composition form. Applications
//!   can define it directly; generated plugins emit it from build.rs and
//!   export it via `fmst_manifest()`.
//!
//! Keep the shapes in sync: build.rs is the translation layer.

use crate::types::{Arch, HookFlavor};
use serde::{Deserialize, Serialize};

// v4 adds explicit runtime-VA native calls to IIBContextOps. Old
// intervention .so files must be rejected rather than called through a
// mismatched trait layout.
pub const CURRENT_ABI_VERSION: u32 = 4;

// ===== JSON side =====

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub manifest_abi_version: u32,
    pub target_image: String,
    pub target_binary: String,
    pub arch: Arch,
    pub global_state: GlobalStateDesc,
    #[serde(default)]
    pub callsite_hooks: Vec<CallsiteHookDesc>,
    #[serde(default)]
    pub function_stubs: Vec<FunctionStubDesc>,
    #[serde(default)]
    pub pseudo_files: Vec<PseudoFileDesc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalStateDesc {
    pub type_path: String,
    pub init_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleTarget {
    pub binary: String,
    pub offset: String,
    #[serde(default, rename = "_symbol_hint")]
    pub symbol_hint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallsiteHookDesc {
    pub id: String,
    pub target: ModuleTarget,
    pub resume_offset: String,
    pub flavor: HookFlavor,
    pub entry_fn_path: String,
    pub source_file: String,
    #[serde(default)]
    pub diagnostic_report: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionStubDesc {
    pub id: String,
    pub target: ModuleTarget,
    pub flavor: HookFlavor,
    pub entry_fn_path: String,
    pub source_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PseudoFileDesc {
    pub id: String,
    pub paths: Vec<String>,
    pub impl_type_path: String,
    pub factory_path: String,
    pub source_file: String,
    #[serde(default)]
    pub diagnostic_report: Option<String>,
}

// ===== Static / runtime side =====

use crate::types::GuestAddr;

pub struct ModuleTargetStatic {
    pub binary: &'static str,
    pub offset: GuestAddr,
    pub symbol_hint: Option<&'static str>,
}

pub struct StaticGlobalState {
    pub type_name: &'static str,
    pub init_fn: fn() -> Box<dyn std::any::Any + Send + Sync>,
}

use crate::context::IIBContextOps;
use crate::pseudo_file::PseudoFileFactory;

pub struct CallsiteHookStatic {
    pub id: &'static str,
    pub target: ModuleTargetStatic,
    pub resume_offset: GuestAddr,
    pub flavor: HookFlavor,
    pub entry_fn: fn(&mut dyn IIBContextOps),
}

pub struct FunctionStubStatic {
    pub id: &'static str,
    pub target: ModuleTargetStatic,
    pub flavor: HookFlavor,
    pub entry_fn: fn(&mut dyn IIBContextOps),
}

pub struct PseudoFileStatic {
    pub id: &'static str,
    pub paths: &'static [&'static str],
    pub factory: PseudoFileFactory,
    pub impl_name: &'static str,
}

/// Behavior plus image/resource bindings, suitable for direct Rust linking.
/// Optional .so plugins export this through
/// `#[no_mangle] pub extern "Rust" fn fmst_manifest() -> &'static StaticManifest`.
pub struct StaticManifest {
    pub abi_version: u32,
    pub arch: Arch,
    pub global_state: StaticGlobalState,
    pub callsite_hooks: &'static [CallsiteHookStatic],
    pub function_stubs: &'static [FunctionStubStatic],
    pub pseudo_files: &'static [PseudoFileStatic],
}

unsafe impl Sync for StaticManifest {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_roundtrip_minimal() {
        let json = r#"{
            "manifest_abi_version": 4,
            "target_image": "R6700v3",
            "target_binary": "httpd",
            "arch": "arm",
            "global_state": {
                "type_path": "crate::state::GlobalState",
                "init_path": "crate::state::GlobalState::default"
            }
        }"#;
        let m: Manifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.manifest_abi_version, CURRENT_ABI_VERSION);
        assert_eq!(m.arch, Arch::Arm);
        assert!(m.callsite_hooks.is_empty());
        assert!(m.pseudo_files.is_empty());
    }

    #[test]
    fn callsite_hook_parses_with_symbol_hint() {
        let json = r#"{
            "id": "h_foo",
            "target": {
                "binary": "httpd",
                "offset": "0x00001040",
                "_symbol_hint": "getIfIp"
            },
            "resume_offset": "0x00001044",
            "flavor": "Call",
            "entry_fn_path": "crate::callsite_hooks::h_foo::intercept",
            "source_file": "callsite_hooks/h_foo.rs"
        }"#;
        let h: CallsiteHookDesc = serde_json::from_str(json).unwrap();
        assert_eq!(h.target.symbol_hint.as_deref(), Some("getIfIp"));
        assert_eq!(h.resume_offset, "0x00001044");
        assert_eq!(h.flavor, HookFlavor::Call);
    }

    #[test]
    fn static_manifest_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<&'static StaticManifest>();
    }

    #[test]
    fn static_target_ctor_works() {
        const T: ModuleTargetStatic = ModuleTargetStatic {
            binary: "httpd",
            offset: 0x1040,
            symbol_hint: Some("getIfIp"),
        };
        assert_eq!(T.offset, 0x1040);
    }

    #[test]
    fn callsite_hook_static_holds_fn_ptr() {
        fn noop(_ctx: &mut dyn crate::context::IIBContextOps) {}
        const H: CallsiteHookStatic = CallsiteHookStatic {
            id: "h_test",
            target: ModuleTargetStatic {
                binary: "httpd",
                offset: 0x1040,
                symbol_hint: None,
            },
            resume_offset: 0x1044,
            flavor: HookFlavor::Call,
            entry_fn: noop,
        };
        assert_eq!(H.id, "h_test");
    }
}
