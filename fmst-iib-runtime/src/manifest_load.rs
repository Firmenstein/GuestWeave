//! Loads an intervention .so and extracts its StaticManifest.
//!
//! The .so is leaked (`mem::forget`) so fn pointers captured into hook
//! closures remain valid for the process lifetime. Harness process is
//! short-lived; no unload path needed.

use fmst_iib_api::manifest::{StaticManifest, CURRENT_ABI_VERSION};
use fmst_iib_api::types::Arch;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("dlopen failed: {0}")]
    Dlopen(#[from] libloading::Error),

    #[error("fmst_manifest symbol not found in .so")]
    SymbolNotFound,

    #[error("manifest ABI version mismatch: .so has {got}, harness expects {expected}")]
    AbiVersion { got: u32, expected: u32 },

    #[error("arch mismatch: .so is {got:?}, harness is {expected:?}")]
    ArchMismatch { got: Arch, expected: Arch },
}

pub struct LoadedIntervention {
    pub manifest: &'static StaticManifest,
    /// Kept around in case future code wants to re-symbol. Dropping this
    /// unloads the library, which would invalidate every fn pointer — hence
    /// `load_and_leak` below is the only safe entry.
    _library: libloading::Library,
}

/// Load an intervention .so, validate ABI + arch, and LEAK the library so
/// fn pointers referenced from the returned manifest remain valid forever.
pub fn load_and_leak(
    so_path: &Path,
    harness_arch: Arch,
) -> Result<&'static StaticManifest, LoadError> {
    let lib = unsafe { libloading::Library::new(so_path)? };
    let manifest = {
        let sym: libloading::Symbol<unsafe extern "Rust" fn() -> &'static StaticManifest> =
            unsafe { lib.get(b"fmst_manifest\0") }.map_err(|_| LoadError::SymbolNotFound)?;
        let m: &'static StaticManifest = unsafe { sym() };

        validate_manifest(m, harness_arch)?;
        m
    };

    // Leak the library. Fn pointers inside `manifest` point into the .so's
    // .text segment; they must stay mapped.
    std::mem::forget(lib);
    Ok(manifest)
}

/// Apply the same ABI and architecture checks to linked and loaded manifests.
pub fn validate_manifest(manifest: &StaticManifest, arch: Arch) -> Result<(), LoadError> {
    if manifest.abi_version != CURRENT_ABI_VERSION {
        return Err(LoadError::AbiVersion {
            got: manifest.abi_version,
            expected: CURRENT_ABI_VERSION,
        });
    }
    if manifest.arch != arch {
        return Err(LoadError::ArchMismatch {
            got: manifest.arch,
            expected: arch,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_nonexistent_file_errors() {
        let res = load_and_leak(Path::new("/nonexistent/foo.so"), Arch::Arm);
        let err = match res {
            Ok(_) => panic!("expected dlopen failure on missing path"),
            Err(e) => e,
        };
        matches!(err, LoadError::Dlopen(_));
    }
}
