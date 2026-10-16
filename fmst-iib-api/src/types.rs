//! Core types shared across the IIB API boundary.

use serde::{Deserialize, Serialize};

/// Guest architecture. Per-arch harness binaries pin one of these via
/// the `arch` field of the manifest; runtime validates at dlopen time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arch {
    Arm,
    Mips,
    X86_64,
}

/// Callsite / function stub hook flavor.
///
/// - `Enter`: run hook, then let original code continue.
/// - `Call`: hook replaces the original (hook must set a return value or
///   otherwise transfer control). Default.
/// - `Exit`: hook runs after the original returns. **v1 NOT IMPLEMENTED**;
///   registration fails with a clear error. Tracked in IIB-FLAVOR-EXIT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HookFlavor {
    Enter,
    Call,
    Exit,
}

impl Default for HookFlavor {
    fn default() -> Self {
        HookFlavor::Call
    }
}

/// Guest virtual address. Always `u64` regardless of guest word size
/// (32-bit guests use lower 32 bits; runtime masks before use).
pub type GuestAddr = u64;

/// Guest register value. Width matches [`GuestAddr`].
pub type GuestReg = u64;

/// POSIX errno values used across IIB error returns.
///
/// Discriminants retain Linux asm-generic numbers for API/ABI stability.
/// Pseudo-file implementations return these semantic variants; the runtime
/// maps them to the selected guest syscall ABI (MIPS uses different numbers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum Errno {
    EPERM = 1,
    ENOENT = 2,
    EIO = 5,
    EBADF = 9,
    EAGAIN = 11,
    ENOMEM = 12,
    EACCES = 13,
    EFAULT = 14,
    EBUSY = 16,
    EEXIST = 17,
    ENODEV = 19,
    EINVAL = 22,
    ENOTTY = 25,
    ENOSPC = 28,
    ESPIPE = 29,
    EPIPE = 32,
    ERANGE = 34,
    ENAMETOOLONG = 36,
    ENOSYS = 38,
    EOVERFLOW = 75,
}

impl Errno {
    /// Returns the negative asm-generic number, not a portable guest ABI value.
    /// Runtime syscall adapters must translate it for architectures such as MIPS.
    #[inline]
    pub fn as_neg_i64(self) -> i64 {
        -(self as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_as_neg_i64_converts_correctly() {
        assert_eq!(Errno::EPERM.as_neg_i64(), -1);
        assert_eq!(Errno::EBADF.as_neg_i64(), -9);
        assert_eq!(Errno::ENOSYS.as_neg_i64(), -38);
    }

    #[test]
    fn errno_is_copy() {
        let e = Errno::EINVAL;
        let _copy = e;
        let _still_usable = e;
    }

    #[test]
    fn arch_serde_roundtrip() {
        let json = serde_json::to_string(&Arch::Arm).unwrap();
        assert_eq!(json, "\"arm\"");
        let back: Arch = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Arch::Arm);
    }

    #[test]
    fn hook_flavor_default_is_call() {
        let f: HookFlavor = Default::default();
        assert_eq!(f, HookFlavor::Call);
    }

    #[test]
    fn hook_flavor_serde_roundtrip() {
        for f in [HookFlavor::Enter, HookFlavor::Call, HookFlavor::Exit] {
            let json = serde_json::to_string(&f).unwrap();
            let back: HookFlavor = serde_json::from_str(&json).unwrap();
            assert_eq!(back, f);
        }
    }
}
