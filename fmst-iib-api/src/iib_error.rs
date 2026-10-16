//! Errors returned by IIB-level operations (native_call, dispatch, etc.).

use crate::types::Errno;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum IibError {
    #[error("guest errno: {0:?}")]
    Errno(Errno),

    #[error("guest crashed with signal {0}")]
    GuestCrash(i32),

    #[error("guest execution timed out")]
    GuestTimeout,

    #[error("IIB stack pool exhausted")]
    StackPoolExhausted,

    #[error("nested native_call depth {0} exceeds MAX_NESTING")]
    NestingTooDeep(u32),

    #[error("binary '{binary}' not loaded; cannot resolve offset {offset:#x}")]
    MissingBinary { binary: String, offset: u64 },

    #[error("no MockIIBContextOps response programmed for target {0:#x}")]
    NoResponseProgrammed(u64),
}

impl From<Errno> for IibError {
    fn from(e: Errno) -> Self {
        IibError::Errno(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_auto_conversion() {
        let e: IibError = Errno::EBADF.into();
        matches!(e, IibError::Errno(Errno::EBADF));
    }

    #[test]
    fn missing_binary_display_includes_offset() {
        let e = IibError::MissingBinary {
            binary: "libnat.so".to_string(),
            offset: 0x1a28,
        };
        let msg = format!("{e}");
        assert!(msg.contains("libnat.so"));
        assert!(msg.contains("0x1a28"));
    }
}
