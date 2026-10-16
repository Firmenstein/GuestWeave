//! PseudoFile — trait implementations of which route file I/O for a
//! specific guest path (e.g., /dev/acos_nat_cli).
//!
//! All methods default to `Err(Errno::ENOSYS)` except `close`/`fsync`/`name`.
//! Users override only what they need. Once a factory returns `Handled`, the
//! descriptor is owned by this PseudoFile; an unimplemented operation is a
//! guest-visible `ENOSYS`, never native fallback. Factories use
//! [`PseudoFileOpen`] to decline ownership before a descriptor exists.

use crate::context::IIBContextOps;
use crate::types::{Errno, GuestAddr};

/// Outcome of attempting to claim a registered path during `open`.
///
/// `NativeFallback` is a control-flow result: the Unit declines ownership of
/// this exact path/flag combination. `GuestError` is visible to the guest and
/// must never be treated as permission to run the native syscall.
pub enum PseudoFileOpen {
    Handled(Box<dyn PseudoFile>),
    NativeFallback,
    GuestError(Errno),
}

/// Constructor used by the VFS for a registered pseudo path.
///
/// The path and open flags are passed to the constructor deliberately.  A
/// single intervention Unit may own several exact paths (for example two
/// MTD partitions), but those paths must still be able to select different
/// backing state.  The constructor must not retain the borrowed path.
pub type PseudoFileFactory = for<'a> fn(path: &'a str, flags: i64) -> PseudoFileOpen;

pub trait PseudoFile: Send {
    fn read(
        &mut self,
        _buf: GuestAddr,
        _len: usize,
        _ctx: &mut dyn IIBContextOps,
    ) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }

    fn write(
        &mut self,
        _buf: GuestAddr,
        _len: usize,
        _ctx: &mut dyn IIBContextOps,
    ) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }

    fn close(&mut self) -> Result<(), Errno> {
        Ok(())
    }

    fn lseek(&mut self, _offset: i64, _whence: i32) -> Result<i64, Errno> {
        Err(Errno::ENOSYS)
    }

    fn tell(&mut self) -> Result<i64, Errno> {
        Err(Errno::ENOSYS)
    }

    fn fstat(&mut self, _stat_buf: GuestAddr, _ctx: &mut dyn IIBContextOps) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    fn readline(
        &mut self,
        _buf: GuestAddr,
        _max: usize,
        _end: u8,
        _ctx: &mut dyn IIBContextOps,
    ) -> Result<usize, Errno> {
        Err(Errno::ENOSYS)
    }

    fn fsync(&mut self) -> Result<(), Errno> {
        Ok(())
    }

    fn ioctl(
        &mut self,
        _cmd: u32,
        _arg: GuestAddr,
        _ctx: &mut dyn IIBContextOps,
    ) -> Result<i64, Errno> {
        Err(Errno::ENOSYS)
    }

    fn name(&self) -> &str {
        "<unnamed>"
    }

    /// Capture the state that must survive a successful guest `execve`.
    ///
    /// Returning `Some(bytes)` opts this pseudo-file into the Runtime's
    /// explicit cross-image handoff.  The bytes are opaque to the Runtime and
    /// should contain only the mutable open-file-description state needed by
    /// the implementation.  Returning `None` keeps the historical behavior:
    /// a virtual descriptor cannot be carried across a host-harness exec and
    /// the Runtime reports that boundary instead of silently reopening it.
    fn exec_snapshot(&mut self) -> Result<Option<Vec<u8>>, Errno> {
        Ok(None)
    }

    /// Restore bytes previously returned by [`Self::exec_snapshot`].  The
    /// factory has already constructed a fresh object for the same guest path;
    /// this hook restores its open-file-description state before the new guest
    /// image starts.
    fn exec_restore(&mut self, _state: &[u8]) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dummy;
    impl PseudoFile for Dummy {}

    #[test]
    fn defaults_return_enosys() {
        let mut d = Dummy;
        assert_eq!(d.lseek(0, 0), Err(Errno::ENOSYS));
        assert_eq!(d.tell(), Err(Errno::ENOSYS));
    }

    #[test]
    fn close_and_fsync_default_ok() {
        let mut d = Dummy;
        assert_eq!(d.close(), Ok(()));
        assert_eq!(d.fsync(), Ok(()));
    }

    #[test]
    fn name_default() {
        let d = Dummy;
        assert_eq!(d.name(), "<unnamed>");
    }

    #[test]
    fn trait_is_object_safe_and_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Box<dyn PseudoFile>>();
    }
}
