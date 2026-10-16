//! IIBContextOps — the sole surface intervention code uses to interact
//! with emulator state. Defined here as a trait so that fmst-iib-runtime
//! can implement it against libafl_qemu, while intervention crates (which
//! must not depend on libafl_qemu) see only this interface.

use crate::iib_error::IibError;
use crate::types::{Errno, GuestAddr, GuestReg};
use std::any::Any;

/// Intervention code's view of emulator state.
///
/// Object-safe: used as `&mut dyn IIBContextOps` by all hook entry functions.
///
/// `read_arg`/`write_arg` access one core ABI word; their index matches a C
/// argument position only when the preceding parameters each use one word.
/// The byte/word helpers expose multiple **ABI word slots**: `index == 0` is
/// the first core argument word, regardless of how the source language grouped
/// those words into a struct. IIB does not know a C signature, but exposes the
/// exact register/stack bytes that an ABI made observable to the hook.
///
/// Floating-point and vector registers are outside this core-word surface. A
/// runtime must return `ENOSYS` for those shapes rather than silently reading a
/// differently classified core argument.
pub trait IIBContextOps {
    // ---------- Single core ABI argument word (not a raw register index) ----------

    /// Read one ABI word. For one-word core scalar/pointer parameters this
    /// matches the parameter index; wide/aggregate signatures need an explicit
    /// word-slot layout because this context does not know the C signature.
    fn read_arg(&self, idx: u8) -> Result<GuestReg, Errno>;
    fn write_arg(&self, idx: u8, val: GuestReg) -> Result<(), Errno>;

    /// Read `word_count` contiguous core ABI argument words.
    ///
    /// `index` is an ABI word-slot index, not a logical C argument index. The
    /// returned values are zero-extended to `GuestReg`.
    fn read_arg_words(&self, _index: u8, _word_count: u8) -> Result<Vec<GuestReg>, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Read bytes from contiguous core ABI argument word slots. The byte
    /// order and word width are those of the target guest ABI.
    fn read_arg_bytes(&self, _index: u8, _size: usize) -> Result<Vec<u8>, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Write bytes to contiguous core ABI argument word slots, preserving any
    /// untouched bytes in a partially addressed final word.
    fn write_arg_bytes(&self, _index: u8, _data: &[u8]) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    // ---------- Return value ----------

    /// Set the guest-visible return value AND redirect PC to the return
    /// address. Intended for `HookFlavor::Call`. Calling from an `Enter`
    /// hook will skip the original function — usually a bug.
    fn set_return_value(&self, val: GuestReg) -> Result<(), Errno>;

    /// Read the core-register bytes used for an aggregate return value.
    /// Implementations must fail with `ENOSYS` when the ABI class is not
    /// represented by this surface (for example FP/vector or hidden sret).
    fn read_return_bytes(&self, _size: usize) -> Result<Vec<u8>, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Write the core-register bytes used for an aggregate return value. This
    /// does not redirect control flow; call `set_return_value` afterwards in a
    /// `Call` hook to complete the replacement.
    fn write_return_bytes(&self, _data: &[u8]) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    // ---------- Named register (escape hatch) ----------

    fn read_reg(&self, name: &str) -> Result<GuestReg, Errno>;
    fn write_reg(&self, name: &str, val: GuestReg) -> Result<(), Errno>;

    fn current_pc(&self) -> GuestAddr;
    fn return_address(&self) -> Result<GuestAddr, Errno>;

    // ---------- Memory (guest VA) ----------

    fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Errno>;
    fn write_mem(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), Errno>;

    /// Read bytes at `SP + offset`. Negative offsets are allowed for a frame
    /// that has already reserved local storage. The offset is checked for
    /// overflow before touching guest memory.
    fn read_stack(&self, offset: i64, size: usize) -> Result<Vec<u8>, Errno> {
        let sp = self.read_reg("sp")?;
        let addr = if offset >= 0 {
            sp.checked_add(offset as u64).ok_or(Errno::EOVERFLOW)?
        } else {
            sp.checked_sub(offset.unsigned_abs())
                .ok_or(Errno::EOVERFLOW)?
        };
        let mut buf = vec![0u8; size];
        self.read_mem(addr, &mut buf)?;
        Ok(buf)
    }

    /// Write bytes at `SP + offset`; see [`Self::read_stack`] for offset
    /// semantics.
    fn write_stack(&self, offset: i64, data: &[u8]) -> Result<(), Errno> {
        let sp = self.read_reg("sp")?;
        let addr = if offset >= 0 {
            sp.checked_add(offset as u64).ok_or(Errno::EOVERFLOW)?
        } else {
            sp.checked_sub(offset.unsigned_abs())
                .ok_or(Errno::EOVERFLOW)?
        };
        self.write_mem(addr, data)
    }

    /// Allocate guest-visible storage owned by the current IIB session.
    /// Implementations must return a guest VA that remains valid until the
    /// session ends or `free_guest` is called. The default is fail-closed for
    /// older third-party contexts that do not provide allocation.
    fn alloc_guest(&self, _size: usize, _align: usize) -> Result<GuestAddr, Errno> {
        Err(Errno::ENOSYS)
    }

    /// Release guest-visible storage previously returned by `alloc_guest`.
    fn free_guest(&self, _addr: GuestAddr, _size: usize) -> Result<(), Errno> {
        Err(Errno::ENOSYS)
    }

    fn read_cstr(&self, addr: GuestAddr, max_len: usize) -> Result<std::ffi::CString, Errno> {
        let mut collected = Vec::with_capacity(32);
        for offset in 0..max_len {
            let mut b = [0u8; 1];
            let current = addr
                .checked_add(offset as GuestAddr)
                .ok_or(Errno::EOVERFLOW)?;
            self.read_mem(current, &mut b)?;
            if b[0] == 0 {
                return std::ffi::CString::new(collected).map_err(|_| Errno::EINVAL);
            }
            collected.push(b[0]);
        }
        Err(Errno::ENAMETOOLONG)
    }

    fn read_u8(&self, addr: GuestAddr) -> Result<u8, Errno> {
        let mut b = [0u8; 1];
        self.read_mem(addr, &mut b)?;
        Ok(b[0])
    }

    /// Read an integer in the guest ABI byte order.
    ///
    /// The default is little-endian for backwards-compatible third-party
    /// implementors. Big-endian runtime and mock implementations override the
    /// typed helpers so intervention code observes the target guest order.
    fn read_u16(&self, addr: GuestAddr) -> Result<u16, Errno> {
        let mut b = [0u8; 2];
        self.read_mem(addr, &mut b)?;
        Ok(u16::from_le_bytes(b))
    }

    fn read_u32(&self, addr: GuestAddr) -> Result<u32, Errno> {
        let mut b = [0u8; 4];
        self.read_mem(addr, &mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn read_u64(&self, addr: GuestAddr) -> Result<u64, Errno> {
        let mut b = [0u8; 8];
        self.read_mem(addr, &mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn read_i32(&self, addr: GuestAddr) -> Result<i32, Errno> {
        self.read_u32(addr).map(|v| v as i32)
    }

    fn write_u8(&self, addr: GuestAddr, val: u8) -> Result<(), Errno> {
        self.write_mem(addr, &[val])
    }

    fn write_u16(&self, addr: GuestAddr, val: u16) -> Result<(), Errno> {
        self.write_mem(addr, &val.to_le_bytes())
    }

    fn write_u32(&self, addr: GuestAddr, val: u32) -> Result<(), Errno> {
        self.write_mem(addr, &val.to_le_bytes())
    }

    fn write_u64(&self, addr: GuestAddr, val: u64) -> Result<(), Errno> {
        self.write_mem(addr, &val.to_le_bytes())
    }

    fn write_i32(&self, addr: GuestAddr, val: i32) -> Result<(), Errno> {
        self.write_u32(addr, val as u32)
    }

    // ---------- GlobalState ----------

    /// Returns the intervention crate's GlobalState as `&dyn Any`.
    /// Use [`state_of`] for typed access.
    fn state(&self) -> &(dyn Any + Send + Sync);

    // ---------- IIB: nested guest call ----------

    /// Invoke guest code with core ABI word arguments and return its scalar
    /// result, restoring the caller's CPU context on successful completion.
    /// Guest-memory side effects remain visible. This executes normal hook
    /// dispatch: calling an installed hook's address re-enters that hook; it
    /// does not implicitly call the original function. A bounded re-entry
    /// guard can let the nested hook return without `set_return_value` to
    /// continue native execution. Do not hold a state lock across this call.
    ///
    /// Use an evidenced runtime virtual address. The legacy resolver also
    /// considers the main-image load base plus `target` and rejects ambiguous
    /// or non-executable candidates; arbitrary library-relative offsets have
    /// no module identity and are not supported. Nesting and stack capacity
    /// are bounded. An error returned after frame allocation releases that
    /// frame and balances the nesting counter, but does not promise CPU or
    /// guest-memory rollback. Guest termination may end the worker instead of
    /// returning a recoverable error; this is not a crash-recovery boundary.
    fn native_call(&mut self, target: GuestAddr, args: &[GuestReg]) -> Result<GuestReg, IibError>;

    /// Invoke an already resolved guest runtime VA without relocation.
    ///
    /// The address must be nonzero and executable in the current image. This
    /// does not resolve a library offset or establish function identity. Hook
    /// re-entry, side effects and failure boundaries match `native_call`.
    /// Unsupported contexts return ENOSYS; they must not use the ambiguous
    /// legacy resolver as a fallback.
    fn native_call_runtime(&mut self, _target: GuestAddr, _args: &[GuestReg]) -> Result<GuestReg, IibError> {
        Err(IibError::Errno(Errno::ENOSYS))
    }
}

/// Downcast the GlobalState returned by [`IIBContextOps::state`] to the
/// concrete type declared in the intervention crate's manifest.
///
/// Panics on type mismatch — this indicates a synthesis bug and should
/// be loud. Intervention crate ≠ manifest global_state.type_path is a
/// build-time problem.
pub fn state_of<T: 'static>(ctx: &dyn IIBContextOps) -> &T {
    ctx.state()
        .downcast_ref::<T>()
        .expect("GlobalState type mismatch — manifest declared type != actual")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: trait is object-safe.
    #[test]
    fn trait_is_object_safe() {
        fn _takes_dyn(_: &dyn IIBContextOps) {}
    }

    /// Smoke test: fn pointer type matches hook entry signature.
    #[test]
    fn fn_ptr_type_compiles() {
        let _fp: fn(&mut dyn IIBContextOps) = noop_hook;
    }

    fn noop_hook(_ctx: &mut dyn IIBContextOps) {}
}
