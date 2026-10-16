//! Guest-side stack pool for IIB native_call.
//!
//! Layout (grows down):
//!
//!   base + size  ────────────► top of usable range
//!                 [frame_N]     (current SP after N nested calls)
//!                 [frame_2]
//!                 [frame_1]
//!   base         ────────────► bottom of pool (guard page below)
//!
//! The pool is a single guest memory region allocated at `pre_qemu_init`.
//! This struct just manages the offset; actual guest mmap is done by
//! the caller.

use fmst_iib_api::types::GuestAddr;

pub struct GuestStackPool {
    base: GuestAddr,
    size: u64,
    // Offset from the TOP (grows downward as frames are pushed).
    used: u64,
}

#[derive(Debug)]
pub struct StackFrameGuard {
    sp_after_push: GuestAddr,
    frame_size: u64,
}

impl StackFrameGuard {
    /// SP value to set the CPU to for the new native call.
    pub fn sp(&self) -> GuestAddr {
        self.sp_after_push
    }

    pub fn frame_size(&self) -> u64 {
        self.frame_size
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StackPoolError {
    #[error("stack pool exhausted: want {want}, have {remaining}")]
    Exhausted { want: u64, remaining: u64 },
}

impl GuestStackPool {
    pub fn new(base: GuestAddr, size: u64) -> Self {
        Self {
            base,
            size,
            used: 0,
        }
    }

    /// Push a new frame of `frame_size` bytes onto the pool.
    /// Returns the SP value to set on the CPU.
    pub fn alloc_frame(&mut self, frame_size: u64) -> Result<StackFrameGuard, StackPoolError> {
        let remaining = self.size - self.used;
        if frame_size > remaining {
            return Err(StackPoolError::Exhausted {
                want: frame_size,
                remaining,
            });
        }
        self.used += frame_size;
        let sp = self.base + (self.size - self.used);
        Ok(StackFrameGuard {
            sp_after_push: sp,
            frame_size,
        })
    }

    /// Pop the topmost frame. Must be called with the guard returned by
    /// the matching `alloc_frame` — LIFO discipline.
    pub fn free_frame(&mut self, guard: StackFrameGuard) {
        debug_assert!(self.used >= guard.frame_size);
        self.used -= guard.frame_size;
    }

    pub fn depth_bytes(&self) -> u64 {
        self.used
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_free_roundtrip() {
        let mut pool = GuestStackPool::new(0x1_0000_0000, 0x2000);
        let g1 = pool.alloc_frame(0x200).unwrap();
        assert_eq!(g1.sp(), 0x1_0000_0000 + 0x2000 - 0x200);
        assert_eq!(pool.depth_bytes(), 0x200);
        pool.free_frame(g1);
        assert_eq!(pool.depth_bytes(), 0);
    }

    #[test]
    fn nested_lifo() {
        let mut pool = GuestStackPool::new(0x1_0000_0000, 0x2000);
        let g1 = pool.alloc_frame(0x200).unwrap();
        let g2 = pool.alloc_frame(0x200).unwrap();
        assert!(g2.sp() < g1.sp());
        pool.free_frame(g2);
        pool.free_frame(g1);
        assert_eq!(pool.depth_bytes(), 0);
    }

    #[test]
    fn exhaustion() {
        let mut pool = GuestStackPool::new(0x1_0000_0000, 0x400);
        pool.alloc_frame(0x200).unwrap();
        pool.alloc_frame(0x200).unwrap();
        let err = pool.alloc_frame(0x100).unwrap_err();
        matches!(err, StackPoolError::Exhausted { want: 0x100, .. });
    }
}
