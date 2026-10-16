//! Bump allocator for guest-visible IIB session state.

use fmst_iib_api::types::GuestAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestAllocation {
    pub addr: GuestAddr,
    pub size: usize,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GuestMemoryError {
    #[error("guest memory pool exhausted: want {want}, remaining {remaining}")]
    Exhausted { want: usize, remaining: usize },
    #[error("guest memory alignment must be a non-zero power of two")]
    InvalidAlignment,
}

/// Session-lifetime allocator over a region already mapped by QEMU.
///
/// It deliberately uses monotonic allocation: intervention state is normally
/// short-lived and tied to one runtime session, while deterministic lifetime
/// is more important than pretending arbitrary deallocation is safe across
/// nested hooks. `free` validates ownership but does not reuse memory.
pub struct GuestMemoryPool {
    base: GuestAddr,
    size: usize,
    used: usize,
}

impl GuestMemoryPool {
    pub fn new(base: GuestAddr, size: usize) -> Self {
        Self {
            base,
            size,
            used: 0,
        }
    }

    pub fn alloc(
        &mut self,
        size: usize,
        align: usize,
    ) -> Result<GuestAllocation, GuestMemoryError> {
        if align == 0 || !align.is_power_of_two() {
            return Err(GuestMemoryError::InvalidAlignment);
        }
        let aligned = (self.used + (align - 1)) & !(align - 1);
        let end = aligned
            .checked_add(size)
            .ok_or(GuestMemoryError::Exhausted {
                want: size,
                remaining: self.size.saturating_sub(aligned),
            })?;
        if end > self.size {
            return Err(GuestMemoryError::Exhausted {
                want: size,
                remaining: self.size.saturating_sub(aligned),
            });
        }
        self.used = end;
        let addr = self
            .base
            .checked_add(aligned as u64)
            .ok_or(GuestMemoryError::Exhausted {
                want: size,
                remaining: 0,
            })?;
        Ok(GuestAllocation { addr, size })
    }

    pub fn free(&self, allocation: GuestAllocation) -> Result<(), GuestMemoryError> {
        let start = allocation
            .addr
            .checked_sub(self.base)
            .unwrap_or(self.size as u64);
        if start as usize >= self.size || allocation.size > self.size - start as usize {
            return Err(GuestMemoryError::Exhausted {
                want: allocation.size,
                remaining: 0,
            });
        }
        Ok(())
    }

    pub fn used(&self) -> usize {
        self.used
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocations_are_aligned_and_session_lived() {
        let mut pool = GuestMemoryPool::new(0x7000_0000, 0x100);
        let first = pool.alloc(3, 8).unwrap();
        let second = pool.alloc(4, 16).unwrap();
        assert_eq!(first.addr % 8, 0);
        assert_eq!(second.addr % 16, 0);
        assert_eq!(pool.used(), 20);
        pool.free(first).unwrap();
        assert_eq!(pool.used(), 20);
    }

    #[test]
    fn exhaustion_and_alignment_are_explicit() {
        let mut pool = GuestMemoryPool::new(0x1000, 8);
        assert_eq!(pool.alloc(1, 3), Err(GuestMemoryError::InvalidAlignment));
        assert!(matches!(
            pool.alloc(9, 1),
            Err(GuestMemoryError::Exhausted { .. })
        ));
    }
}
