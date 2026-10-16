//! An explicit read-only byte stream; no firmware paths or device contents.
//! Run with `cargo run --example pseudo_file --features mock`.
//! This is an offline API example, not a guest or exec-handoff test.

use guestweave::api::{mock::MockIIBContextOps, Errno, GuestAddr, IIBContextOps, PseudoFile};

struct ByteStream {
    bytes: Vec<u8>,
    offset: usize,
}

impl PseudoFile for ByteStream {
    fn read(
        &mut self,
        buf: GuestAddr,
        len: usize,
        ctx: &mut dyn IIBContextOps,
    ) -> Result<usize, Errno> {
        let count = len.min(self.bytes.len().saturating_sub(self.offset));
        if count != 0 {
            ctx.write_mem(buf, &self.bytes[self.offset..self.offset + count])?;
            self.offset += count;
        }
        Ok(count)
    }
}

fn main() {
    let mut file = ByteStream {
        bytes: b"hello".to_vec(),
        offset: 0,
    };
    let mut ctx = MockIIBContextOps::new();
    let address = ctx.alloc_guest(8, 1).unwrap();
    assert_eq!(file.read(address, 2, &mut ctx), Ok(2));
    assert_eq!(ctx.memory_slice(address, 2), b"he");
    assert_eq!(file.read(address, 8, &mut ctx), Ok(3));
    assert_eq!(ctx.memory_slice(address, 3), b"llo");
    assert_eq!(file.read(address, 8, &mut ctx), Ok(0));
    // The descriptor is owned: an unsupported operation remains a guest error.
    assert_eq!(file.write(address, 1, &mut ctx), Err(Errno::ENOSYS));
    // This example does not claim cross-exec state persistence.
    assert_eq!(file.exec_snapshot(), Ok(None));
    println!("partial reads, EOF, guest-memory writes and unsupported operation verified");
}
