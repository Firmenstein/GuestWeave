//! Hand-curated POSIX argument decoders.
//!
//! v1 only covers the APIs referenced in the initial diagnostic reports.
//! Grow as new targets surface new API needs.

use crate::context::IIBContextOps;
use crate::types::{Errno, GuestAddr};

pub struct OpenArgs {
    pub path: GuestAddr,
    pub flags: i32,
    pub mode: i32,
}

impl OpenArgs {
    pub fn from_ctx(ctx: &dyn IIBContextOps) -> Result<Self, Errno> {
        Ok(Self {
            path: ctx.read_arg(0)? as GuestAddr,
            flags: ctx.read_arg(1)? as i32,
            mode: ctx.read_arg(2)? as i32,
        })
    }
}

pub struct IoctlArgs {
    pub fd: i32,
    pub cmd: u32,
    pub arg: GuestAddr,
}

impl IoctlArgs {
    pub fn from_ctx(ctx: &dyn IIBContextOps) -> Result<Self, Errno> {
        Ok(Self {
            fd: ctx.read_arg(0)? as i32,
            cmd: ctx.read_arg(1)? as u32,
            arg: ctx.read_arg(2)? as GuestAddr,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iib_error::IibError;
    use crate::types::GuestReg;
    use std::any::Any;

    /// Minimal mock IIBContextOps that returns canned register values.
    struct MockCtx {
        args: [GuestReg; 6],
    }

    impl IIBContextOps for MockCtx {
        fn read_arg(&self, idx: u8) -> Result<GuestReg, Errno> {
            self.args.get(idx as usize).copied().ok_or(Errno::EINVAL)
        }
        fn write_arg(&self, _: u8, _: GuestReg) -> Result<(), Errno> {
            unimplemented!()
        }
        fn set_return_value(&self, _: GuestReg) -> Result<(), Errno> {
            unimplemented!()
        }
        fn read_reg(&self, _: &str) -> Result<GuestReg, Errno> {
            unimplemented!()
        }
        fn write_reg(&self, _: &str, _: GuestReg) -> Result<(), Errno> {
            unimplemented!()
        }
        fn current_pc(&self) -> GuestAddr {
            0
        }
        fn return_address(&self) -> Result<GuestAddr, Errno> {
            unimplemented!()
        }
        fn read_mem(&self, _: GuestAddr, _: &mut [u8]) -> Result<(), Errno> {
            unimplemented!()
        }
        fn write_mem(&self, _: GuestAddr, _: &[u8]) -> Result<(), Errno> {
            unimplemented!()
        }
        fn state(&self) -> &(dyn Any + Send + Sync) {
            &()
        }
        fn native_call(&mut self, _: GuestAddr, _: &[GuestReg]) -> Result<GuestReg, IibError> {
            unimplemented!()
        }
    }

    #[test]
    fn open_args_parsed_in_order() {
        let ctx = MockCtx {
            args: [0xdead_beef, 2, 0o644, 0, 0, 0],
        };
        let a = OpenArgs::from_ctx(&ctx).unwrap();
        assert_eq!(a.path, 0xdead_beef);
        assert_eq!(a.flags, 2);
        assert_eq!(a.mode, 0o644);
    }

    #[test]
    fn ioctl_args_parsed_in_order() {
        let ctx = MockCtx {
            args: [5, 0x8004_644D, 0x1000_0000, 0, 0, 0],
        };
        let a = IoctlArgs::from_ctx(&ctx).unwrap();
        assert_eq!(a.fd, 5);
        assert_eq!(a.cmd, 0x8004_644D);
        assert_eq!(a.arg, 0x1000_0000);
    }

    struct MockCtxWithMem {
        args: [GuestReg; 6],
        mem: std::collections::HashMap<GuestAddr, u8>,
    }

    impl IIBContextOps for MockCtxWithMem {
        fn read_arg(&self, idx: u8) -> Result<GuestReg, Errno> {
            self.args.get(idx as usize).copied().ok_or(Errno::EINVAL)
        }
        fn write_arg(&self, _: u8, _: GuestReg) -> Result<(), Errno> {
            unimplemented!()
        }
        fn set_return_value(&self, _: GuestReg) -> Result<(), Errno> {
            unimplemented!()
        }
        fn read_reg(&self, _: &str) -> Result<GuestReg, Errno> {
            unimplemented!()
        }
        fn write_reg(&self, _: &str, _: GuestReg) -> Result<(), Errno> {
            unimplemented!()
        }
        fn current_pc(&self) -> GuestAddr {
            0
        }
        fn return_address(&self) -> Result<GuestAddr, Errno> {
            unimplemented!()
        }
        fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Errno> {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = self
                    .mem
                    .get(&(addr + i as u64))
                    .copied()
                    .ok_or(Errno::EFAULT)?;
            }
            Ok(())
        }
        fn write_mem(&self, _: GuestAddr, _: &[u8]) -> Result<(), Errno> {
            unimplemented!()
        }
        fn state(&self) -> &(dyn Any + Send + Sync) {
            &()
        }
        fn native_call(&mut self, _: GuestAddr, _: &[GuestReg]) -> Result<GuestReg, IibError> {
            unimplemented!()
        }
    }

    #[test]
    fn read_cstr_stops_at_null() {
        let bytes = b"hello\0rest";
        let mem: std::collections::HashMap<_, _> = bytes
            .iter()
            .enumerate()
            .map(|(i, b)| (0x1000 + i as u64, *b))
            .collect();
        let ctx = MockCtxWithMem { args: [0; 6], mem };
        let s = ctx.read_cstr(0x1000, 64).unwrap();
        assert_eq!(s.to_bytes(), b"hello");
    }
}
