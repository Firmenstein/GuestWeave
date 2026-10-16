//! Concrete IIBContextOps implementation on top of libafl_qemu primitives.

use crate::native_call::IibState;
use fmst_iib_api::context::IIBContextOps;
use fmst_iib_api::iib_error::IibError;
use fmst_iib_api::types::{Errno, GuestAddr, GuestReg};
use libafl_qemu::{ArchExtras, CallingConvention, Qemu};
use std::any::Any;
use std::cell::Cell;

#[cfg(feature = "arm")]
const DEFAULT_CC: CallingConvention = CallingConvention::Aapcs;
#[cfg(any(feature = "mips", feature = "mipsbe"))]
const DEFAULT_CC: CallingConvention = CallingConvention::MipsO32;
#[cfg(feature = "x86_64")]
const DEFAULT_CC: CallingConvention = CallingConvention::SystemV;

pub struct IIBContextImpl<'a> {
    qemu: Qemu,
    cpu: libafl_qemu::CPU,
    cc: CallingConvention,
    state_ref: &'a (dyn Any + Send + Sync),
    iib_state: &'a IibState,
    callsite_resume_pc: Option<GuestAddr>,
    return_value_set: Cell<bool>,
}

impl<'a> IIBContextImpl<'a> {
    /// Construct from the current CPU context. Must be called from within
    /// a libafl_qemu hook closure (otherwise `current_cpu()` returns None).
    pub fn new(state_ref: &'a (dyn Any + Send + Sync), iib_state: &'a IibState) -> Self {
        let qemu = unsafe { Qemu::get_unchecked() };
        let cpu = qemu
            .current_cpu()
            .expect("IIBContextImpl::new called outside cpu context");
        Self {
            qemu,
            cpu,
            cc: DEFAULT_CC,
            state_ref,
            iib_state,
            callsite_resume_pc: None,
            return_value_set: Cell::new(false),
        }
    }

    /// Construct a context for a call instruction intercepted before the
    /// native call executes. Its return PC is an explicit manifest fact, not
    /// LR/RA/the caller stack, which do not yet contain this call's return.
    pub fn new_callsite(
        state_ref: &'a (dyn Any + Send + Sync),
        iib_state: &'a IibState,
        resume_pc: GuestAddr,
    ) -> Self {
        let mut context = Self::new(state_ref, iib_state);
        context.callsite_resume_pc = Some(resume_pc);
        context
    }

    /// A hook owns intercepted execution only after it explicitly supplies
    /// the caller-visible return value. Merely returning from Rust means that
    /// the original guest call/function must execute unchanged.
    pub(crate) fn return_value_set(&self) -> bool {
        self.return_value_set.get()
    }

    fn read_abi_word(&self, index: u8) -> Result<GuestReg, Errno> {
        #[cfg(any(feature = "arm", feature = "x86_64"))]
        {
            return self
                .cpu
                .read_function_argument_with_cc(index, self.cc.clone())
                .map(|value| value as GuestReg)
                .map_err(|_| Errno::EFAULT);
        }
        #[cfg(any(feature = "mips", feature = "mipsbe"))]
        {
            use libafl_qemu::arch::mips::Regs;
            if index < 4 {
                return self
                    .cpu
                    .read_function_argument_with_cc(index, self.cc.clone())
                    .map(|value| value as GuestReg)
                    .map_err(|_| Errno::EFAULT);
            }

            // MIPS O32 reserves four argument-build words at the entry SP;
            // the fifth argument starts at SP + 16. This is the only stack
            // layout that the current MIPS runtime claims to decode.
            let sp = self
                .cpu
                .read_reg(Regs::Sp)
                .map(|value| value as GuestAddr)
                .map_err(|_| Errno::EFAULT)?;
            let addr = sp
                .checked_add(16 + (index as GuestAddr - 4) * 4)
                .ok_or(Errno::EOVERFLOW)?;
            let mut bytes = [0u8; 4];
            self.qemu
                .read_mem(addr as libafl_qemu::GuestAddr, &mut bytes)
                .map_err(|_| Errno::EFAULT)?;
            return Ok(word_from_bytes(&bytes, 4));
        }
        #[cfg(not(any(
            feature = "arm",
            feature = "mips",
            feature = "mipsbe",
            feature = "x86_64"
        )))]
        {
            let _ = index;
            Err(Errno::ENOSYS)
        }
    }

    fn write_abi_word(&self, index: u8, value: GuestReg) -> Result<(), Errno> {
        #[cfg(any(feature = "arm", feature = "x86_64"))]
        {
            return self
                .cpu
                .write_function_argument_with_cc(
                    index,
                    value as libafl_qemu::GuestReg,
                    self.cc.clone(),
                )
                .map_err(|_| Errno::EFAULT);
        }
        #[cfg(any(feature = "mips", feature = "mipsbe"))]
        {
            use libafl_qemu::arch::mips::Regs;
            if index < 4 {
                return self
                    .cpu
                    .write_function_argument_with_cc(
                        index,
                        value as libafl_qemu::GuestReg,
                        self.cc.clone(),
                    )
                    .map_err(|_| Errno::EFAULT);
            }
            let sp = self
                .cpu
                .read_reg(Regs::Sp)
                .map(|value| value as GuestAddr)
                .map_err(|_| Errno::EFAULT)?;
            let addr = sp
                .checked_add(16 + (index as GuestAddr - 4) * 4)
                .ok_or(Errno::EOVERFLOW)?;
            let bytes = word_to_bytes(value, 4);
            return self
                .qemu
                .write_mem(addr as libafl_qemu::GuestAddr, &bytes)
                .map_err(|_| Errno::EFAULT);
        }
        #[cfg(not(any(
            feature = "arm",
            feature = "mips",
            feature = "mipsbe",
            feature = "x86_64"
        )))]
        {
            let _ = (index, value);
            Err(Errno::ENOSYS)
        }
    }

    fn return_word_count() -> usize {
        #[cfg(any(feature = "arm"))]
        {
            return 4;
        }
        #[cfg(any(feature = "mips", feature = "mipsbe", feature = "x86_64"))]
        {
            return 2;
        }
        #[allow(unreachable_code)]
        0
    }

    fn read_return_word(&self, index: usize) -> Result<GuestReg, Errno> {
        #[cfg(feature = "arm")]
        {
            use libafl_qemu::arch::arm::Regs;
            let reg = match index {
                0 => Regs::R0,
                1 => Regs::R1,
                2 => Regs::R2,
                3 => Regs::R3,
                _ => return Err(Errno::ENOSYS),
            };
            return self
                .cpu
                .read_reg(reg)
                .map(|v| v as GuestReg)
                .map_err(|_| Errno::EFAULT);
        }
        #[cfg(any(feature = "mips", feature = "mipsbe"))]
        {
            use libafl_qemu::arch::mips::Regs;
            let reg = match index {
                0 => Regs::V0,
                1 => Regs::V1,
                _ => return Err(Errno::ENOSYS),
            };
            return self
                .cpu
                .read_reg(reg)
                .map(|v| v as GuestReg)
                .map_err(|_| Errno::EFAULT);
        }
        #[cfg(feature = "x86_64")]
        {
            use libafl_qemu::arch::x86_64::Regs;
            let reg = match index {
                0 => Regs::Rax,
                1 => Regs::Rdx,
                _ => return Err(Errno::ENOSYS),
            };
            return self
                .cpu
                .read_reg(reg)
                .map(|v| v as GuestReg)
                .map_err(|_| Errno::EFAULT);
        }
        #[cfg(not(any(
            feature = "arm",
            feature = "mips",
            feature = "mipsbe",
            feature = "x86_64"
        )))]
        {
            let _ = index;
            Err(Errno::ENOSYS)
        }
    }

    fn write_return_word(&self, index: usize, value: GuestReg) -> Result<(), Errno> {
        #[cfg(feature = "arm")]
        {
            use libafl_qemu::arch::arm::Regs;
            let reg = match index {
                0 => Regs::R0,
                1 => Regs::R1,
                2 => Regs::R2,
                3 => Regs::R3,
                _ => return Err(Errno::ENOSYS),
            };
            return self
                .cpu
                .write_reg(reg, value as libafl_qemu::GuestReg)
                .map_err(|_| Errno::EFAULT);
        }
        #[cfg(any(feature = "mips", feature = "mipsbe"))]
        {
            use libafl_qemu::arch::mips::Regs;
            let reg = match index {
                0 => Regs::V0,
                1 => Regs::V1,
                _ => return Err(Errno::ENOSYS),
            };
            return self
                .cpu
                .write_reg(reg, value as libafl_qemu::GuestReg)
                .map_err(|_| Errno::EFAULT);
        }
        #[cfg(feature = "x86_64")]
        {
            use libafl_qemu::arch::x86_64::Regs;
            let reg = match index {
                0 => Regs::Rax,
                1 => Regs::Rdx,
                _ => return Err(Errno::ENOSYS),
            };
            return self
                .cpu
                .write_reg(reg, value as libafl_qemu::GuestReg)
                .map_err(|_| Errno::EFAULT);
        }
        #[cfg(not(any(
            feature = "arm",
            feature = "mips",
            feature = "mipsbe",
            feature = "x86_64"
        )))]
        {
            let _ = (index, value);
            Err(Errno::ENOSYS)
        }
    }
}

// Trait impl: read_arg, write_arg, read_mem, write_mem, read_reg, write_reg,
// current_pc, return_address added in Tasks 21–23.
// set_return_value + native_call added in Tasks 24, 29+.
impl<'a> IIBContextOps for IIBContextImpl<'a> {
    fn read_arg(&self, idx: u8) -> Result<GuestReg, Errno> {
        self.read_abi_word(idx)
    }

    fn write_arg(&self, idx: u8, val: GuestReg) -> Result<(), Errno> {
        self.write_abi_word(idx, val)
    }

    fn read_arg_words(&self, index: u8, word_count: u8) -> Result<Vec<GuestReg>, Errno> {
        (0..word_count)
            .map(|offset| {
                let slot = index.checked_add(offset).ok_or(Errno::EOVERFLOW)?;
                self.read_abi_word(slot)
            })
            .collect()
    }

    fn read_arg_bytes(&self, index: u8, size: usize) -> Result<Vec<u8>, Errno> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let width = abi_word_size();
        let count = size.checked_add(width - 1).ok_or(Errno::EOVERFLOW)? / width;
        if count > u8::MAX as usize || (index as usize).checked_add(count - 1).is_none() {
            return Err(Errno::EOVERFLOW);
        }
        let mut bytes = Vec::with_capacity(count * width);
        for word in self.read_arg_words(index, count as u8)? {
            bytes.extend_from_slice(&word_to_bytes(word, width));
        }
        bytes.truncate(size);
        Ok(bytes)
    }

    fn write_arg_bytes(&self, index: u8, data: &[u8]) -> Result<(), Errno> {
        if data.is_empty() {
            return Ok(());
        }
        let width = abi_word_size();
        let count = data.len().checked_add(width - 1).ok_or(Errno::EOVERFLOW)? / width;
        if count > u8::MAX as usize || (index as usize).checked_add(count - 1).is_none() {
            return Err(Errno::EOVERFLOW);
        }
        let mut existing = self.read_arg_words(index, count as u8)?;
        for (word_index, chunk) in data.chunks(width).enumerate() {
            let mut word_bytes = word_to_bytes(existing[word_index], width);
            word_bytes[..chunk.len()].copy_from_slice(chunk);
            existing[word_index] = word_from_bytes(&word_bytes, width);
        }
        for (offset, word) in existing.into_iter().enumerate() {
            self.write_abi_word(index + offset as u8, word)?;
        }
        Ok(())
    }

    fn set_return_value(&self, val: GuestReg) -> Result<(), Errno> {
        #[cfg(feature = "arm")]
        {
            use libafl_qemu::arch::arm::Regs;
            // Write return value to R0 (per AAPCS).
            self.cpu
                .write_reg(Regs::R0, val as libafl_qemu::GuestReg)
                .map_err(|_| Errno::EINVAL)?;
            if let Some(resume_pc) = self.callsite_resume_pc {
                self.cpu
                    .write_reg(Regs::R15, resume_pc as libafl_qemu::GuestReg)
                    .map_err(|_| Errno::EINVAL)?;
                self.return_value_set.set(true);
                return Ok(());
            }
            // Skip the original function: PC <- LR (the caller's return address).
            let lr = self.cpu.read_reg(Regs::R14).map_err(|_| Errno::EINVAL)?;
            self.cpu
                .write_reg(Regs::R15, lr)
                .map_err(|_| Errno::EINVAL)?;
            self.return_value_set.set(true);
            Ok(())
        }
        #[cfg(any(feature = "mips", feature = "mipsbe"))]
        {
            use libafl_qemu::arch::mips::Regs;
            // Write return value to V0 (per MIPS O32).
            self.cpu
                .write_reg(Regs::V0, val as libafl_qemu::GuestReg)
                .map_err(|_| Errno::EINVAL)?;
            if let Some(resume_pc) = self.callsite_resume_pc {
                self.cpu
                    .write_reg(Regs::Pc, resume_pc as libafl_qemu::GuestReg)
                    .map_err(|_| Errno::EINVAL)?;
                self.return_value_set.set(true);
                return Ok(());
            }
            // Skip the original function: PC <- RA (the caller's return address).
            let ra = self.cpu.read_reg(Regs::Ra).map_err(|_| Errno::EINVAL)?;
            self.cpu
                .write_reg(Regs::Pc, ra)
                .map_err(|_| Errno::EINVAL)?;
            self.return_value_set.set(true);
            Ok(())
        }
        #[cfg(feature = "x86_64")]
        {
            use libafl_qemu::arch::x86_64::Regs;
            // x86_64 `ret` semantics: pop [RSP] into RIP, then RSP += 8.
            // Return value goes in RAX (per SystemV).
            self.cpu
                .write_reg(Regs::Rax, val as libafl_qemu::GuestReg)
                .map_err(|_| Errno::EINVAL)?;
            if let Some(resume_pc) = self.callsite_resume_pc {
                self.cpu
                    .write_reg(Regs::Rip, resume_pc as libafl_qemu::GuestReg)
                    .map_err(|_| Errno::EINVAL)?;
                self.return_value_set.set(true);
                return Ok(());
            }
            let ret = <libafl_qemu::CPU as ArchExtras>::read_return_address(&self.cpu)
                .map_err(|_| Errno::EINVAL)?;
            let rsp = self.cpu.read_reg(Regs::Rsp).map_err(|_| Errno::EINVAL)?;
            self.cpu
                .write_reg(Regs::Rsp, rsp.wrapping_add(8))
                .map_err(|_| Errno::EINVAL)?;
            self.cpu
                .write_reg(Regs::Rip, ret as libafl_qemu::GuestReg)
                .map_err(|_| Errno::EINVAL)?;
            self.return_value_set.set(true);
            Ok(())
        }
        #[cfg(not(any(
            feature = "arm",
            feature = "mips",
            feature = "mipsbe",
            feature = "x86_64"
        )))]
        {
            let _ = val;
            unimplemented!("set_return_value: no arch feature enabled")
        }
    }

    fn read_return_bytes(&self, size: usize) -> Result<Vec<u8>, Errno> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let width = abi_word_size();
        let count = size.checked_add(width - 1).ok_or(Errno::EOVERFLOW)? / width;
        if count > Self::return_word_count() {
            return Err(Errno::ENOSYS);
        }
        let mut bytes = Vec::with_capacity(count * width);
        for index in 0..count {
            bytes.extend_from_slice(&word_to_bytes(self.read_return_word(index)?, width));
        }
        bytes.truncate(size);
        Ok(bytes)
    }

    fn write_return_bytes(&self, data: &[u8]) -> Result<(), Errno> {
        if data.is_empty() {
            return Ok(());
        }
        let width = abi_word_size();
        let count = data.len().checked_add(width - 1).ok_or(Errno::EOVERFLOW)? / width;
        if count > Self::return_word_count() {
            return Err(Errno::ENOSYS);
        }
        let mut existing = (0..count)
            .map(|index| self.read_return_word(index))
            .collect::<Result<Vec<_>, _>>()?;
        for (word_index, chunk) in data.chunks(width).enumerate() {
            let mut word_bytes = word_to_bytes(existing[word_index], width);
            word_bytes[..chunk.len()].copy_from_slice(chunk);
            existing[word_index] = word_from_bytes(&word_bytes, width);
        }
        for (index, word) in existing.into_iter().enumerate() {
            self.write_return_word(index, word)?;
        }
        Ok(())
    }

    fn read_reg(&self, name: &str) -> Result<GuestReg, Errno> {
        #[cfg(feature = "arm")]
        {
            let reg_id = arm_reg_id_by_name(name).ok_or(Errno::EINVAL)?;
            self.cpu
                .read_reg(reg_id)
                .map(|v| v as GuestReg)
                .map_err(|_| Errno::EINVAL)
        }
        #[cfg(any(feature = "mips", feature = "mipsbe"))]
        {
            let reg_id = mips_reg_id_by_name(name).ok_or(Errno::EINVAL)?;
            self.cpu
                .read_reg(reg_id)
                .map(|v| v as GuestReg)
                .map_err(|_| Errno::EINVAL)
        }
        #[cfg(feature = "x86_64")]
        {
            let reg_id = x86_64_reg_id_by_name(name).ok_or(Errno::EINVAL)?;
            self.cpu
                .read_reg(reg_id)
                .map(|v| v as GuestReg)
                .map_err(|_| Errno::EINVAL)
        }
        #[cfg(not(any(
            feature = "arm",
            feature = "mips",
            feature = "mipsbe",
            feature = "x86_64"
        )))]
        {
            let _ = name;
            Err(Errno::EINVAL)
        }
    }

    fn write_reg(&self, name: &str, val: GuestReg) -> Result<(), Errno> {
        #[cfg(feature = "arm")]
        {
            let reg_id = arm_reg_id_by_name(name).ok_or(Errno::EINVAL)?;
            self.cpu
                .write_reg(reg_id, val as libafl_qemu::GuestReg)
                .map_err(|_| Errno::EINVAL)
        }
        #[cfg(any(feature = "mips", feature = "mipsbe"))]
        {
            let reg_id = mips_reg_id_by_name(name).ok_or(Errno::EINVAL)?;
            self.cpu
                .write_reg(reg_id, val as libafl_qemu::GuestReg)
                .map_err(|_| Errno::EINVAL)
        }
        #[cfg(feature = "x86_64")]
        {
            let reg_id = x86_64_reg_id_by_name(name).ok_or(Errno::EINVAL)?;
            self.cpu
                .write_reg(reg_id, val as libafl_qemu::GuestReg)
                .map_err(|_| Errno::EINVAL)
        }
        #[cfg(not(any(
            feature = "arm",
            feature = "mips",
            feature = "mipsbe",
            feature = "x86_64"
        )))]
        {
            let _ = (name, val);
            Err(Errno::EINVAL)
        }
    }

    fn current_pc(&self) -> GuestAddr {
        #[cfg(feature = "arm")]
        {
            self.cpu
                .read_reg(libafl_qemu::arch::arm::Regs::Pc)
                .map(|v| v as GuestAddr)
                .unwrap_or(0)
        }
        #[cfg(any(feature = "mips", feature = "mipsbe"))]
        {
            self.cpu
                .read_reg(libafl_qemu::arch::mips::Regs::Pc)
                .map(|v| v as GuestAddr)
                .unwrap_or(0)
        }
        #[cfg(feature = "x86_64")]
        {
            self.cpu
                .read_reg(libafl_qemu::arch::x86_64::Regs::Rip)
                .map(|v| v as GuestAddr)
                .unwrap_or(0)
        }
        #[cfg(not(any(
            feature = "arm",
            feature = "mips",
            feature = "mipsbe",
            feature = "x86_64"
        )))]
        {
            0
        }
    }

    fn return_address(&self) -> Result<GuestAddr, Errno> {
        if let Some(resume_pc) = self.callsite_resume_pc {
            return Ok(resume_pc);
        }
        self.cpu
            .read_return_address()
            .map(|v| v as GuestAddr)
            .map_err(|_| Errno::EINVAL)
    }
    fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Errno> {
        self.qemu
            .read_mem(addr as libafl_qemu::GuestAddr, buf)
            .map_err(|_| Errno::EFAULT)
    }

    fn write_mem(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), Errno> {
        self.qemu
            .write_mem(addr as libafl_qemu::GuestAddr, buf)
            .map_err(|_| Errno::EFAULT)
    }

    fn alloc_guest(&self, size: usize, align: usize) -> Result<GuestAddr, Errno> {
        self.iib_state
            .guest_memory
            .lock()
            .map_err(|_| Errno::EBUSY)?
            .alloc(size, align)
            .map(|allocation| allocation.addr)
            .map_err(|_| Errno::ENOMEM)
    }

    fn free_guest(&self, addr: GuestAddr, size: usize) -> Result<(), Errno> {
        self.iib_state
            .guest_memory
            .lock()
            .map_err(|_| Errno::EBUSY)?
            .free(crate::guest_memory::GuestAllocation { addr, size })
            .map_err(|_| Errno::EINVAL)
    }

    fn read_u16(&self, addr: GuestAddr) -> Result<u16, Errno> {
        let mut bytes = [0u8; 2];
        self.read_mem(addr, &mut bytes)?;
        #[cfg(feature = "mipsbe")]
        return Ok(u16::from_be_bytes(bytes));
        #[cfg(not(feature = "mipsbe"))]
        Ok(u16::from_le_bytes(bytes))
    }

    fn read_u32(&self, addr: GuestAddr) -> Result<u32, Errno> {
        let mut bytes = [0u8; 4];
        self.read_mem(addr, &mut bytes)?;
        #[cfg(feature = "mipsbe")]
        return Ok(u32::from_be_bytes(bytes));
        #[cfg(not(feature = "mipsbe"))]
        Ok(u32::from_le_bytes(bytes))
    }

    fn read_u64(&self, addr: GuestAddr) -> Result<u64, Errno> {
        let mut bytes = [0u8; 8];
        self.read_mem(addr, &mut bytes)?;
        #[cfg(feature = "mipsbe")]
        return Ok(u64::from_be_bytes(bytes));
        #[cfg(not(feature = "mipsbe"))]
        Ok(u64::from_le_bytes(bytes))
    }

    fn write_u16(&self, addr: GuestAddr, value: u16) -> Result<(), Errno> {
        #[cfg(feature = "mipsbe")]
        return self.write_mem(addr, &value.to_be_bytes());
        #[cfg(not(feature = "mipsbe"))]
        self.write_mem(addr, &value.to_le_bytes())
    }

    fn write_u32(&self, addr: GuestAddr, value: u32) -> Result<(), Errno> {
        #[cfg(feature = "mipsbe")]
        return self.write_mem(addr, &value.to_be_bytes());
        #[cfg(not(feature = "mipsbe"))]
        self.write_mem(addr, &value.to_le_bytes())
    }

    fn write_u64(&self, addr: GuestAddr, value: u64) -> Result<(), Errno> {
        #[cfg(feature = "mipsbe")]
        return self.write_mem(addr, &value.to_be_bytes());
        #[cfg(not(feature = "mipsbe"))]
        self.write_mem(addr, &value.to_le_bytes())
    }

    fn state(&self) -> &(dyn Any + Send + Sync) {
        self.state_ref
    }

    fn native_call(&mut self, target: GuestAddr, args: &[GuestReg]) -> Result<GuestReg, IibError> {
        #[cfg(feature = "arm")]
        {
            crate::native_call::native_call_arm(self.qemu, self.iib_state, target, args, false)
        }
        #[cfg(any(feature = "mips", feature = "mipsbe"))]
        {
            crate::native_call::native_call_mips(self.qemu, self.iib_state, target, args, false)
        }
        #[cfg(feature = "x86_64")]
        {
            crate::native_call::native_call_x86_64(self.qemu, self.iib_state, target, args, false)
        }
        #[cfg(not(any(
            feature = "arm",
            feature = "mips",
            feature = "mipsbe",
            feature = "x86_64"
        )))]
        {
            let _ = (target, args);
            unimplemented!("native_call: no arch feature enabled")
        }
    }

    fn native_call_runtime(&mut self, target: GuestAddr, args: &[GuestReg]) -> Result<GuestReg, IibError> {
        #[cfg(feature = "arm")]
        { crate::native_call::native_call_arm(self.qemu, self.iib_state, target, args, true) }
        #[cfg(any(feature = "mips", feature = "mipsbe"))]
        { crate::native_call::native_call_mips(self.qemu, self.iib_state, target, args, true) }
        #[cfg(feature = "x86_64")]
        { crate::native_call::native_call_x86_64(self.qemu, self.iib_state, target, args, true) }
    }
}

fn abi_word_size() -> usize {
    #[cfg(any(feature = "arm", feature = "mips", feature = "mipsbe"))]
    {
        return 4;
    }
    #[cfg(feature = "x86_64")]
    {
        return 8;
    }
    #[allow(unreachable_code)]
    0
}

fn word_to_bytes(value: GuestReg, width: usize) -> Vec<u8> {
    let bytes = if cfg!(feature = "mipsbe") {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    if cfg!(feature = "mipsbe") {
        bytes[bytes.len() - width..].to_vec()
    } else {
        bytes[..width].to_vec()
    }
}

fn word_from_bytes(bytes: &[u8], width: usize) -> GuestReg {
    let mut padded = [0u8; 8];
    if cfg!(feature = "mipsbe") {
        padded[8 - width..].copy_from_slice(bytes);
        u64::from_be_bytes(padded)
    } else {
        padded[..width].copy_from_slice(bytes);
        u64::from_le_bytes(padded)
    }
}

#[cfg(feature = "arm")]
fn arm_reg_id_by_name(name: &str) -> Option<libafl_qemu::arch::arm::Regs> {
    use libafl_qemu::arch::arm::Regs;
    let lc = name.to_ascii_lowercase();
    match lc.as_str() {
        "r0" => Some(Regs::R0),
        "r1" => Some(Regs::R1),
        "r2" => Some(Regs::R2),
        "r3" => Some(Regs::R3),
        "r4" => Some(Regs::R4),
        "r5" => Some(Regs::R5),
        "r6" => Some(Regs::R6),
        "r7" => Some(Regs::R7),
        "r8" => Some(Regs::R8),
        "r9" => Some(Regs::R9),
        "r10" => Some(Regs::R10),
        "r11" => Some(Regs::R11),
        "r12" => Some(Regs::R12),
        "r13" | "sp" => Some(Regs::R13),
        "r14" | "lr" => Some(Regs::R14),
        "r15" | "pc" => Some(Regs::R15),
        "cpsr" => Some(Regs::R25),
        _ => None,
    }
}

#[cfg(any(feature = "mips", feature = "mipsbe"))]
fn mips_reg_id_by_name(name: &str) -> Option<libafl_qemu::arch::mips::Regs> {
    use libafl_qemu::arch::mips::Regs;
    let lc = name.to_ascii_lowercase();
    match lc.as_str() {
        "zero" | "r0" => Some(Regs::R0),
        "at" => Some(Regs::At),
        "v0" => Some(Regs::V0),
        "v1" => Some(Regs::V1),
        "a0" => Some(Regs::A0),
        "a1" => Some(Regs::A1),
        "a2" => Some(Regs::A2),
        "a3" => Some(Regs::A3),
        "t0" => Some(Regs::T0),
        "t1" => Some(Regs::T1),
        "t2" => Some(Regs::T2),
        "t3" => Some(Regs::T3),
        "t4" => Some(Regs::T4),
        "t5" => Some(Regs::T5),
        "t6" => Some(Regs::T6),
        "t7" => Some(Regs::T7),
        "s0" => Some(Regs::S0),
        "s1" => Some(Regs::S1),
        "s2" => Some(Regs::S2),
        "s3" => Some(Regs::S3),
        "s4" => Some(Regs::S4),
        "s5" => Some(Regs::S5),
        "s6" => Some(Regs::S6),
        "s7" => Some(Regs::S7),
        "t8" => Some(Regs::T8),
        "t9" => Some(Regs::T9),
        "k0" => Some(Regs::K0),
        "k1" => Some(Regs::K1),
        "gp" => Some(Regs::Gp),
        "sp" => Some(Regs::Sp),
        "fp" | "s8" => Some(Regs::Fp),
        "ra" => Some(Regs::Ra),
        "pc" => Some(Regs::Pc),
        _ => None,
    }
}

#[cfg(feature = "x86_64")]
fn x86_64_reg_id_by_name(name: &str) -> Option<libafl_qemu::arch::x86_64::Regs> {
    use libafl_qemu::arch::x86_64::Regs;
    let lc = name.to_ascii_lowercase();
    match lc.as_str() {
        "rax" => Some(Regs::Rax),
        "rbx" => Some(Regs::Rbx),
        "rcx" => Some(Regs::Rcx),
        "rdx" => Some(Regs::Rdx),
        "rsi" => Some(Regs::Rsi),
        "rdi" => Some(Regs::Rdi),
        "rbp" => Some(Regs::Rbp),
        "rsp" | "sp" => Some(Regs::Rsp),
        "r8" => Some(Regs::R8),
        "r9" => Some(Regs::R9),
        "r10" => Some(Regs::R10),
        "r11" => Some(Regs::R11),
        "r12" => Some(Regs::R12),
        "r13" => Some(Regs::R13),
        "r14" => Some(Regs::R14),
        "r15" => Some(Regs::R15),
        "rip" | "pc" => Some(Regs::Rip),
        "rflags" | "eflags" => Some(Regs::Rflags),
        _ => None,
    }
}
