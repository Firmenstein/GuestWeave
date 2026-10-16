//! MockIIBContextOps — a host-side, feature-gated implementation of the
//! IIBContextOps trait for unit testing intervention code without QEMU.
//!
//! Feature: `mock`. Intervention crates add this as a dev-dependency only.
//!
//! Design notes (per spec §9):
//! - Sparse memory via BTreeMap<GuestAddr, u8>. `read_mem` errors if any
//!   requested byte is unset (EFAULT).
//! - named registers are kept in a small architecture-neutral map so tests
//!   can exercise an explicitly declared register escape hatch without a
//!   QEMU process.
//! - native_call logs every invocation; returns programmed response or
//!   Err(IibError::NoResponseProgrammed).
//! - return_value uses Cell<Option<...>> because IIBContextOps
//!   `set_return_value` takes &self.

use crate::context::IIBContextOps;
use crate::iib_error::IibError;
use crate::types::{Errno, GuestAddr, GuestReg};
use std::any::Any;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

pub struct MockIIBContextOps {
    args: RefCell<BTreeMap<u8, GuestReg>>,
    registers: RefCell<BTreeMap<String, GuestReg>>,
    return_words: RefCell<BTreeMap<usize, GuestReg>>,
    memory: RefCell<BTreeMap<GuestAddr, u8>>,
    state: Box<dyn Any + Send + Sync>,
    return_value: Cell<Option<GuestReg>>,
    return_address: Cell<GuestAddr>,
    current_pc: Cell<GuestAddr>,
    stack_pointer: Cell<GuestAddr>,
    native_call_responses: RefCell<BTreeMap<GuestAddr, Result<GuestReg, IibError>>>,
    native_call_log: RefCell<Vec<(GuestAddr, Vec<GuestReg>)>>,
    guest_alloc_next: Cell<GuestAddr>,
}

impl MockIIBContextOps {
    pub fn new() -> Self {
        Self {
            args: RefCell::new(BTreeMap::new()),
            registers: RefCell::new(BTreeMap::new()),
            return_words: RefCell::new(BTreeMap::new()),
            memory: RefCell::new(BTreeMap::new()),
            state: Box::new(()),
            return_value: Cell::new(None),
            return_address: Cell::new(0),
            current_pc: Cell::new(0),
            stack_pointer: Cell::new(0),
            native_call_responses: RefCell::new(BTreeMap::new()),
            native_call_log: RefCell::new(Vec::new()),
            guest_alloc_next: Cell::new(0x6000_0000),
        }
    }

    // ---------- Pre-intercept seeding (chainable) ----------

    pub fn set_arg(&mut self, idx: u8, val: GuestReg) -> &mut Self {
        self.args.borrow_mut().insert(idx, val);
        self
    }

    pub fn set_memory(&mut self, addr: GuestAddr, data: &[u8]) -> &mut Self {
        {
            let mut mem = self.memory.borrow_mut();
            for (i, b) in data.iter().enumerate() {
                mem.insert(addr + i as GuestAddr, *b);
            }
        }
        self
    }

    pub fn set_state<T: Any + Send + Sync>(&mut self, s: T) -> &mut Self {
        self.state = Box::new(s);
        self
    }

    pub fn set_return_address(&mut self, a: GuestAddr) -> &mut Self {
        self.return_address.set(a);
        self
    }

    pub fn set_current_pc(&mut self, pc: GuestAddr) -> &mut Self {
        self.current_pc.set(pc);
        self
    }

    pub fn set_stack_pointer(&mut self, sp: GuestAddr) -> &mut Self {
        self.stack_pointer.set(sp);
        self.registers.borrow_mut().insert("sp".to_owned(), sp);
        self
    }

    /// Seed a named register for an ABI-specific intervention test.
    /// Register names are case-insensitive and otherwise intentionally opaque
    /// to keep the mock independent of one guest architecture.
    pub fn set_reg(&mut self, name: &str, value: GuestReg) -> &mut Self {
        let name = normalize_register_name(name);
        self.registers.borrow_mut().insert(name.clone(), value);
        match name.as_str() {
            "sp" => self.stack_pointer.set(value),
            "pc" => self.current_pc.set(value),
            _ => {}
        }
        self
    }

    pub fn set_native_call_response(
        &mut self,
        target: GuestAddr,
        r: Result<GuestReg, IibError>,
    ) -> &mut Self {
        self.native_call_responses.borrow_mut().insert(target, r);
        self
    }

    // ---------- Post-intercept observation ----------

    /// Value supplied by an explicit `set_return_value` replacement.
    /// Register-only writes do not complete a hook's return path; inspect
    /// those separately with `read_return_bytes`.
    pub fn return_value(&self) -> Option<GuestReg> {
        self.return_value.get()
    }

    pub fn memory_slice(&self, addr: GuestAddr, len: usize) -> Vec<u8> {
        let mem = self.memory.borrow();
        (0..len)
            .map(|i| mem.get(&(addr + i as GuestAddr)).copied().unwrap_or(0))
            .collect()
    }

    pub fn native_call_invocations(&self) -> Vec<(GuestAddr, Vec<GuestReg>)> {
        self.native_call_log.borrow().clone()
    }

    pub fn state_ref<T: Any>(&self) -> Option<&T> {
        self.state.downcast_ref()
    }
}

impl Default for MockIIBContextOps {
    fn default() -> Self {
        Self::new()
    }
}

impl IIBContextOps for MockIIBContextOps {
    fn read_arg(&self, idx: u8) -> Result<GuestReg, Errno> {
        self.args.borrow().get(&idx).copied().ok_or(Errno::EINVAL)
    }

    fn read_arg_words(&self, index: u8, word_count: u8) -> Result<Vec<GuestReg>, Errno> {
        (0..word_count)
            .map(|offset| {
                let slot = index.checked_add(offset).ok_or(Errno::EOVERFLOW)?;
                self.args.borrow().get(&slot).copied().ok_or(Errno::EINVAL)
            })
            .collect()
    }

    fn read_arg_bytes(&self, index: u8, size: usize) -> Result<Vec<u8>, Errno> {
        let count = word_count_for(size);
        let count = u8::try_from(count).map_err(|_| Errno::EOVERFLOW)?;
        read_words_as_bytes(self.read_arg_words(index, count)?, size)
    }

    fn write_arg_bytes(&self, index: u8, data: &[u8]) -> Result<(), Errno> {
        write_bytes_to_words(
            data,
            word_count_for(data.len()),
            |word| self.args.borrow().get(&word).copied().ok_or(Errno::EINVAL),
            |word, value| {
                self.args.borrow_mut().insert(word, value);
                Ok(())
            },
            index,
        )
    }

    fn write_arg(&self, idx: u8, val: GuestReg) -> Result<(), Errno> {
        self.args.borrow_mut().insert(idx, val);
        Ok(())
    }

    fn set_return_value(&self, val: GuestReg) -> Result<(), Errno> {
        self.return_words.borrow_mut().insert(0, val);
        self.return_value.set(Some(val));
        Ok(())
    }

    fn read_return_bytes(&self, size: usize) -> Result<Vec<u8>, Errno> {
        let count = word_count_for(size);
        if count > return_word_count() {
            return Err(Errno::ENOSYS);
        }
        let words = (0..count)
            .map(|index| {
                self.return_words
                    .borrow()
                    .get(&index)
                    .copied()
                    .ok_or(Errno::EINVAL)
            })
            .collect::<Result<Vec<_>, _>>()?;
        read_words_as_bytes(words, size)
    }

    fn write_return_bytes(&self, data: &[u8]) -> Result<(), Errno> {
        let count = word_count_for(data.len());
        if count > return_word_count() {
            return Err(Errno::ENOSYS);
        }
        write_bytes_to_words(
            data,
            count,
            |word| {
                Ok(self
                    .return_words
                    .borrow()
                    .get(&(word as usize))
                    .copied()
                    .unwrap_or(0))
            },
            |word, value| {
                self.return_words.borrow_mut().insert(word as usize, value);
                Ok(())
            },
            0,
        )
    }

    fn read_reg(&self, name: &str) -> Result<GuestReg, Errno> {
        self.registers
            .borrow()
            .get(&normalize_register_name(name))
            .copied()
            .ok_or(Errno::EINVAL)
    }

    fn write_reg(&self, name: &str, val: GuestReg) -> Result<(), Errno> {
        let name = normalize_register_name(name);
        self.registers.borrow_mut().insert(name.clone(), val);
        match name.as_str() {
            "sp" => self.stack_pointer.set(val),
            "pc" => self.current_pc.set(val),
            _ => {}
        }
        Ok(())
    }

    fn current_pc(&self) -> GuestAddr {
        self.current_pc.get()
    }

    fn return_address(&self) -> Result<GuestAddr, Errno> {
        Ok(self.return_address.get())
    }

    fn read_mem(&self, addr: GuestAddr, buf: &mut [u8]) -> Result<(), Errno> {
        let mem = self.memory.borrow();
        for (i, slot) in buf.iter_mut().enumerate() {
            let current = addr.checked_add(i as GuestAddr).ok_or(Errno::EOVERFLOW)?;
            match mem.get(&current) {
                Some(b) => *slot = *b,
                None => return Err(Errno::EFAULT),
            }
        }
        Ok(())
    }

    fn read_stack(&self, offset: i64, size: usize) -> Result<Vec<u8>, Errno> {
        let sp = self.stack_pointer.get();
        let addr = if offset >= 0 {
            sp.checked_add(offset as u64).ok_or(Errno::EOVERFLOW)?
        } else {
            sp.checked_sub(offset.unsigned_abs())
                .ok_or(Errno::EOVERFLOW)?
        };
        let mut data = vec![0u8; size];
        self.read_mem(addr, &mut data)?;
        Ok(data)
    }

    fn write_stack(&self, offset: i64, data: &[u8]) -> Result<(), Errno> {
        let sp = self.stack_pointer.get();
        let addr = if offset >= 0 {
            sp.checked_add(offset as u64).ok_or(Errno::EOVERFLOW)?
        } else {
            sp.checked_sub(offset.unsigned_abs())
                .ok_or(Errno::EOVERFLOW)?
        };
        self.write_mem(addr, data)
    }

    fn write_mem(&self, addr: GuestAddr, buf: &[u8]) -> Result<(), Errno> {
        let mut mem = self.memory.borrow_mut();
        for (i, b) in buf.iter().enumerate() {
            let current = addr.checked_add(i as GuestAddr).ok_or(Errno::EOVERFLOW)?;
            mem.insert(current, *b);
        }
        Ok(())
    }

    fn alloc_guest(&self, size: usize, align: usize) -> Result<GuestAddr, Errno> {
        if align == 0 || !align.is_power_of_two() {
            return Err(Errno::EINVAL);
        }
        let current = self.guest_alloc_next.get();
        let aligned = (current + (align as u64 - 1)) & !(align as u64 - 1);
        let next = aligned.checked_add(size as u64).ok_or(Errno::ENOMEM)?;
        self.guest_alloc_next.set(next);
        Ok(aligned)
    }

    fn free_guest(&self, _addr: GuestAddr, _size: usize) -> Result<(), Errno> {
        Ok(())
    }

    #[cfg(feature = "mock-big-endian")]
    fn read_u16(&self, addr: GuestAddr) -> Result<u16, Errno> {
        let mut bytes = [0u8; 2];
        self.read_mem(addr, &mut bytes)?;
        Ok(u16::from_be_bytes(bytes))
    }

    #[cfg(feature = "mock-big-endian")]
    fn read_u32(&self, addr: GuestAddr) -> Result<u32, Errno> {
        let mut bytes = [0u8; 4];
        self.read_mem(addr, &mut bytes)?;
        Ok(u32::from_be_bytes(bytes))
    }

    #[cfg(feature = "mock-big-endian")]
    fn read_u64(&self, addr: GuestAddr) -> Result<u64, Errno> {
        let mut bytes = [0u8; 8];
        self.read_mem(addr, &mut bytes)?;
        Ok(u64::from_be_bytes(bytes))
    }

    #[cfg(feature = "mock-big-endian")]
    fn write_u16(&self, addr: GuestAddr, value: u16) -> Result<(), Errno> {
        self.write_mem(addr, &value.to_be_bytes())
    }

    #[cfg(feature = "mock-big-endian")]
    fn write_u32(&self, addr: GuestAddr, value: u32) -> Result<(), Errno> {
        self.write_mem(addr, &value.to_be_bytes())
    }

    #[cfg(feature = "mock-big-endian")]
    fn write_u64(&self, addr: GuestAddr, value: u64) -> Result<(), Errno> {
        self.write_mem(addr, &value.to_be_bytes())
    }

    fn state(&self) -> &(dyn Any + Send + Sync) {
        &*self.state
    }

    fn native_call(&mut self, target: GuestAddr, args: &[GuestReg]) -> Result<GuestReg, IibError> {
        self.native_call_log
            .borrow_mut()
            .push((target, args.to_vec()));
        let responses = self.native_call_responses.borrow();
        match responses.get(&target) {
            Some(Ok(v)) => Ok(*v),
            Some(Err(e)) => Err(e.clone()),
            None => Err(IibError::NoResponseProgrammed(target)),
        }
    }

    fn native_call_runtime(&mut self, target: GuestAddr, args: &[GuestReg]) -> Result<GuestReg, IibError> {
        self.native_call(target, args)
    }
}

fn word_size() -> usize {
    #[cfg(feature = "mock-32-bit")]
    {
        return 4;
    }
    #[allow(unreachable_code)]
    8
}

fn normalize_register_name(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

fn word_count_for(size: usize) -> usize {
    if size == 0 {
        0
    } else {
        (size + word_size() - 1) / word_size()
    }
}

fn return_word_count() -> usize {
    if cfg!(feature = "mock-32-bit") {
        4
    } else {
        2
    }
}

fn word_to_bytes(value: GuestReg) -> Vec<u8> {
    let bytes = if cfg!(feature = "mock-big-endian") {
        value.to_be_bytes()
    } else {
        value.to_le_bytes()
    };
    if cfg!(feature = "mock-big-endian") {
        bytes[bytes.len() - word_size()..].to_vec()
    } else {
        bytes[..word_size()].to_vec()
    }
}

fn word_from_bytes(bytes: &[u8]) -> GuestReg {
    let mut padded = [0u8; 8];
    if cfg!(feature = "mock-big-endian") {
        padded[8 - word_size()..].copy_from_slice(bytes);
        u64::from_be_bytes(padded)
    } else {
        padded[..word_size()].copy_from_slice(bytes);
        u64::from_le_bytes(padded)
    }
}

fn read_words_as_bytes(words: Vec<GuestReg>, size: usize) -> Result<Vec<u8>, Errno> {
    let mut bytes = Vec::with_capacity(words.len() * word_size());
    for word in words {
        bytes.extend_from_slice(&word_to_bytes(word));
    }
    bytes.truncate(size);
    Ok(bytes)
}

fn write_bytes_to_words<FRead, FWrite>(
    data: &[u8],
    word_count: usize,
    mut read_word: FRead,
    mut write_word: FWrite,
    index: u8,
) -> Result<(), Errno>
where
    FRead: FnMut(u8) -> Result<GuestReg, Errno>,
    FWrite: FnMut(u8, GuestReg) -> Result<(), Errno>,
{
    let mut words = (0..word_count)
        .map(|offset| index.checked_add(offset as u8).ok_or(Errno::EOVERFLOW))
        .map(|slot| slot.and_then(&mut read_word))
        .collect::<Result<Vec<_>, _>>()?;
    for (word_index, chunk) in data.chunks(word_size()).enumerate() {
        let mut bytes = word_to_bytes(words[word_index]);
        bytes[..chunk.len()].copy_from_slice(chunk);
        words[word_index] = word_from_bytes(&bytes);
    }
    for (offset, word) in words.into_iter().enumerate() {
        let slot = index.checked_add(offset as u8).ok_or(Errno::EOVERFLOW)?;
        write_word(slot, word)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty() {
        let m = MockIIBContextOps::new();
        assert_eq!(m.return_value(), None);
        assert_eq!(m.memory_slice(0, 4), vec![0, 0, 0, 0]);
        assert!(m.native_call_invocations().is_empty());
    }

    #[test]
    fn set_arg_and_read_arg_roundtrip() {
        let mut m = MockIIBContextOps::new();
        m.set_arg(0, 0x1000);
        m.set_arg(1, 0x42);
        assert_eq!(m.read_arg(0), Ok(0x1000));
        assert_eq!(m.read_arg(1), Ok(0x42));
        assert_eq!(m.read_arg(2), Err(Errno::EINVAL));
    }

    #[cfg(all(not(feature = "mock-big-endian"), not(feature = "mock-32-bit")))]
    #[test]
    fn abi_argument_bytes_roundtrip_preserves_word_tail() {
        let mut m = MockIIBContextOps::new();
        m.set_arg(0, 0x8877_6655_4433_2211)
            .set_arg(1, 0xfeed_face_cafe_babe);
        assert_eq!(
            m.read_arg_bytes(0, 10).unwrap(),
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0xbe, 0xba]
        );
        m.write_arg_bytes(0, &[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(m.read_arg(0), Ok(0x8877_6605_0403_0201));
        assert_eq!(m.read_arg(1), Ok(0xfeed_face_cafe_babe));
    }

    #[cfg(all(not(feature = "mock-big-endian"), feature = "mock-32-bit"))]
    #[test]
    fn abi_argument_bytes_use_32_bit_words_when_configured() {
        let mut m = MockIIBContextOps::new();
        m.set_arg(0, 0x4433_2211).set_arg(1, 0x8877_6655);
        assert_eq!(
            m.read_arg_bytes(0, 6).unwrap(),
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        );
        m.write_arg_bytes(0, &[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(m.read_arg(0), Ok(0x0403_0201));
        assert_eq!(m.read_arg(1), Ok(0x8877_6605));
    }

    #[test]
    fn stack_helpers_use_configured_guest_stack_pointer() {
        let mut m = MockIIBContextOps::new();
        m.set_stack_pointer(0x7000).set_memory(0x7004, b"abc");
        assert_eq!(m.read_stack(4, 3).unwrap(), b"abc");
        m.write_stack(-2, b"xy").unwrap();
        assert_eq!(m.memory_slice(0x6ffe, 2), b"xy");
    }

    #[cfg(not(feature = "mock-big-endian"))]
    #[test]
    fn aggregate_return_helpers_use_core_return_words() {
        let m = MockIIBContextOps::new();
        m.write_return_bytes(&[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert_eq!(m.read_return_bytes(9).unwrap(), [1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(
            m.return_value(),
            None,
            "register writes must not claim a return"
        );
    }

    #[test]
    fn register_only_adapter_does_not_replace_the_native_call() {
        fn broken_adapter(ctx: &mut dyn IIBContextOps) {
            ctx.write_return_bytes(&[1, 0, 0, 0]).unwrap();
        }
        let mut context = MockIIBContextOps::new();
        broken_adapter(&mut context);
        assert_eq!(context.read_return_bytes(4).unwrap(), [1, 0, 0, 0]);
        assert_eq!(context.return_value(), None);
        context.set_return_value(1).unwrap();
        assert_eq!(context.return_value(), Some(1));
    }

    #[test]
    fn set_memory_and_read_mem_roundtrip() {
        let mut m = MockIIBContextOps::new();
        m.set_memory(0x2000, b"hello\0");
        let s = String::from_utf8(m.memory_slice(0x2000, 5)).unwrap();
        assert_eq!(s, "hello");
    }

    #[test]
    fn read_mem_eunmapped_returns_efault() {
        let m = MockIIBContextOps::new();
        let mut buf = [0u8; 4];
        assert_eq!(m.read_mem(0x3000, &mut buf), Err(Errno::EFAULT));
    }

    #[test]
    fn write_mem_via_trait() {
        let m = MockIIBContextOps::new();
        m.write_mem(0x4000, b"abc").unwrap();
        assert_eq!(m.memory_slice(0x4000, 3), b"abc".to_vec());
    }

    #[test]
    fn set_return_value_is_observable() {
        let m = MockIIBContextOps::new();
        m.set_return_value(0xdead_beef).unwrap();
        assert_eq!(m.return_value(), Some(0xdead_beef));
    }

    #[test]
    fn named_registers_are_seedable_and_mutable() {
        let mut m = MockIIBContextOps::new();
        m.set_reg("R0", 7);
        assert_eq!(m.read_reg("r0"), Ok(7));
        assert_eq!(m.write_reg("rax", 42), Ok(()));
        assert_eq!(m.read_reg("RAX"), Ok(42));
    }

    #[test]
    fn stack_and_pc_aliases_follow_named_registers() {
        let mut m = MockIIBContextOps::new();
        m.set_reg("SP", 0x7100).set_reg("PC", 0x1234);
        assert_eq!(m.read_reg("sp"), Ok(0x7100));
        assert_eq!(m.current_pc(), 0x1234);
        m.write_reg("sp", 0x7200).unwrap();
        assert_eq!(m.read_stack(0, 0), Ok(Vec::new()));
    }

    #[test]
    fn state_set_and_ref_typed() {
        struct S {
            x: u64,
        }
        let mut m = MockIIBContextOps::new();
        m.set_state(S { x: 99 });
        let s: &S = m.state_ref().expect("state_ref should match S");
        assert_eq!(s.x, 99);
    }

    #[test]
    fn state_ref_mismatch_returns_none() {
        let mut m = MockIIBContextOps::new();
        m.set_state(42u32);
        let s: Option<&String> = m.state_ref();
        assert!(s.is_none());
    }

    #[test]
    fn native_call_logs_and_returns_programmed() {
        let mut m = MockIIBContextOps::new();
        m.set_native_call_response(0x1000, Ok(0x42));
        let r = m.native_call(0x1000, &[1, 2, 3]);
        assert_eq!(r.ok(), Some(0x42));
        let log = m.native_call_invocations();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].0, 0x1000);
        assert_eq!(log[0].1, vec![1, 2, 3]);
    }

    #[test]
    fn native_call_unprogrammed_returns_noresponse() {
        let mut m = MockIIBContextOps::new();
        let r = m.native_call(0x2000, &[]);
        match r {
            Err(IibError::NoResponseProgrammed(addr)) => assert_eq!(addr, 0x2000),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn explicit_runtime_call_preserves_arguments_and_programmed_result() {
        let mut context = MockIIBContextOps::new();
        context.set_native_call_response(0x8000, Ok(42));
        assert_eq!(context.native_call_runtime(0x8000, &[1, 2]).unwrap(), 42);
        assert_eq!(context.native_call_invocations(), vec![(0x8000, vec![1, 2])]);
        assert!(matches!(context.native_call_runtime(0x9000, &[]), Err(IibError::NoResponseProgrammed(0x9000))));
    }

    #[test]
    fn return_address_default_zero() {
        let m = MockIIBContextOps::new();
        assert_eq!(m.return_address(), Ok(0));
    }

    #[test]
    fn current_pc_set_and_read() {
        let mut m = MockIIBContextOps::new();
        m.set_current_pc(0xffff_0000);
        assert_eq!(m.current_pc(), 0xffff_0000);
    }

    #[test]
    fn guest_allocation_is_available_to_mock_interventions() {
        let m = MockIIBContextOps::new();
        let addr = m.alloc_guest(32, 16).unwrap();
        assert_eq!(addr % 16, 0);
        m.write_mem(addr, b"state").unwrap();
        assert_eq!(m.memory_slice(addr, 5), b"state".to_vec());
        m.free_guest(addr, 32).unwrap();
    }

    #[test]
    fn typed_integer_helpers_follow_mock_guest_endianness() {
        let mut mock = MockIIBContextOps::new();
        mock.set_memory(0x5000, &[0x12, 0x34, 0x56, 0x78]);
        #[cfg(feature = "mock-big-endian")]
        assert_eq!(mock.read_u32(0x5000), Ok(0x1234_5678));
        #[cfg(not(feature = "mock-big-endian"))]
        assert_eq!(mock.read_u32(0x5000), Ok(0x7856_3412));

        mock.write_u32(0x6000, 0x1234_5678).unwrap();
        #[cfg(feature = "mock-big-endian")]
        assert_eq!(mock.memory_slice(0x6000, 4), [0x12, 0x34, 0x56, 0x78]);
        #[cfg(not(feature = "mock-big-endian"))]
        assert_eq!(mock.memory_slice(0x6000, 4), [0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn mock_impls_iib_context_ops_trait() {
        fn takes_ctx(_: &mut dyn IIBContextOps) {}
        let mut m = MockIIBContextOps::new();
        takes_ctx(&mut m);
    }
}
