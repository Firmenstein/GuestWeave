//! IIB native_call: nested guest function invocation from a hook.
//!
//! Three mechanisms per paper §3.4:
//!   1. Save/restore CPU state
//!   2. Allocate independent stack frame (via GuestStackPool)
//!   3. Push a trap address as the return address; pre-registered
//!      breakpoint at the trap catches the return.
//!
//! v1 supports depth >= 2 (paper figure 6 chain).

use crate::cpu_snapshot;
use crate::guest_memory::GuestMemoryPool;
use crate::stack_pool::{GuestStackPool, StackFrameGuard};
use fmst_iib_api::iib_error::IibError;
use fmst_iib_api::types::{GuestAddr, GuestReg};
use libafl_qemu::Qemu;
use std::sync::{
    atomic::{AtomicU32, Ordering},
    Mutex,
};

pub const MAX_NESTING: u32 = 8;
pub const STACK_FRAME_SIZE: u64 = 0x2000; // 8 KiB per frame

/// Own one guest stack frame for the complete native-call attempt.
///
/// Native calls can fail after changing registers or while dispatching a
/// nested hook.  The old success-only `free_frame` left the pool occupied on
/// those paths, so a later call could report `StackPoolExhausted` even though
/// no guest frame was still active.  Keeping the guard next to the frame
/// makes cleanup independent of the architecture-specific return path.
struct StackFrameLease<'a> {
    pool: &'a Mutex<GuestStackPool>,
    frame: Option<StackFrameGuard>,
}

impl<'a> StackFrameLease<'a> {
    fn new(pool: &'a Mutex<GuestStackPool>, frame: StackFrameGuard) -> Self {
        Self {
            pool,
            frame: Some(frame),
        }
    }

    fn sp(&self) -> GuestAddr {
        self.frame
            .as_ref()
            .expect("stack frame lease is already released")
            .sp()
    }

    fn release(mut self) {
        let frame = self
            .frame
            .take()
            .expect("stack frame lease is already released");
        self.pool.lock().unwrap().free_frame(frame);
    }
}

impl Drop for StackFrameLease<'_> {
    fn drop(&mut self) {
        if let Some(frame) = self.frame.take() {
            self.pool.lock().unwrap().free_frame(frame);
        }
    }
}

/// The legacy API accepts a runtime VA or a main-image link-time VA. Resolve
/// only when exactly one of those candidates is executable in the current
/// guest. Numeric ordering against load_base is not address-space evidence.
/// Library-relative offsets require a future explicit module/address API.
fn resolve_link_time_target(
    load_base: GuestAddr,
    target: GuestAddr,
    mut executable: impl FnMut(GuestAddr) -> bool,
) -> Result<GuestAddr, String> {
    if target == 0 {
        return Err("native-call null target".to_owned());
    }
    let relocated = target
        .checked_add(load_base)
        .filter(|value| *value != target);
    let absolute_valid = executable(target);
    let relocated_valid = relocated.filter(|value| executable(*value));
    match (absolute_valid, relocated_valid) {
        (true, None) => Ok(target),
        (false, Some(value)) => Ok(value),
        (true, Some(value)) => Err(format!(
            "ambiguous native-call target: runtime={target:#x} and relocated={value:#x} are executable"
        )),
        (false, None) => Err(format!(
            "unmapped/non-executable native-call target={target:#x}, load_base={load_base:#x}, relocated={relocated:?} (None means duplicate or overflow)"
        )),
    }
}

fn resolve_runtime_target(target: GuestAddr, mut executable: impl FnMut(GuestAddr) -> bool) -> Result<GuestAddr, String> {
    if target == 0 || !executable(target) {
        return Err(format!("non-executable runtime native-call target={target:#x}"));
    }
    Ok(target)
}

fn resolve_native_target(qemu: &Qemu, target: GuestAddr, runtime_address: bool) -> Result<GuestAddr, IibError> {
    let load_base = qemu.load_addr() as GuestAddr;
    let executable = |address| {
        // Thumb uses bit zero for mode, not as part of the page address.
        let address = if cfg!(feature = "arm") {
            address & !1
        } else {
            address
        };
        let Ok(address) = libafl_qemu::GuestAddr::try_from(address) else {
            return false;
        };
        // QEMU PAGE_EXEC equals PROT_EXEC. Unlike host maps, this tests actual
        // guest permissions (also valid for the non-identity x86_64 layout).
        unsafe { libafl_qemu::sys::page_check_range(address, 1, libc::PROT_EXEC) }
    };
    (if runtime_address {
        resolve_runtime_target(target, executable)
    } else {
        resolve_link_time_target(load_base, target, executable)
    })
    .map_err(|reason| {
        crate::runtime_trace::record_runtime_state_event(
            "native_call_resolution_failed",
            reason.clone(),
        );
        log::error!("{reason}");
        IibError::Errno(fmst_iib_api::Errno::EINVAL)
    })
}

#[cfg(test)]
mod target_resolution_tests {
    use super::{resolve_link_time_target, resolve_runtime_target};

    #[test]
    fn explicit_runtime_address_does_not_consider_a_second_executable_page() {
        let executable = |a| a == 0x8000 || a == 0x9000;
        assert!(resolve_link_time_target(0x1000, 0x8000, executable).is_err());
        assert_eq!(resolve_runtime_target(0x8000, executable).unwrap(), 0x8000);
        assert!(resolve_runtime_target(0, |_| true).is_err());
        assert!(resolve_runtime_target(0x1000, |_| false).is_err());
    }

    #[test]
    fn chooses_only_executable_candidate_without_numeric_guessing() {
        assert_eq!(
            resolve_link_time_target(0x5555_0000, 0x12aa0, |a| a == 0x5556_2aa0).unwrap(),
            0x5556_2aa0
        );
        assert_eq!(
            resolve_link_time_target(0x5555_0000, 0x12aa0, |a| a == 0x12aa0).unwrap(),
            0x12aa0
        );
        assert_eq!(
            resolve_link_time_target(0x5555_0000, 0x5556_2aa0, |a| a == 0x5556_2aa0).unwrap(),
            0x5556_2aa0
        );
    }

    #[test]
    fn rejects_ambiguous_or_nonexecutable_candidates() {
        assert!(resolve_link_time_target(0x1000, 0x20, |_| true)
            .unwrap_err()
            .contains("ambiguous"));
        assert!(resolve_link_time_target(0x1000, 0x20, |_| false)
            .unwrap_err()
            .contains("non-executable"));
        assert!(resolve_link_time_target(0x1000, 0, |_| true).is_err());
    }

    #[test]
    fn zero_base_deduplicates_and_overflow_never_falls_back_to_invalid_target() {
        assert_eq!(
            resolve_link_time_target(0, 0x12aa0, |_| true).unwrap(),
            0x12aa0
        );
        assert!(resolve_link_time_target(u64::MAX - 4, 8, |_| false).is_err());
        assert_eq!(
            resolve_link_time_target(u64::MAX - 4, 8, |a| a == 8).unwrap(),
            8
        );
    }
}

#[cfg(test)]
mod stack_frame_lease_tests {
    use super::{GuestStackPool, StackFrameLease};
    use std::sync::Mutex;

    #[test]
    fn dropping_a_failed_native_call_reclaims_the_frame() {
        let pool = Mutex::new(GuestStackPool::new(0x1_0000, 0x400));
        let outer = pool.lock().unwrap().alloc_frame(0x200).unwrap();
        let outer = StackFrameLease::new(&pool, outer);
        let fail_after_allocation = || -> Result<(), &'static str> {
            let frame = pool.lock().unwrap().alloc_frame(0x200).unwrap();
            let lease = StackFrameLease::new(&pool, frame);
            assert!(lease.sp() < outer.sp());
            Err("nested dispatch failed")?;
            lease.release();
            Ok(())
        };
        // More attempts than this two-frame pool could serve if any error
        // leaked its frame. The still-active outer frame must remain owned.
        for _ in 0..32 {
            assert_eq!(fail_after_allocation(), Err("nested dispatch failed"));
            assert_eq!(pool.lock().unwrap().depth_bytes(), 0x200);
        }
        outer.release();
        assert_eq!(pool.lock().unwrap().depth_bytes(), 0);
        let full = pool.lock().unwrap().alloc_frame(0x400).unwrap();
        StackFrameLease::new(&pool, full).release();
    }

    #[test]
    fn explicit_success_release_is_not_repeated_by_drop() {
        let pool = Mutex::new(GuestStackPool::new(0x1_0000, 0x400));
        let frame = pool.lock().unwrap().alloc_frame(0x200).unwrap();
        StackFrameLease::new(&pool, frame).release();
        assert_eq!(pool.lock().unwrap().depth_bytes(), 0);
    }
}

/// IIB state shared between context impls for nested call tracking.
pub struct IibState {
    pub trap_addr: GuestAddr,
    pub stack_pool: Mutex<GuestStackPool>,
    pub guest_memory: Mutex<GuestMemoryPool>,
    pub depth: AtomicU32,
}

impl IibState {
    pub fn new(
        trap_addr: GuestAddr,
        stack_pool: GuestStackPool,
        guest_memory: GuestMemoryPool,
    ) -> Self {
        Self {
            trap_addr,
            stack_pool: Mutex::new(stack_pool),
            guest_memory: Mutex::new(guest_memory),
            depth: AtomicU32::new(0),
        }
    }
}

#[cfg(feature = "arm")]
pub fn native_call_arm(
    qemu: Qemu,
    state: &IibState,
    target: GuestAddr,
    args: &[GuestReg],
    runtime_address: bool,
) -> Result<GuestReg, IibError> {
    use cpu_snapshot::arm::ArmCpuSnapshot;
    use libafl_qemu::arch::arm::Regs;
    use libafl_qemu::ArchExtras;

    if target == 0 {
        return Err(IibError::Errno(fmst_iib_api::Errno::EINVAL));
    }
    let target = resolve_native_target(&qemu, target, runtime_address)?;
    log::info!(
        "IIB native_call ARM target={target:#x}, args={}",
        args.len()
    );

    let cpu = qemu
        .current_cpu()
        .ok_or(IibError::Errno(fmst_iib_api::Errno::EINVAL))?;
    log::info!("IIB native_call ARM CPU acquired for target={target:#x}");

    // 1. Depth check.
    let depth = state.depth.fetch_add(1, Ordering::SeqCst);
    if depth >= MAX_NESTING {
        state.depth.fetch_sub(1, Ordering::SeqCst);
        return Err(IibError::NestingTooDeep(depth));
    }

    // Clean up depth counter on any exit path.
    struct DepthGuard<'a>(&'a AtomicU32);
    impl Drop for DepthGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let _depth_guard = DepthGuard(&state.depth);

    // 2. Save CPU state (ARM: R0-R12 + SP + LR + PC + CPSR).
    let read = |r: Regs| {
        cpu.read_reg(r)
            .map_err(|_| IibError::Errno(fmst_iib_api::Errno::EINVAL))
    };
    let snapshot = ArmCpuSnapshot {
        r0: read(Regs::R0)? as GuestReg,
        r1: read(Regs::R1)? as GuestReg,
        r2: read(Regs::R2)? as GuestReg,
        r3: read(Regs::R3)? as GuestReg,
        r4: read(Regs::R4)? as GuestReg,
        r5: read(Regs::R5)? as GuestReg,
        r6: read(Regs::R6)? as GuestReg,
        r7: read(Regs::R7)? as GuestReg,
        r8: read(Regs::R8)? as GuestReg,
        r9: read(Regs::R9)? as GuestReg,
        r10: read(Regs::R10)? as GuestReg,
        r11: read(Regs::R11)? as GuestReg,
        r12: read(Regs::R12)? as GuestReg,
        sp: read(Regs::R13)? as GuestReg,
        lr: read(Regs::R14)? as GuestReg,
        pc: read(Regs::R15)? as GuestReg,
        cpsr: read(Regs::R25)? as GuestReg,
    };

    // 3. Allocate stack frame.
    let frame = StackFrameLease::new(
        &state.stack_pool,
        state
            .stack_pool
            .lock()
            .unwrap()
            .alloc_frame(STACK_FRAME_SIZE)
            .map_err(|_| IibError::StackPoolExhausted)?,
    );

    // 4. Setup args, SP, LR=TRAP, PC=target.
    let write = |r: Regs, v: libafl_qemu::GuestReg| {
        cpu.write_reg(r, v)
            .map_err(|_| IibError::Errno(fmst_iib_api::Errno::EINVAL))
    };
    for (i, &a) in args.iter().enumerate() {
        cpu.write_function_argument_with_cc(
            i as u8,
            a as libafl_qemu::GuestReg,
            libafl_qemu::CallingConvention::Aapcs,
        )
        .map_err(|_| IibError::Errno(fmst_iib_api::Errno::EINVAL))?;
    }
    write(Regs::R13, frame.sp() as libafl_qemu::GuestReg)?;
    write(Regs::R14, state.trap_addr as libafl_qemu::GuestReg)?;
    write(Regs::R15, target as libafl_qemu::GuestReg)?;

    // 5. Run until trap breakpoint fires at our depth. Any non-trap
    //    breakpoint is a nested IIB hook: dispatch it (which updates the
    //    guest CPU state per the hook's `set_return_value` call) and
    //    resume qemu. This is what makes the paper §3.4 nested-bidirectional
    //    flow work — nvram_* hooks fire while this outer native_call is
    //    still executing apply_runtime_profile.
    let expected_trap = state.trap_addr;
    loop {
        match unsafe { qemu.run() } {
            Ok(libafl_qemu::QemuExitReason::Breakpoint(addr))
                if addr as GuestAddr == expected_trap =>
            {
                break;
            }
            Ok(libafl_qemu::QemuExitReason::Breakpoint(addr)) => {
                log::info!("IIB native_call ARM nested breakpoint at {addr:#x}");
                match crate::module::dispatch_nested_hook(addr as GuestAddr) {
                    Ok(true) => {}
                    Ok(false) => {
                        log::warn!("IIB native_call ARM hit an unregistered nested breakpoint at {addr:#x}");
                        return Err(IibError::GuestCrash(-1));
                    }
                    Err(error) => {
                        log::warn!(
                            "IIB native_call ARM nested dispatch failed at {addr:#x}: {error}"
                        );
                        return Err(IibError::GuestCrash(-1));
                    }
                }
                continue;
            }
            Ok(libafl_qemu::QemuExitReason::End(_)) => {
                log::warn!("IIB native_call ARM guest ended before trap at target={target:#x}");
                return Err(IibError::GuestCrash(0));
            }
            Ok(reason) => {
                log::warn!(
                    "IIB native_call ARM unexpected QEMU exit at target={target:#x}: {reason:?}"
                );
                continue;
            }
            Err(_) => return Err(IibError::GuestCrash(-1)),
        }
    }

    // 6. Read return value.
    let ret = read(Regs::R0)? as GuestReg;

    // 7. Restore CPU state.
    write(Regs::R0, snapshot.r0 as libafl_qemu::GuestReg)?;
    write(Regs::R1, snapshot.r1 as libafl_qemu::GuestReg)?;
    write(Regs::R2, snapshot.r2 as libafl_qemu::GuestReg)?;
    write(Regs::R3, snapshot.r3 as libafl_qemu::GuestReg)?;
    write(Regs::R4, snapshot.r4 as libafl_qemu::GuestReg)?;
    write(Regs::R5, snapshot.r5 as libafl_qemu::GuestReg)?;
    write(Regs::R6, snapshot.r6 as libafl_qemu::GuestReg)?;
    write(Regs::R7, snapshot.r7 as libafl_qemu::GuestReg)?;
    write(Regs::R8, snapshot.r8 as libafl_qemu::GuestReg)?;
    write(Regs::R9, snapshot.r9 as libafl_qemu::GuestReg)?;
    write(Regs::R10, snapshot.r10 as libafl_qemu::GuestReg)?;
    write(Regs::R11, snapshot.r11 as libafl_qemu::GuestReg)?;
    write(Regs::R12, snapshot.r12 as libafl_qemu::GuestReg)?;
    write(Regs::R13, snapshot.sp as libafl_qemu::GuestReg)?;
    write(Regs::R14, snapshot.lr as libafl_qemu::GuestReg)?;
    write(Regs::R15, snapshot.pc as libafl_qemu::GuestReg)?;
    write(Regs::R25, snapshot.cpsr as libafl_qemu::GuestReg)?;

    // 8. Free frame.
    frame.release();

    Ok(ret)
}

#[cfg(any(feature = "mips", feature = "mipsbe"))]
pub fn native_call_mips(
    qemu: Qemu,
    state: &IibState,
    target: GuestAddr,
    args: &[GuestReg],
    runtime_address: bool,
) -> Result<GuestReg, IibError> {
    use cpu_snapshot::mips::MipsCpuSnapshot;
    use libafl_qemu::arch::mips::Regs;
    use libafl_qemu::ArchExtras;

    if target == 0 {
        return Err(IibError::Errno(fmst_iib_api::Errno::EINVAL));
    }
    let target = resolve_native_target(&qemu, target, runtime_address)?;
    log::info!(
        "IIB native_call MIPS target={target:#x}, args={}",
        args.len()
    );

    let cpu = qemu
        .current_cpu()
        .ok_or(IibError::Errno(fmst_iib_api::Errno::EINVAL))?;
    log::info!("IIB native_call MIPS CPU acquired for target={target:#x}");

    // 1. Depth check.
    let depth = state.depth.fetch_add(1, Ordering::SeqCst);
    if depth >= MAX_NESTING {
        state.depth.fetch_sub(1, Ordering::SeqCst);
        return Err(IibError::NestingTooDeep(depth));
    }

    struct DepthGuard<'a>(&'a AtomicU32);
    impl Drop for DepthGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let _depth_guard = DepthGuard(&state.depth);

    // 2. Save CPU state (MIPS: 32 GPRs + PC).
    let read = |r: Regs| {
        cpu.read_reg(r)
            .map_err(|_| IibError::Errno(fmst_iib_api::Errno::EINVAL))
    };
    let snapshot = MipsCpuSnapshot {
        zero: read(Regs::R0)? as GuestReg,
        at: read(Regs::At)? as GuestReg,
        v0: read(Regs::V0)? as GuestReg,
        v1: read(Regs::V1)? as GuestReg,
        a0: read(Regs::A0)? as GuestReg,
        a1: read(Regs::A1)? as GuestReg,
        a2: read(Regs::A2)? as GuestReg,
        a3: read(Regs::A3)? as GuestReg,
        t0: read(Regs::T0)? as GuestReg,
        t1: read(Regs::T1)? as GuestReg,
        t2: read(Regs::T2)? as GuestReg,
        t3: read(Regs::T3)? as GuestReg,
        t4: read(Regs::T4)? as GuestReg,
        t5: read(Regs::T5)? as GuestReg,
        t6: read(Regs::T6)? as GuestReg,
        t7: read(Regs::T7)? as GuestReg,
        s0: read(Regs::S0)? as GuestReg,
        s1: read(Regs::S1)? as GuestReg,
        s2: read(Regs::S2)? as GuestReg,
        s3: read(Regs::S3)? as GuestReg,
        s4: read(Regs::S4)? as GuestReg,
        s5: read(Regs::S5)? as GuestReg,
        s6: read(Regs::S6)? as GuestReg,
        s7: read(Regs::S7)? as GuestReg,
        t8: read(Regs::T8)? as GuestReg,
        t9: read(Regs::T9)? as GuestReg,
        k0: read(Regs::K0)? as GuestReg,
        k1: read(Regs::K1)? as GuestReg,
        gp: read(Regs::Gp)? as GuestReg,
        sp: read(Regs::Sp)? as GuestReg,
        fp: read(Regs::Fp)? as GuestReg,
        ra: read(Regs::Ra)? as GuestReg,
        pc: read(Regs::Pc)? as GuestReg,
    };
    log::info!("IIB native_call MIPS CPU snapshot captured for target={target:#x}");

    // 3. Allocate stack frame.
    let frame = StackFrameLease::new(
        &state.stack_pool,
        state
            .stack_pool
            .lock()
            .unwrap()
            .alloc_frame(STACK_FRAME_SIZE)
            .map_err(|_| IibError::StackPoolExhausted)?,
    );
    log::info!(
        "IIB native_call MIPS allocated nested frame sp={:#x}",
        frame.sp()
    );

    // 4. Setup args (A0..A3 via cc), SP, RA=TRAP, PC=target.
    let write = |r: Regs, v: libafl_qemu::GuestReg| {
        cpu.write_reg(r, v)
            .map_err(|_| IibError::Errno(fmst_iib_api::Errno::EINVAL))
    };
    // MIPS O32 carries only four words in $a0-$a3.  Remaining words are in
    // the caller-provided argument area beginning at SP+0x10; the fifth
    // argument is therefore visible to a callee at `new_sp + 0x10`.  The
    // generic LibAFL calling-convention helper deliberately rejects an
    // out-of-register index, so writing all words through it made every
    // nested call with a fifth argument fail before the target was entered.
    for (i, &a) in args.iter().take(4).enumerate() {
        cpu.write_function_argument_with_cc(
            i as u8,
            a as libafl_qemu::GuestReg,
            libafl_qemu::CallingConvention::MipsO32,
        )
        .map_err(|_| IibError::Errno(fmst_iib_api::Errno::EINVAL))?;
    }
    let stack_arg_base = frame
        .sp()
        .checked_add(0x10)
        .ok_or(IibError::Errno(fmst_iib_api::Errno::EOVERFLOW))?;
    for (index, &a) in args.iter().skip(4).enumerate() {
        let address = stack_arg_base
            .checked_add((index as GuestAddr).saturating_mul(4))
            .ok_or(IibError::Errno(fmst_iib_api::Errno::EOVERFLOW))?;
        #[cfg(feature = "mipsbe")]
        let bytes = (a as u32).to_be_bytes();
        #[cfg(not(feature = "mipsbe"))]
        let bytes = (a as u32).to_le_bytes();
        qemu.write_mem(address as libafl_qemu::GuestAddr, &bytes)
            .map_err(|_| IibError::Errno(fmst_iib_api::Errno::EFAULT))?;
    }
    write(Regs::Sp, frame.sp() as libafl_qemu::GuestReg)?;
    write(Regs::Ra, state.trap_addr as libafl_qemu::GuestReg)?;
    // O32 PIC entry sequences derive $gp from the callee address in $t9.
    // This is a calling-convention responsibility, including after legacy
    // address resolution, not an intervention-specific register workaround.
    write(Regs::T9, target as libafl_qemu::GuestReg)?;
    write(Regs::Pc, target as libafl_qemu::GuestReg)?;
    log::info!("IIB native_call MIPS entered target={target:#x}");

    // 5. Run until trap breakpoint fires. Any non-trap breakpoint is a
    //    nested IIB hook (see native_call_arm for the paper §3.4 rationale).
    let expected_trap = state.trap_addr;
    loop {
        match unsafe { qemu.run() } {
            Ok(libafl_qemu::QemuExitReason::Breakpoint(addr))
                if addr as GuestAddr == expected_trap =>
            {
                break;
            }
            Ok(libafl_qemu::QemuExitReason::Breakpoint(addr)) => {
                log::info!("IIB native_call MIPS nested breakpoint at {addr:#x}");
                match crate::module::dispatch_nested_hook(addr as GuestAddr) {
                    Ok(true) => {}
                    Ok(false) => {
                        log::warn!("IIB native_call MIPS hit an unregistered nested breakpoint at {addr:#x}");
                        return Err(IibError::GuestCrash(-1));
                    }
                    Err(error) => {
                        log::warn!(
                            "IIB native_call MIPS nested dispatch failed at {addr:#x}: {error}"
                        );
                        return Err(IibError::GuestCrash(-1));
                    }
                }
                continue;
            }
            Ok(libafl_qemu::QemuExitReason::End(_)) => {
                log::warn!("IIB native_call MIPS guest ended before trap at target={target:#x}");
                return Err(IibError::GuestCrash(0));
            }
            Ok(reason) => {
                log::warn!(
                    "IIB native_call MIPS unexpected QEMU exit at target={target:#x}: {reason:?}"
                );
                continue;
            }
            Err(error) => {
                log::warn!("IIB native_call MIPS qemu.run failed at target={target:#x}: {error:?}");
                return Err(IibError::GuestCrash(-1));
            }
        }
    }

    // 6. Read return value (V0).
    let ret = read(Regs::V0)? as GuestReg;

    // 7. Restore CPU state (all 32 GPRs + PC).
    write(Regs::R0, snapshot.zero as libafl_qemu::GuestReg)?;
    write(Regs::At, snapshot.at as libafl_qemu::GuestReg)?;
    write(Regs::V0, snapshot.v0 as libafl_qemu::GuestReg)?;
    write(Regs::V1, snapshot.v1 as libafl_qemu::GuestReg)?;
    write(Regs::A0, snapshot.a0 as libafl_qemu::GuestReg)?;
    write(Regs::A1, snapshot.a1 as libafl_qemu::GuestReg)?;
    write(Regs::A2, snapshot.a2 as libafl_qemu::GuestReg)?;
    write(Regs::A3, snapshot.a3 as libafl_qemu::GuestReg)?;
    write(Regs::T0, snapshot.t0 as libafl_qemu::GuestReg)?;
    write(Regs::T1, snapshot.t1 as libafl_qemu::GuestReg)?;
    write(Regs::T2, snapshot.t2 as libafl_qemu::GuestReg)?;
    write(Regs::T3, snapshot.t3 as libafl_qemu::GuestReg)?;
    write(Regs::T4, snapshot.t4 as libafl_qemu::GuestReg)?;
    write(Regs::T5, snapshot.t5 as libafl_qemu::GuestReg)?;
    write(Regs::T6, snapshot.t6 as libafl_qemu::GuestReg)?;
    write(Regs::T7, snapshot.t7 as libafl_qemu::GuestReg)?;
    write(Regs::S0, snapshot.s0 as libafl_qemu::GuestReg)?;
    write(Regs::S1, snapshot.s1 as libafl_qemu::GuestReg)?;
    write(Regs::S2, snapshot.s2 as libafl_qemu::GuestReg)?;
    write(Regs::S3, snapshot.s3 as libafl_qemu::GuestReg)?;
    write(Regs::S4, snapshot.s4 as libafl_qemu::GuestReg)?;
    write(Regs::S5, snapshot.s5 as libafl_qemu::GuestReg)?;
    write(Regs::S6, snapshot.s6 as libafl_qemu::GuestReg)?;
    write(Regs::S7, snapshot.s7 as libafl_qemu::GuestReg)?;
    write(Regs::T8, snapshot.t8 as libafl_qemu::GuestReg)?;
    write(Regs::T9, snapshot.t9 as libafl_qemu::GuestReg)?;
    write(Regs::K0, snapshot.k0 as libafl_qemu::GuestReg)?;
    write(Regs::K1, snapshot.k1 as libafl_qemu::GuestReg)?;
    write(Regs::Gp, snapshot.gp as libafl_qemu::GuestReg)?;
    write(Regs::Sp, snapshot.sp as libafl_qemu::GuestReg)?;
    write(Regs::Fp, snapshot.fp as libafl_qemu::GuestReg)?;
    write(Regs::Ra, snapshot.ra as libafl_qemu::GuestReg)?;
    write(Regs::Pc, snapshot.pc as libafl_qemu::GuestReg)?;

    // 8. Free frame.
    frame.release();

    Ok(ret)
}

#[cfg(feature = "x86_64")]
pub fn native_call_x86_64(
    qemu: Qemu,
    state: &IibState,
    target: GuestAddr,
    args: &[GuestReg],
    runtime_address: bool,
) -> Result<GuestReg, IibError> {
    use cpu_snapshot::x86_64::X86_64CpuSnapshot;
    use libafl_qemu::arch::x86_64::Regs;
    use libafl_qemu::ArchExtras;

    if target == 0 {
        return Err(IibError::Errno(fmst_iib_api::Errno::EINVAL));
    }
    let target = resolve_native_target(&qemu, target, runtime_address)?;
    log::info!(
        "IIB native_call x86_64 target={target:#x}, args={}",
        args.len()
    );

    let cpu = qemu
        .current_cpu()
        .ok_or(IibError::Errno(fmst_iib_api::Errno::EINVAL))?;

    // 1. Depth check.
    let depth = state.depth.fetch_add(1, Ordering::SeqCst);
    if depth >= MAX_NESTING {
        state.depth.fetch_sub(1, Ordering::SeqCst);
        return Err(IibError::NestingTooDeep(depth));
    }

    struct DepthGuard<'a>(&'a AtomicU32);
    impl Drop for DepthGuard<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    let _depth_guard = DepthGuard(&state.depth);

    // 2. Save CPU state (16 GPRs + RIP + RFLAGS).
    let read = |r: Regs| {
        cpu.read_reg(r)
            .map_err(|_| IibError::Errno(fmst_iib_api::Errno::EINVAL))
    };
    let snapshot = X86_64CpuSnapshot {
        rax: read(Regs::Rax)? as GuestReg,
        rbx: read(Regs::Rbx)? as GuestReg,
        rcx: read(Regs::Rcx)? as GuestReg,
        rdx: read(Regs::Rdx)? as GuestReg,
        rsi: read(Regs::Rsi)? as GuestReg,
        rdi: read(Regs::Rdi)? as GuestReg,
        rbp: read(Regs::Rbp)? as GuestReg,
        rsp: read(Regs::Rsp)? as GuestReg,
        r8: read(Regs::R8)? as GuestReg,
        r9: read(Regs::R9)? as GuestReg,
        r10: read(Regs::R10)? as GuestReg,
        r11: read(Regs::R11)? as GuestReg,
        r12: read(Regs::R12)? as GuestReg,
        r13: read(Regs::R13)? as GuestReg,
        r14: read(Regs::R14)? as GuestReg,
        r15: read(Regs::R15)? as GuestReg,
        rip: read(Regs::Rip)? as GuestReg,
        rflags: read(Regs::Rflags)? as GuestReg,
    };

    // 3. Allocate stack frame.
    let frame = StackFrameLease::new(
        &state.stack_pool,
        state
            .stack_pool
            .lock()
            .unwrap()
            .alloc_frame(STACK_FRAME_SIZE)
            .map_err(|_| IibError::StackPoolExhausted)?,
    );

    // 4. Setup args (SystemV: RDI,RSI,RDX,RCX,R8,R9 for first 6).
    let write = |r: Regs, v: libafl_qemu::GuestReg| {
        cpu.write_reg(r, v)
            .map_err(|_| IibError::Errno(fmst_iib_api::Errno::EINVAL))
    };
    for (i, &a) in args.iter().enumerate() {
        cpu.write_function_argument_with_cc(
            i as u8,
            a as libafl_qemu::GuestReg,
            libafl_qemu::CallingConvention::SystemV,
        )
        .map_err(|_| IibError::Errno(fmst_iib_api::Errno::EINVAL))?;
    }

    // 5. x86_64 `call` pushes the return address on the stack and jumps.
    //    We simulate: write trap_addr to [new_sp], set RSP=new_sp, RIP=target.
    //    `set_return_value` later pops + advances RSP, completing the `ret`.
    let new_sp = (frame.sp() as u64).wrapping_sub(8);
    let trap_bytes = (state.trap_addr as u64).to_le_bytes();
    qemu.write_mem(new_sp as libafl_qemu::GuestAddr, &trap_bytes)
        .map_err(|_| IibError::Errno(fmst_iib_api::Errno::EFAULT))?;
    write(Regs::Rsp, new_sp as libafl_qemu::GuestReg)?;
    write(Regs::Rip, target as libafl_qemu::GuestReg)?;

    // 6. Run until trap breakpoint fires. Non-trap breakpoints are nested
    //    IIB hooks dispatched via dispatch_nested_hook.
    let expected_trap = state.trap_addr;
    loop {
        match unsafe { qemu.run() } {
            Ok(libafl_qemu::QemuExitReason::Breakpoint(addr))
                if addr as GuestAddr == expected_trap =>
            {
                break;
            }
            Ok(libafl_qemu::QemuExitReason::Breakpoint(addr)) => {
                if !crate::module::dispatch_nested_hook(addr as GuestAddr)
                    .map_err(|_| IibError::GuestCrash(-1))?
                {
                    return Err(IibError::GuestCrash(-1));
                }
                continue;
            }
            Ok(libafl_qemu::QemuExitReason::End(_)) => {
                return Err(IibError::GuestCrash(0));
            }
            Ok(_) => continue,
            Err(_) => return Err(IibError::GuestCrash(-1)),
        }
    }

    // 7. Read return value (RAX).
    let ret = read(Regs::Rax)? as GuestReg;

    // 8. Restore CPU state (16 GPRs + RIP + RFLAGS).
    write(Regs::Rax, snapshot.rax as libafl_qemu::GuestReg)?;
    write(Regs::Rbx, snapshot.rbx as libafl_qemu::GuestReg)?;
    write(Regs::Rcx, snapshot.rcx as libafl_qemu::GuestReg)?;
    write(Regs::Rdx, snapshot.rdx as libafl_qemu::GuestReg)?;
    write(Regs::Rsi, snapshot.rsi as libafl_qemu::GuestReg)?;
    write(Regs::Rdi, snapshot.rdi as libafl_qemu::GuestReg)?;
    write(Regs::Rbp, snapshot.rbp as libafl_qemu::GuestReg)?;
    write(Regs::Rsp, snapshot.rsp as libafl_qemu::GuestReg)?;
    write(Regs::R8, snapshot.r8 as libafl_qemu::GuestReg)?;
    write(Regs::R9, snapshot.r9 as libafl_qemu::GuestReg)?;
    write(Regs::R10, snapshot.r10 as libafl_qemu::GuestReg)?;
    write(Regs::R11, snapshot.r11 as libafl_qemu::GuestReg)?;
    write(Regs::R12, snapshot.r12 as libafl_qemu::GuestReg)?;
    write(Regs::R13, snapshot.r13 as libafl_qemu::GuestReg)?;
    write(Regs::R14, snapshot.r14 as libafl_qemu::GuestReg)?;
    write(Regs::R15, snapshot.r15 as libafl_qemu::GuestReg)?;
    write(Regs::Rip, snapshot.rip as libafl_qemu::GuestReg)?;
    write(Regs::Rflags, snapshot.rflags as libafl_qemu::GuestReg)?;

    // 9. Free frame.
    frame.release();

    Ok(ret)
}
