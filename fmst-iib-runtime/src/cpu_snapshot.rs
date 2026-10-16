//! Per-architecture CPU state save/restore for IIB native_call.
//!
//! ARM32 (AAPCS):   saves R0-R12, SP (R13), LR (R14), PC (R15), CPSR.
//! MIPS32 (O32):    saves all 32 GPRs (zero..ra) + PC.
//! x86_64 (SystemV): saves 16 GPRs + RIP + RFLAGS.
//!
//! This module does NOT touch libafl_qemu directly. Instead it defines a
//! data structure + trait that fmst-iib-runtime::context_impl fills from
//! the real CPU.

#[cfg(feature = "arm")]
pub mod arm {
    use fmst_iib_api::types::GuestReg;

    /// Snapshot of ARM32 CPU state captured before a native_call and
    /// restored after trap.
    #[derive(Debug, Clone)]
    pub struct ArmCpuSnapshot {
        pub r0: GuestReg,
        pub r1: GuestReg,
        pub r2: GuestReg,
        pub r3: GuestReg,
        pub r4: GuestReg,
        pub r5: GuestReg,
        pub r6: GuestReg,
        pub r7: GuestReg,
        pub r8: GuestReg,
        pub r9: GuestReg,
        pub r10: GuestReg,
        pub r11: GuestReg,
        pub r12: GuestReg,
        pub sp: GuestReg, // R13
        pub lr: GuestReg, // R14
        pub pc: GuestReg, // R15
        pub cpsr: GuestReg,
    }

    impl ArmCpuSnapshot {
        pub const GPR_NAMES: [&'static str; 13] = [
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12",
        ];
    }
}

#[cfg(any(feature = "mips", feature = "mipsbe"))]
pub mod mips {
    use fmst_iib_api::types::GuestReg;

    /// Snapshot of MIPS32 CPU state captured before a native_call and
    /// restored after trap.
    #[derive(Debug, Clone)]
    pub struct MipsCpuSnapshot {
        pub zero: GuestReg,
        pub at: GuestReg,
        pub v0: GuestReg,
        pub v1: GuestReg,
        pub a0: GuestReg,
        pub a1: GuestReg,
        pub a2: GuestReg,
        pub a3: GuestReg,
        pub t0: GuestReg,
        pub t1: GuestReg,
        pub t2: GuestReg,
        pub t3: GuestReg,
        pub t4: GuestReg,
        pub t5: GuestReg,
        pub t6: GuestReg,
        pub t7: GuestReg,
        pub s0: GuestReg,
        pub s1: GuestReg,
        pub s2: GuestReg,
        pub s3: GuestReg,
        pub s4: GuestReg,
        pub s5: GuestReg,
        pub s6: GuestReg,
        pub s7: GuestReg,
        pub t8: GuestReg,
        pub t9: GuestReg,
        pub k0: GuestReg,
        pub k1: GuestReg,
        pub gp: GuestReg,
        pub sp: GuestReg,
        pub fp: GuestReg,
        pub ra: GuestReg,
        pub pc: GuestReg,
    }

    impl MipsCpuSnapshot {
        pub const GPR_NAMES: [&'static str; 32] = [
            "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3", "t4", "t5",
            "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7", "t8", "t9", "k0", "k1",
            "gp", "sp", "fp", "ra",
        ];
    }
}

#[cfg(feature = "x86_64")]
pub mod x86_64 {
    use fmst_iib_api::types::GuestReg;

    /// Snapshot of x86_64 CPU state captured before a native_call and
    /// restored after trap.
    #[derive(Debug, Clone)]
    pub struct X86_64CpuSnapshot {
        pub rax: GuestReg,
        pub rbx: GuestReg,
        pub rcx: GuestReg,
        pub rdx: GuestReg,
        pub rsi: GuestReg,
        pub rdi: GuestReg,
        pub rbp: GuestReg,
        pub rsp: GuestReg,
        pub r8: GuestReg,
        pub r9: GuestReg,
        pub r10: GuestReg,
        pub r11: GuestReg,
        pub r12: GuestReg,
        pub r13: GuestReg,
        pub r14: GuestReg,
        pub r15: GuestReg,
        pub rip: GuestReg,
        pub rflags: GuestReg,
    }

    impl X86_64CpuSnapshot {
        pub const GPR_NAMES: [&'static str; 16] = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11",
            "r12", "r13", "r14", "r15",
        ];
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "arm")]
    use super::arm::*;
    #[cfg(any(feature = "mips", feature = "mipsbe"))]
    use super::mips::*;
    #[cfg(feature = "x86_64")]
    use super::x86_64::*;

    #[cfg(feature = "arm")]
    #[test]
    fn arm_snapshot_is_send_sync_clone() {
        fn assert_bounds<T: Send + Sync + Clone>() {}
        assert_bounds::<ArmCpuSnapshot>();
    }

    #[cfg(feature = "arm")]
    #[test]
    fn gpr_names_cover_r0_to_r12() {
        assert_eq!(ArmCpuSnapshot::GPR_NAMES.len(), 13);
        assert_eq!(ArmCpuSnapshot::GPR_NAMES[0], "r0");
        assert_eq!(ArmCpuSnapshot::GPR_NAMES[12], "r12");
    }

    #[cfg(any(feature = "mips", feature = "mipsbe"))]
    #[test]
    fn mips_snapshot_is_send_sync_clone() {
        fn assert_bounds<T: Send + Sync + Clone>() {}
        assert_bounds::<MipsCpuSnapshot>();
    }

    #[cfg(any(feature = "mips", feature = "mipsbe"))]
    #[test]
    fn mips_gpr_names_cover_all_32_gprs() {
        assert_eq!(MipsCpuSnapshot::GPR_NAMES.len(), 32);
        assert_eq!(MipsCpuSnapshot::GPR_NAMES[0], "zero");
        assert_eq!(MipsCpuSnapshot::GPR_NAMES[31], "ra");
    }

    #[cfg(feature = "x86_64")]
    #[test]
    fn x86_64_snapshot_is_send_sync_clone() {
        fn assert_bounds<T: Send + Sync + Clone>() {}
        assert_bounds::<X86_64CpuSnapshot>();
    }

    #[cfg(feature = "x86_64")]
    #[test]
    fn x86_64_gpr_names_cover_all_16_gprs() {
        assert_eq!(X86_64CpuSnapshot::GPR_NAMES.len(), 16);
        assert_eq!(X86_64CpuSnapshot::GPR_NAMES[0], "rax");
        assert_eq!(X86_64CpuSnapshot::GPR_NAMES[15], "r15");
    }
}
