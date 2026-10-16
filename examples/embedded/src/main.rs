//! A consumer of GuestWeave's Rust API, with no CLI framework or .so plugin.
use guestweave::api::{manifest::*, *};
use guestweave::{run, ExecLauncher, Intervention, RunConfig};

include!(concat!(env!("OUT_DIR"), "/demo-bindings.rs"));

#[cfg(feature = "x86_64")]
const GUEST_ARCH: Arch = Arch::X86_64;
#[cfg(feature = "arm")]
const GUEST_ARCH: Arch = Arch::Arm;
#[cfg(any(feature = "mips", feature = "mipsbe"))]
const GUEST_ARCH: Arch = Arch::Mips;

struct ByteStream {
    bytes: &'static [u8],
    offset: usize,
}

impl PseudoFile for ByteStream {
    fn exec_snapshot(&mut self) -> Result<Option<Vec<u8>>, Errno> {
        Ok(Some(vec![1, self.offset as u8]))
    }

    fn exec_restore(&mut self, state: &[u8]) -> Result<(), Errno> {
        match state {
            [1, offset] if (*offset as usize) <= self.bytes.len() => {
                self.offset = *offset as usize;
                Ok(())
            }
            _ => Err(Errno::EINVAL),
        }
    }

    fn read(
        &mut self,
        address: GuestAddr,
        len: usize,
        ctx: &mut dyn IIBContextOps,
    ) -> Result<usize, Errno> {
        let n = len.min(self.bytes.len().saturating_sub(self.offset));
        ctx.write_mem(address, &self.bytes[self.offset..self.offset + n])?;
        self.offset += n;
        Ok(n)
    }
}

fn open_stream(_: &str, _: i64) -> PseudoFileOpen {
    PseudoFileOpen::Handled(Box::new(ByteStream {
        bytes: b"ABC",
        offset: 0,
    }))
}

fn answer(ctx: &mut dyn IIBContextOps) {
    let value = ctx.read_arg(0).expect("first guest argument");
    ctx.set_return_value(value + 1)
        .expect("resume after callsite");
}

static INTERVENTION: StaticManifest = StaticManifest {
    abi_version: CURRENT_ABI_VERSION,
    arch: GUEST_ARCH,
    global_state: StaticGlobalState {
        type_name: "()",
        init_fn: || Box::new(()),
    },
    callsite_hooks: &[CallsiteHookStatic {
        id: "answer",
        target: ModuleTargetStatic {
            binary: "demo-guest",
            offset: CALL_OFFSET,
            symbol_hint: Some("demo_call"),
        },
        resume_offset: RESUME_OFFSET,
        flavor: HookFlavor::Call,
        entry_fn: answer,
    }],
    function_stubs: &[],
    pseudo_files: &[PseudoFileStatic {
        id: "byte-stream",
        paths: &["/guestweave/demo-bytes", "/guestweave/demo-alias"],
        factory: open_stream,
        impl_name: "ByteStream",
    }],
};

mod exec_bindings {
    include!(concat!(env!("OUT_DIR"), "/exec-bindings.rs"));
    pub(super) const CALL: u64 = CALL_OFFSET;
    pub(super) const RESUME: u64 = RESUME_OFFSET;
}
static EXEC_INTERVENTION: StaticManifest = StaticManifest {
    abi_version: CURRENT_ABI_VERSION,
    arch: GUEST_ARCH,
    global_state: StaticGlobalState {
        type_name: "()",
        init_fn: || Box::new(()),
    },
    callsite_hooks: &[CallsiteHookStatic {
        id: "exec-answer",
        target: ModuleTargetStatic {
            binary: "exec-guest",
            offset: exec_bindings::CALL,
            symbol_hint: Some("exec_call"),
        },
        resume_offset: exec_bindings::RESUME,
        flavor: HookFlavor::Call,
        entry_fn: answer,
    }],
    function_stubs: &[],
    pseudo_files: INTERVENTION.pseudo_files,
};

fn main() {
    let trace = std::env::args_os()
        .nth(1)
        .expect("supply a trace output path");
    let mut config = RunConfig::new(env!("DEMO_GUEST"), "/");
    config.intervention = Intervention::Static(&INTERVENTION);
    config.trace_output = Some(trace.into());
    if let Some(mode) = std::env::args_os().nth(2) {
        config.binary = env!("EXEC_GUEST").into();
        config.args = vec![mode, env!("EXEC_GUEST").into()];
        config.intervention = Intervention::Static(&EXEC_INTERVENTION);
        config.exec = Some(ExecLauncher::current_process().expect("worker executable"));
    }
    if let Err(error) = run(config) {
        // Runtime diagnostics are separated from guest stdout/stderr.
        // Propagate failure to the worker's caller; ordinary guest exit does
        // not return here and keeps its own exit status.
        panic!("GuestWeave failed: {error}");
    }
}
