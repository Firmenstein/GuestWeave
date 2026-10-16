//! A real guest exercising GuestWeave's public native_call contract.
use guestweave::api::{manifest::*, *};
use guestweave::{run, Intervention, RunConfig};
use std::sync::atomic::{AtomicBool, Ordering};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(feature = "x86_64")]
const GUEST_ARCH: Arch = Arch::X86_64;
#[cfg(feature = "arm")]
const GUEST_ARCH: Arch = Arch::Arm;
#[cfg(any(feature = "mips", feature = "mipsbe"))]
const GUEST_ARCH: Arch = Arch::Mips;

static GUARDED_CALL_ACTIVE: AtomicBool = AtomicBool::new(false);

fn intercept(ctx: &mut dyn IIBContextOps) {
    let depth = ctx.read_arg(0).expect("depth");
    let entries_addr = ctx.read_arg(1).expect("entries address");
    let mode = ctx.read_arg(2).expect("mode");
    let bodies_addr = ctx.read_arg(3).expect("bodies address");
    let pc = ctx.current_pc();
    let entries = ctx.read_u32(entries_addr).expect("counter") + 1;
    ctx.write_u32(entries_addr, entries).expect("counter write");
    eprintln!(
        "PROBE hook mode={mode} depth={depth} entries={entries} runtime_pc={pc:#x} elf_va={PROBE_LINK_VA:#x} manifest_offset={PROBE_OFFSET:#x} map_base={ELF_MAP_BASE:#x}"
    );
    assert_eq!(
        pc, PROBE_LINK_VA,
        "the ET_EXEC fixture requires identity mapping"
    );

    match mode {
        0 => {}
        1 => {
            assert!(depth <= 2);
            let value = if depth == 2 {
                700
            } else {
                let returned = ctx
                    .native_call_runtime(pc, &[depth + 1, entries_addr, mode, bodies_addr])
                    .expect("bounded nested call");
                eprintln!("PROBE nested-return depth={depth} value={returned}");
                returned + 100
            };
            ctx.set_return_value(value).expect("replace bounded call");
        }
        2 => {
            if GUARDED_CALL_ACTIVE.load(Ordering::SeqCst) {
                eprintln!("PROBE guard-fallthrough runtime_pc={pc:#x}");
                return;
            }
            GUARDED_CALL_ACTIVE.store(true, Ordering::SeqCst);
            let returned = ctx.native_call_runtime(pc, &[depth, entries_addr, mode, bodies_addr]);
            GUARDED_CALL_ACTIVE.store(false, Ordering::SeqCst);
            let returned = returned.expect("guarded native call");
            eprintln!("PROBE guarded-native-return value={returned}");
            ctx.set_return_value(returned + 1)
                .expect("replace guarded call");
        }
        3 => {
            assert!(depth <= 1);
            let returned = if depth == 1 {
                601
            } else {
                let result = ctx.native_call(PROBE_OFFSET, &[1, entries_addr, mode, bodies_addr]);
                eprintln!(
                    "PROBE manifest-offset-call raw_target={PROBE_OFFSET:#x} result={result:?}"
                );
                result.expect("fixture has one executable relocated candidate")
            };
            ctx.set_return_value(returned)
                .expect("address-resolution result");
        }
        4 => {
            if depth == 1 {
                ctx.set_return_value(602).expect("nested explicit result");
                return;
            }
            assert!(
                ctx.native_call(pc, &[1, entries_addr, mode, bodies_addr])
                    .is_err(),
                "legacy address has two executable candidates"
            );
            let result = ctx
                .native_call_runtime(pc, &[1, entries_addr, mode, bodies_addr])
                .expect("explicit VA selects only its executable address");
            ctx.set_return_value(result).expect("explicit result");
        }
        5 => {
            let before = ctx.read_reg("t9").ok();
            // The assembly callee checks t9 and uses it to find its own data.
            // Other architectures exercise the same explicit-address surface.
            let result = ctx
                .native_call_runtime(PIC_LINK_VA, &[bodies_addr])
                .expect("PIC native callee");
            assert_eq!(ctx.read_reg("t9").ok(), before, "caller register restored");
            ctx.set_return_value(result).expect("PIC return");
        }
        _ => panic!("unexpected experiment mode"),
    }
}

static MANIFEST: StaticManifest = StaticManifest {
    abi_version: CURRENT_ABI_VERSION,
    arch: GUEST_ARCH,
    global_state: StaticGlobalState {
        type_name: "()",
        init_fn: || Box::new(()),
    },
    callsite_hooks: &[],
    function_stubs: &[FunctionStubStatic {
        id: "native-call-reentry-probe",
        target: ModuleTargetStatic {
            binary: "probe-guest",
            offset: PROBE_OFFSET,
            symbol_hint: Some("probe"),
        },
        flavor: HookFlavor::Call,
        entry_fn: intercept,
    }],
    pseudo_files: &[],
};

fn main() {
    let guest = std::env::args_os().nth(1).expect("guest ELF path");
    let trace = std::env::args_os().nth(2).expect("trace output path");
    let mode = std::env::args_os().nth(3).expect("experiment mode");
    let mut config = RunConfig::new(guest, "/");
    config.args = vec![mode];
    config.intervention = Intervention::Static(&MANIFEST);
    config.trace_output = Some(trace.into());
    if let Err(error) = run(config) {
        panic!("GuestWeave failed: {error}");
    }
}
