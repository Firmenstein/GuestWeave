# GuestWeave API and boundaries

Intervention authors depend on `fmst-iib-api` or the `guestweave::api` facade.
They do not depend directly on `libafl_qemu`, QEMU internals, the host filesystem,
or Firmenstein's Analyzer, Plan or Runner. The existing `fmst` crate names remain
available for compatibility; independent Rust applications can use the framework.

See [intervention engineering](interventions.md) for implementing and composing
behavior, and the [ABI reference](abi.md) for precise argument, control-flow and
state-access semantics.

## Using the library

An independent Cargo project can use a local path dependency. Adjust the path
relative to the consuming project:

```toml
[dependencies]
guestweave = { path = "../GuestWeave" }

[dev-dependencies]
guestweave = { path = "../GuestWeave", features = ["mock"] }
```

The default configuration builds the API without QEMU. Use
`guestweave::api::mock` for offline behavior tests. To integrate the runtime on
Linux, select one architecture feature: `arm`, `mips` (little endian), `mipsbe`
or `x86_64`, and use `guestweave::{run, RunConfig, Intervention}`. Public callers
do not need to import LibAFL types. `guestweave::runtime` also exposes a lower-level
interface for consumers integrating their own EmulatorModule. Do not select
multiple guest architectures or use `--all-features`.

Cargo resolution currently requires the adjacent local LibAFL checkout described
in the [build guide](build.md). The library is not yet available as a standalone
crates.io dependency.

The [executable pseudo-file example](../examples/pseudo_file.rs) demonstrates
partial reads, EOF, guest-memory writes and errors for unsupported operations.
Its bytes are supplied by the caller; it contains no firmware-specific device
values and does not register the resource in a running guest. For actual guest
execution, see the [independent Rust example](../examples/embedded/README.md).
It defines and statically links a `StaticManifest` directly, without a cdylib,
generator or JSON-to-Rust conversion.

## Rust runtime entry point

`RunConfig::new(binary, rootfs)` specifies the main ELF and guest loader prefix.
The caller configures `intervention`, `args`, `argv0`, `env`, `unset_env`,
`trace_output` and optional `syscall_trace`, then calls `run(config)` once.
The rootfs is not a chroot or an isolation guarantee. The caller controls the
working directory, file permissions, containers and process supervision.

| Configuration or result | Contract |
| --- | --- |
| `Intervention::Static(&MANIFEST)` | Link Rust behavior and bindings directly; validate the ABI and compiled architecture. |
| `Intervention::SharedObject(path)` | Load an existing plugin with the same validation; keep the library loaded until process exit. |
| `Intervention::None` | Install no intervention; traces can still be collected. |
| `env` / `unset_env` | Preserve OS bytes. A nonempty env replaces the guest environment; an empty env inherits the worker baseline, matching the existing harness. An empty list does not mean an empty environment. |
| `exec: None` (default) | Return ENOSYS for execve/execveat and record `guest_exec_disabled`; do not allow unmanaged host execution. |
| `ExecLauncher::current_process()` | Restart the current worker and restore guest startup arguments. Supports Static/SharedObject/None without a CLI parser. |
| `ExecLauncher::harness(program)` | Adapt the existing harness argument protocol. Supports SharedObject/None; Static with this mode is rejected before initialization. |
| `RunOutcome` | Information returned by backend shutdown. It does not indicate scenario success or guarantee a Linux guest exit code. |
| `RunError` | Distinguish configuration, manifest, diagnostics, environment, initialization, dispatch, execution and unhandled-stop failures. Do not blindly resume an unhandled breakpoint, crash or timeout. |

The backend owns process-global state. Run it once on a dedicated worker's main
thread, before starting other threads. A second invocation is rejected.
Initialized modules remain alive until worker exit so global callbacks cannot
refer to freed objects. Linux guest exit or a successful exec may directly
terminate or replace the worker; some backend startup failures also terminate
the process. Callers must observe both the worker's exit status and persisted
evidence, and implement timeout, cancellation and cleanup externally. This API
does not provide a reusable Session abstraction.

A directly linked worker can enable managed exec with:

```rust,ignore
config.exec = Some(guestweave::ExecLauncher::current_process()?);
```

When guest exec succeeds, the runtime reexecutes the same host program with the
original worker arguments. The program registers the same Intervention and calls
`run` again. Before initializing QEMU, the library restores binary, argv/argv0,
exact env/unset settings, rootfs, trace and syscall-trace configuration. The
internal startup record uses a versioned raw-byte format and validates its
version, PID, worker path and Intervention kind. Unknown versions or mismatches
are rejected. This is an internal startup channel, not a public JSON configuration
API. `FMST_EXEC_HANDOFF`, `FMST_EXEC_DEPTH`, `FMST_EXEC_TRANSITION` and
`GUESTWEAVE_EXEC_CONFIG` are reserved host handoff variables and do not enter the
guest environment. When tracing is enabled, the record is retained alongside OFD
snapshots, and the transition contains a `worker_launch_handoff` path. Without
tracing, startup records are deleted after consumption. Failed records are retained.

Worker startup code must tolerate reexecution: do not clear evidence or perform
non-repeatable side effects before `run`. Do not select a different static
manifest because the working directory or environment changed. Keep the worker
and plugins unchanged during execution. A worker started directly by the kernel
can use `current_process()`. If an outer launcher explicitly invokes the host
loader, set the launcher's `program` to the actual worker ELF rather than the
loader referenced by `/proc/self/exe`. The caller supplies any optional host
loader and library path. Firmenstein's thin harness continues to use
`harness(program)` with SharedObject, preserving compatibility with generated
plugins.

Exec reconstructs behavior functions and bindings. GlobalState is initialized
again; arbitrary Rust heap state is not inherited. Non-CLOEXEC pseudo-file OFD
state is restored through the existing ABI-v3 `exec_snapshot`/`exec_restore`
interface. Handoff is rejected if a live descriptor does not support snapshots.
The guest's working directory is preserved. Host paths for the rootfs, plugins
and traces are fixed as absolute paths on the first `run`. This snapshot mechanism
does not guarantee shared mutable state between concurrently running forked
parent and child processes.

Real-guest validation covers direct and fork-to-exec paths with two successive
exec transitions, hook/OFD/CLOEXEC behavior, non-UTF-8 argv/env, empty guest
environments and chdir on x86_64, ARM32 A32 and MIPS o32 in both byte orders.
These results do not establish support for other ABIs, Thumb or complete firmware
scenarios. See the [independent example](../examples/embedded/README.md) for
commands and scope.

## Reusing behavior, bindings and state

Pseudo-file implementations return semantic `Errno` variants. At the syscall
return boundary, the runtime encodes the error number for the selected guest
architecture. The public enum's asm-generic discriminants remain ABI-stable;
`as_neg_i64()` only negates that generic number and is not a portable guest errno.
For example, `ENOSYS` is 89 on MIPS and 38 on ARM/x86_64. Ordinary function hooks
follow their own API/ABI return contract.

- **Behavior:** an ordinary hook function or `PseudoFile` implementation,
  independent of LibAFL.
- **Bindings:** `CallsiteHookStatic`/`FunctionStubStatic` bind functions to image
  offsets; `PseudoFileStatic` binds a factory to one or more paths. Multiple
  bindings can reuse the same implementation.
- **Lifecycle:** each factory invocation creates a new open file description.
  Duplicated descriptors share its state; independent opens normally create
  independent instances. Reusing a Rust type does not automatically share data
  between processes. Fork/exec boundaries and snapshot/restore capabilities
  require validation of the actual execution path.

Hook image selection currently uses loaded binary basenames and rejects ambiguous
matches. Offsets are relative to the lowest file mapping, not arbitrary runtime
PCs; symbol hints do not automatically resolve them. The independent example
extracts offsets from the ELF built for that run and checks the bindings against
actual traces. Dynamic loading and stronger image identifiers are outside the
current scope.

The core contracts are:

- `IIBContextOps` provides guest arguments, registers, memory, stack, return
  values, guest allocation, shared state and native calls with evidenced targets.
  `native_call_runtime` accepts an already resolved executable runtime address;
  `native_call` retains the legacy address resolver and rejects ambiguous targets.
- `Manifest` describes the architecture, function/callsite hooks, global state
  and exact pseudo-file ownership. `CURRENT_ABI_VERSION` is 4. ABI 4 plugins
  are required; ABI 3 and older plugins are rejected before hook dispatch.
- `PseudoFileFactory(path, flags)` chooses `Handled`, `NativeFallback` or
  `GuestError` before creating a descriptor. Unsupported operations on an owned
  descriptor must not masquerade as native fallback.
- Descriptor duplication, OFD state, descriptor flags and `CLOEXEC` belong to
  the runtime. A pseudo-file should implement `exec_snapshot`/`exec_restore` only
  when its state can actually be serialized.
- Traces, load maps, ELF identities and receipts are execution evidence, not
  substitutes for success criteria or target semantics.

GuestWeave provides raw harness traces, load maps, capabilities and exec
transitions. Firmenstein owns Runner session/attempt receipts, interpretation of
traces against firmware sources, core-debug packaging and success criteria.
Independent consumers supply their own application policies.

The [`native_call_contract`](../examples/native_call_contract/README.md) example
uses only the public API to test all four architectures. It covers same-address
function-hook reentry, guarded native execution, target-address disambiguation,
explicit runtime-address calls and MIPS o32 PIC entry.
A returned native_call error releases stack frames and balances nesting counts.
CPU context restoration is guaranteed only on success; errors do not roll back
guest memory or recover a terminated process.

| Contract | Source |
| --- | --- |
| Intervention API | [`fmst-iib-api`](../fmst-iib-api/src/lib.rs) |
| Context | [`context.rs`](../fmst-iib-api/src/context.rs) |
| Manifest | [`manifest.rs`](../fmst-iib-api/src/manifest.rs) |
| Pseudo-file | [`pseudo_file.rs`](../fmst-iib-api/src/pseudo_file.rs) |
| Runtime | [`fmst-iib-runtime`](../fmst-iib-runtime/src/lib.rs) |
| Harness | [`harness-x86`](../harness-x86/Cargo.toml), [`harness-arm`](../harness-arm/Cargo.toml), [`harness-mips`](../harness-mips/Cargo.toml) |
