# GuestWeave intervention engineering

Use this reference to implement, compose or test an intervention against the public API.

Start from the caller's behavior contract and bindings. Function hooks use
the selected binary and function location; callsite hooks use the recorded
instruction location. Report an unexpressible operation or unresolved binding
instead of silently weakening the caller-visible guarantee.
Never recover a hook address from a source line. Exact pseudo-file paths may
share one shared state, but each path must select the correct resource instance.
The factory receives the exact path and open flags; do not silently route
every path in a multi-resource Unit to the first resource's factory. Path
patterns are not supported by the current IIB VFS.

## IIB context contract

`ctx: &mut dyn IIBContextOps` exposes architecture-neutral operations:

- `read_arg(idx)` and `write_arg(idx, value)` access one core argument word;
  consult the [ABI reference](abi.md) before treating a C argument index as a
  word slot, especially for wide values or preceding aggregate arguments.
- `set_return_value(value)` writes the guest-visible result and redirects to
  the return address. It is intended for `Call` hooks; using it in an `Enter`
  hook skips the original function. In a `Call` hook, returning from the
  adapter without setting a return value preserves the original guest call.
- `read_mem`, `write_mem`, `read_cstr`, and the `read_u*`/`write_u*` helpers
  operate on guest virtual addresses.
- `read_u16`/`read_u32`/`read_u64` and their write counterparts follow the
  target guest byte order. Use them for ordinary guest integers; use
  `read_mem`/`write_mem` with an explicit conversion only when the data format
  itself specifies a byte order that differs from the guest ABI.
- `state_of::<S>(ctx)` obtains the shared state whose concrete type `S` is
  declared by the manifest. A different Rust type cannot stand in for it.
- `native_call(target, args)` invokes a guest-native function. Release any
  borrow obtained through `state_of` before calling it, then borrow again.
  `target` must be a proven nonzero guest function address. Zero,
  `current_pc()`, and the hook callsite address do not mean "the original
  callee". When a `Call` hook should fall through to the original call, leave
  the return value unset instead of using `native_call`.
- `native_call_runtime(target, args)` uses an already resolved executable runtime
  address without the legacy resolver's module-relative interpretation. It has
  the same lock, borrow and guest-context requirements as `native_call`.

Prefer architecture-neutral operations. Necessary guest named-register access
follows the evidence and public-API boundaries in [ABI reference](abi.md);
record its exact ABI reason. If no public operation can express a required
effect, record the missing operation and the concrete candidate's limitation.
Do not substitute a placeholder or claim that the effect was implemented.

## Rust ownership boundary

Keep business behavior in ordinary Rust logic. Function-stub, callsite-hook,
and pseudo-file adapters should only decode values from `ctx`, call logic, and
write observable results back. Logic functions receive ordinary values and
intervention state rather than `IIBContextOps`.

Use one state object for operations that share counters, key-value data,
descriptor state, buffers, or caches. Since `state_of` returns a shared
reference and the manifest state must implement `Any + Send + Sync`, use
compatible interior mutability such as `Mutex`, `RwLock` or atomics. An
unwrapped `Cell` or `RefCell` does not satisfy that shared-state contract.
Drop a lock or borrow before `native_call` and
reacquire it afterward.

When cooperating behaviors share one logical state machine, reuse the public state
surface supplied by the earlier Unit rather than creating a disconnected copy.
Keep binding-local adapters thin even when the shared state lives in a another behavior module.

Compilation success does not prove that the adapter implements its contract.
An unimplemented caller-visible effect remains a limitation even when other
parts of the candidate compile and pass their tests.

## Pseudo-file descriptor lifecycle

The GuestWeave runtime, rather than an individual `PseudoFile`, owns guest
descriptor duplication and descriptor flags. It routes `dup`, `dup2`, `dup3`,
`fcntl`/`fcntl64` descriptor duplication, `F_GETFD`/`F_SETFD`, and
`F_GETFL`/`F_SETFL` for virtual descriptors on ARM32, MIPS32, and x86_64.
Duplicated descriptors share one open-file description while `FD_CLOEXEC`
remains per descriptor; successful `execve` drops marked descriptors. Do not
implement a second descriptor table or a `dup` method inside intervention
code.

This support does not turn a pseudo-file into a native kernel descriptor. The
virtual descriptor has no host fd, so an unsupported operation cannot be
passed to the host kernel as a native fallback. Implement operations consumed
by the target, or choose a different semantic owner; do not claim support by
returning success and do not require an unrelated callsite selector.
Replacing an existing native descriptor with `dup2`, process-shared open-file
state after `fork`, and syscall families not routed through the VFS still
require runtime-level evidence or another semantic owner. Standard native
resources such as `/dev/null` must retain the host/container descriptor path
rather than being converted to pseudo-files merely to obtain fd lifecycle.

## Independent Test-Harness contract

`MockIIBContextOps` supports:

- seeding with `set_arg`, `set_memory`, `set_state`, `set_return_address`,
  `set_current_pc`, and `set_native_call_response`;
- observing `return_value`, `memory_slice`, `native_call_invocations`, and
  `state_ref`.

Use the typed `read_u16/u32/u64` and `write_u16/u32/u64` helpers for guest
integers. They follow the target guest byte order. Configure the mock for the target byte order and seed numeric fixtures accordingly.

Before invoking an adapter that uses `state_of`, seed the mock with the
exact state type declared by the manifest. A fall-through `Call` hook is
verified by an unset `return_value`; it must not produce a `native_call`
invocation.

Seed each applicability input at its actual guest source. Function arguments
belong in `set_arg`; guest globals require their resolved guest address in
`set_memory`; fields reached through guest pointers require the complete
pointer chain. Writing an arbitrary argument buffer is not a substitute for a
global or pointee used by the adapter. If the source cannot be resolved from
the matching ELF/source evidence, the fixture is not a valid
positive test.

Derive expected behavior from the supplied behavior contract and independent caller evidence,
not from the generated Intervention source. Exercise the behavior required by
the contract, including shared-state transitions and caller-visible outputs.
Pass `&mut mock` to the intercept through the `IIBContextOps` interface.

Select tests from the contract rather than applying a fixed checklist. Cover
the relevant normal result and any boundary, output-buffer, shared-state, or
`native_call` behavior that distinguishes a correct mock from a forced-success
stub. Program native-call responses and assert invocation arguments when the
contract retains a native side effect. Compilation success alone is not a
semantic test; every test must contain an assertion over observable behavior.


## Forms, bindings and assembly

A function replacement defines behavior at a function entry; a callsite hook
binds behavior to a particular instruction and resume location. Both use the
context and control-flow contract in the [ABI reference](abi.md). A pseudo-file
provides behavior through an exact path/flags factory and open-file-description
state; it is not tied to the hook location of one calling binary.

Keep behavior, binding and state lifetime explicit. Reusing a function or
factory across bindings reuses implementation, not automatically shared
mutable process state. Separate opens normally create separate objects;
duplicated descriptors share an OFD. Exec restoration requires the resource's
explicit snapshot/restore implementation; arbitrary Rust heap is not inherited.

`StaticManifest` supports ordinary Rust linking, while shared-object loading
is an optional assembly route. Applications invoke `run(RunConfig)` in a
dedicated worker. Configuration, image-offset rules, supported guest features,
and lifecycle limits are maintained in the [API guide](api.md).

For a small offline resource example use [pseudo_file.rs](../examples/pseudo_file.rs).
For actual guest execution, hook binding and repeated exec use the
[independent Rust application](../examples/embedded/README.md). Build instructions
are in [build.md](build.md); mock checks and actual guest evidence establish
different parts of the contract.
