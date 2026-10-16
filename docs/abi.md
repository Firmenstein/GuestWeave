# GuestWeave ABI and state access

This reference defines the public intervention context. Intervention code
uses `guestweave::api::IIBContextOps` (or the compatible `fmst_iib_api` crate);
it must never depend on `libafl_qemu` or host process, filesystem, socket, or
register APIs.

## Two levels of argument access

`read_arg(index)` and `write_arg(index, value)` access **one core ABI argument
word** as `GuestReg`. For ordinary one-word integer/pointer parameters whose
layout uses one slot each, the index matches the C argument position. Runtime
does not know the function signature: wide or aggregate arguments, alignment
gaps and non-core register classes must not be indexed as if every C parameter
occupied one word. Use the evidenced ABI slot layout for those cases.

`read_arg_words(index, count)`, `read_arg_bytes(index, size)`, and
`write_arg_bytes(index, data)` use **core ABI word slots**, not logical C
argument indexes. Slot zero is the first core argument word; a struct split
over registers and the argument area can therefore be read as contiguous slots
when the caller supplies its ABI slot and byte size. The runtime handles the
current ARM AAPCS, MIPS O32, and x86_64 System V core layouts. It preserves
untouched bytes in a partial final word.

The byte helpers cover core integer/pointer classes only. They do not guess
floating-point, SIMD/vector, variadic, hidden-structure-return, or compiler-
specific extensions. If the required value uses one of those classes, record
the exact operation-level limitation and do not reinterpret another register
as the requested value.

## Stack and memory

`read_mem`/`write_mem` operate on guest virtual addresses and are the primitive
for pointer arguments, globals, buffers, and pointed-to structs. They do not
access host memory. `read_stack(offset, size)` and `write_stack(offset, data)`
resolve `SP + offset` with overflow checks and are useful when assembly proves
that a field lives in the current frame. A negative offset is allowed for a
frame that has already reserved locals. Use the explicit guest byte-order
`read_u16/u32/u64` and `write_u16/u32/u64` helpers for ordinary integers.

`read_return_bytes(size)` and `write_return_bytes(data)` expose the core
register bytes of a supported aggregate return. They do not perform the
control transfer. A replacement `Call` hook must write the aggregate and then
complete the return path with `set_return_value` (for a scalar first word) or
the runtime-specific return operation supplied by a future capability. A
hidden sret pointer is a normal pointer argument and must be handled through
guest memory instead of this return-register surface.

The runtime's named-register escape hatch covers the architecture's core
general-purpose/control registers and aliases (`sp`, `pc`, `lr`/`ra` where
applicable). It does not claim FP, SIMD, vector, system-control, or arbitrary
QEMU-internal register access. Generated code should remain architecture
neutral and use named registers only when source evidence and the public API
establish that the access is required; record the exact ABI reason when it is
used.

## Pseudo-file and descriptor semantics

Return semantic `Errno` variants from pseudo-file operations. Runtime encodes
the selected guest syscall ABI; `as_neg_i64()` is the negative asm-generic
number, not a portable guest errno. For example ENOSYS is 89 on MIPS o32 and
38 on ARM32/x86_64. Hook return protocols remain governed by their own ABI.

`PseudoFileFactory(path, flags)` decides ownership before a descriptor exists:

- `Handled(file)` creates an IIB-owned virtual descriptor;
- `NativeFallback` declines that exact path/flag combination and lets the
  native guest open path run;
- `GuestError(errno)` returns an error to the guest and must never fall through
  to native execution.

Once a factory returns `Handled`, operations routed by the runtime on that
descriptor are owned by the `PseudoFile`. `read` and `write` copy bytes through
guest memory; `lseek`, the legacy `fstat` syscall, `fsync`, `ioctl`, and `close`
expose the operation that the intervention must implement. The runtime routes
legacy `fstat` as ARM32 108, MIPS o32 4108, and x86_64 5. `fstat64`,
`fstatat64`, `newfstatat`, `tell`, and `readline` are not implicit routes. A
default `ENOSYS` is a guest-visible unsupported operation, not a routing signal.
Descriptor duplication and close-on-exec are runtime properties described by
capabilities; the implementation must preserve shared open-file-description
state when the manifest claims it.

Trait methods and routed guest syscalls are distinct. Implementing a method
does not install an additional syscall interception. The fstat variants listed
above, `tell`, and `readline` remain unrouted. Unrouted syscalls can continue
through the backend's native syscall path, even for a virtual descriptor that
has no host fd. This is an unsupported execution path, not evidence that the
resource implements a valid native fallback.
Check the selected
runtime's [VFS dispatch](../fmst-iib-runtime/src/vfs.rs) and actual guest path
before claiming support for an operation. Keep an unexpressible required
operation visible to the caller.

For a pseudo-file that must survive the Runtime's host-harness `execve`,
implement both `exec_snapshot` and `exec_restore`. The snapshot is opaque
bytes owned by the intervention; the Runtime records one snapshot per shared
open-file-description, keeps non-`CLOEXEC` descriptor numbers and status flags,
and reconstructs the object through the same path factory. Returning the
default `None` deliberately means that a live virtual descriptor cannot cross
the image boundary; the Runtime returns `ENOSYS` for that attempted exec
instead of silently dropping it. `CLOEXEC` descriptors are omitted as Linux
requires. This optional v3 API is for state that is actually serializable; it
does not make arbitrary Rust trait objects, host resources, or an unverified
device protocol portable.

Do not emulate an ioctl table in the runtime itself. The generic bridge supplies the
descriptor lifecycle, guest-memory access, dispatch, and error/fallback
semantics. The generated intervention registers only the commands and state that its
behavior contract requires.

## Native continuation and failure

ABI 4 adds `native_call_runtime(target, args)` for a proven, already resolved
runtime virtual address. It checks that exact address for executable permission
without also trying a module-relative interpretation. `native_call` keeps the
legacy resolver and rejects an address when both interpretations are executable.
MIPS o32 calls establish the callee's `$t9` for PIC entry and restore caller
registers on successful return. Rebuild ABI 3 and older plugins; ABI 4 runtimes
reject them before hook dispatch.

`native_call(target, args)` is an explicit nested guest call. The target must
be a proven nonzero guest function address from the manifest or matching ELF
evidence; a hook address, `current_pc()`, or zero is never an implicit
“original callee”. Release intervention-owned Rust locks or borrows across the call.
Also check the guest context at the hook: an otherwise valid native routine
may reacquire a lock held by its caller or assume initialization has finished.
Choose a context-compatible callee or boundary; do not release caller-owned
guest locks to bypass such a conflict. In a `Call` hook, leaving the return
value unset means native continuation; calling `set_return_value` takes
ownership of the return path.

An error returned after native-call stack allocation releases the allocated
frame and balances nesting depth. CPU restoration is guaranteed on successful
completion; an error does not promise CPU or guest-memory rollback. Guest
termination can end the worker directly. The
[native-call example](../examples/native_call_contract/README.md) checks static
function-hook re-entry on x86_64, ARM32 A32 and MIPSEL/MIPSBE o32; it is not a
general guest crash-recovery test.

The runtime manifest is descriptive metadata for the concrete runtime build;
its names do not replace evidence about the operation or prove target behavior.
Use the public API and source-backed ABI facts in the intervention contract. If an
operation is not expressible, preserve the exact gap and candidate for the next
implementation or runtime iteration without treating a capability declaration as proof of the missing behavior. A virtual descriptor has no host fd: for routed operations, an unsupported
method on an owned virtual resource returns a guest error, not native fallback.
The unrouted-syscall limitation above must be checked separately.
`PseudoFileOpen::NativeFallback` is only for paths the intervention does not own.

## Test-harness obligations

`write_return_bytes` changes return register bytes without marking a hook as
handled, in both the mock and the runtime. Only `set_return_value` completes
the hook's return path. For aggregate-return adapters, assert the explicit
control operation and the register bytes separately, then verify the guest path.

`MockIIBContextOps` mirrors these semantics. Use `set_arg` for scalar argument
slots, `set_memory` for actual guest pointers and globals, and
`set_stack_pointer` plus `set_memory` for stack fixtures. Test the complete
pointer chain and byte order. Use `set_state` with the manifest-declared
top-level `GlobalState` before calling `state_of`. Assert caller-visible bytes,
return words, state transitions, and native-call arguments. Compilation or a
non-error return alone is not evidence that the ABI contract is implemented.


See [intervention engineering](interventions.md) for composition and tests, and [runtime configuration](api.md) for worker and exec-launch constraints.
