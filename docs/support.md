# Support and validation scope

GuestWeave currently targets Linux/glibc usermode execution. The maintained
source pins, Rust 1.98.0 builder and architecture-specific tests define the
supported configuration; a successful API mock is not evidence of guest execution.

## Contract coverage

The public test suite covers the following on a Linux ARM64 Docker host:

| Check | Scope |
| --- | --- |
| Native calls | x86_64, ARM32 A32, MIPSEL o32, MIPSBE o32; six modes per architecture, including explicit runtime addresses and MIPS PIC entry |
| Embedded worker | Static hook and pseudo-file behavior; direct and fork-to-exec, raw argv/env bytes, descriptors and trace persistence |
| Runtime unit tests | Stack-frame cleanup, runtime behavior and VFS syscall routing |
| API tests | Mock context and public intervention contracts |
| Harness | Compatible executable build, host loader/library bundle and startup |
| Offline consumption | Verified source inputs, fresh Cargo home and target, no network |
| Plugin ABI | ABI 4; older plugins are rejected before hook dispatch |

Commands are in the [build guide](build.md); the independent
[native-call](../examples/native_call_contract/README.md) and
[embedded](../examples/embedded/README.md) examples explain their assertions.

## Known limits

- Each worker owns process-global QEMU state and runs once. Cancellation, timeout
  and cleanup belong to its supervisor; guest exit may end the worker directly.
- Only one guest architecture is selected per build. Thumb and other ABIs need
  separate implementation and evidence. Additional host platforms are not covered
  by the Linux ARM64 validation matrix.
- Hook bindings use loaded binary basenames and offsets, and reject ambiguous
  matches. General dynamic loading and unusual/high-address memory layouts are
  not covered by the current freestanding guest examples.
- Native-call stack frames are reclaimed on returned errors. CPU restoration is
  guaranteed on the successful path; guest crashes and memory rollback are not
  recoverable transactions.
- Exec handoff preserves registered behavior and supported descriptor snapshots,
  not arbitrary Rust heap/global state. Concurrent forked processes do not gain
  shared mutable OFD state through snapshot/restore alone.
- Pseudo-file operations have explicit ownership/error rules. Unsupported virtual
  operations must not accidentally fall through to a native host descriptor.
  See the [ABI reference](abi.md) for the supported syscall and operation boundary.
- A rootfs path is not a sandbox. Configure container isolation and permissions in
  the consuming application as appropriate for its workload.
- Cold framework tests and harness startup do not establish that a particular
  firmware service or a Firmenstein application scenario succeeds.

## Reproduction

Keep the source manifest, dependency commits, immutable builder ID and invocation
receipt with each result. Use a new output directory for a new attempt, and retain
failed inputs and logs when investigating behavior. Public issue reports should
contain a minimal reproducer and sanitized evidence rather than private firmware,
credentials or application sessions.
