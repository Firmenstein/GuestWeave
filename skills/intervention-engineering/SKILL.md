---
name: guestweave-intervention-engineering
description: Understand GuestWeave intervention forms and implement, test or refine hooks and pseudo-files using its public API and runtime contracts.
---

# GuestWeave intervention engineering

Express the caller's behavior through the public `guestweave::api` or
compatible `fmst-iib-api` surface. Keep behavior separate from path/image
bindings, and keep context adapters thin. Do not depend on LibAFL-QEMU
internals or application-specific planning and execution machinery.

- To select an expressible form or implement a behavior, read
  [intervention engineering](../../docs/interventions.md).
- For arguments, memory, returns, native continuation/calls, descriptor
  behavior or state handoff, read the [ABI reference](../../docs/abi.md).
- To assemble and run a worker, read [runtime configuration and limits](../../docs/api.md).
- Before architecture-specific compilation or execution, read the
  [build guide](../../docs/build.md).
- Use the [offline pseudo-file example](../../examples/pseudo_file.rs) for
  mock-context testing and the [independent Rust application](../../examples/embedded/README.md)
  for actual hook/resource/exec execution.

Use the reference for the selected library version. Bind hook locations to
matching ELF evidence and distinguish unsupported operations from native
fallback. Claim cross-exec preservation only for state whose snapshot/restore
implementation can actually preserve it; ordinary process-local state is valid
and GlobalState is initialized again after exec.
Compilation, mock checks and a real guest run are separate evidence; retain
the original manifest, source identity, failed result and trace when revising
an implementation. Cross-exec preservation needs actual cross-exec evidence;
a single-image run does not establish it.
The consuming application supplies its own desired behavior, permissions and
success criteria. Keep this skill with the checkout so references resolve.
