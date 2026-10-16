# Calling GuestWeave from a Rust application

This independent Cargo workspace consumes `guestweave` through a path dependency.
It does not require Firmenstein, an agent, a CLI framework, a JSON manifest or a
dynamic intervention plugin.

`build.rs` uses clang and Rust's bundled lld to build a freestanding Linux guest
without libc, defaulting to x86_64. It extracts callsite and resume offsets from
that ELF's symbols and PT_LOAD segments. `src/main.rs` directly defines a Rust
manifest, hook and pseudo-file, then calls `run(RunConfig)`. Example paths and
bytes belong to this consumer project; the framework contains no device-specific
or firmware-specific rules.

On a Linux/glibc host, install Rust and clang and prepare the
[local LibAFL dependency](../../docs/build.md). Then run these commands from this
directory:

```sh
cargo test -- --nocapture
cargo run -- /absolute/path/to/evidence/trace.json
GUESTWEAVE_TEST_OUTPUT=/absolute/path/to/arm-evidence \
  cargo test --no-default-features --features arm --target-dir target/arm -- --nocapture
```

The tests execute real guests in child processes. Each run has a 20-second
deadline; on timeout, the worker is killed and reaped. Exec tests also terminate
their process groups. Set `GUESTWEAVE_TEST_OUTPUT=/absolute/path/to/evidence` to
retain traces, stdout/stderr and diagnostics. By default, each test uses a
temporary directory that is removed on success and retained on failure. Use a
new evidence directory for each validation run.

The guest checks that the callsite return value changes from 41 to 42, reads ABC
in chunks, shares the read offset through dup, observes EOF, receives ENOSYS for
an unimplemented write on an owned resource, closes descriptors, and independently
opens another path. It also checks that exec returns ENOSYS when no launcher is
configured. Only after all checks pass does it print `embedded-guest-ok` and exit
with status 0. The Rust tests also inspect stdout/stderr, image load base, hook
PC, resume block and the persisted terminal state.

A second guest, `exec_guest.c`, exercises direct exec and fork-to-exec paths,
each with two successive image replacements. `ExecLauncher::current_process()`
restarts the same worker, and the library reads the internal startup record;
consumer code does not need a harness argument parser. The guest checks callsites
in each image, a shared read offset for two inherited duplicated descriptors,
CLOEXEC closure, argv/env values containing commas and non-UTF-8 bytes, an empty
environment from NULL envp, and independent state for a fresh open. After guest
chdir, a trace configured with a relative path still goes to its original
location. Only a successful run prints `embedded-exec-ok`. The Rust tests check
transitions, saved startup records, OFD restoration events and hook traces for
each image.

The example has been validated on a Linux ARM64 host with x86_64, ARM32 A32 EABI,
MIPSEL o32 and MIPSBE o32 guests. The respective features are `x86_64`, `arm`,
`mips` and `mipsbe`. Select one feature per build and use separate target and
evidence directories. `guest_abi.h` supplies raw Linux syscalls and callsite
instructions for this example; it is not an additional framework API. Each guest
checks results against its own ABI, including ENOSYS=89 on MIPS. The corresponding
trace word sizes and byte orders are 64/little, 32/little, 32/little and 32/big.
ARM Thumb is not covered.

These tests do not validate shared mutable OFD state between concurrently running
forked processes, resumable VMs, complete firmware services or an end-to-end agent
workflow. The backend may terminate the worker directly, so cleanup must not rely
on `run` returning.
