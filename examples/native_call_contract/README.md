# Native-call contract example

This is an independent GuestWeave consumer. It uses only the public API to
exercise a real freestanding ET_EXEC guest through six native-call cases:

- direct function-hook fallthrough;
- bounded same-address re-entry;
- guarded re-entry that falls through into the native body;
- module-relative target resolution;
- explicit runtime-address calls when the legacy resolver sees two candidates;
- guest-native PIC entry, including the callee's `$t9` on MIPS o32.

The guest and its bindings are built from the selected architecture feature,
so the test does not carry a guessed address or a synthetic CPU fixture. The
supported features are `x86_64` (default), `arm`, `mips`, and `mipsbe`.

The runtime is Linux/glibc-only. Run these commands in the project builder (or
another Linux environment with the pinned QEMU and libvharness sources):

```sh
cargo test --locked --release --manifest-path examples/native_call_contract/Cargo.toml --offline
# Run each guest architecture with its own native Linux target directory.
for feature in x86_64 arm mips mipsbe; do
  cargo test --locked --release --offline \
    --manifest-path examples/native_call_contract/Cargo.toml \
    --no-default-features --features "$feature" \
    --target-dir "/tmp/guestweave-native-call-$feature"
done
```

Each mode runs in a separate worker with a 30-second deadline. The test checks
the guest's return value/body count, hook count, ELF addresses and exit trace.
Set `GUESTWEAVE_TEST_OUTPUT` to a fresh output directory to retain the guest
ELF, bindings, stdout/stderr and traces on success. The default temporary
directory is retained on failure.

These cases verify static function hooks for ARM32 A32, MIPSEL/MIPSBE o32 and
x86_64. They do not inject guest crashes or prove CPU/guest-memory rollback
after errors. Stack-frame error cleanup has separate runtime unit tests.

All four features were run in the fixed Linux builder; see the
[support and validation scope](../../docs/support.md).
For a complete offline delivery with vendored Cargo crates and pinned QEMU and
libvharness sources, use `tools/offline.py run --suite native-call`; see the
[offline build instructions](../../docs/build.md#offline-delivery).
