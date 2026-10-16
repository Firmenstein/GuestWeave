# Building GuestWeave

Use Python 3.9+, Git and Rust 1.98.0. Runtime builds need Linux/glibc;
API-only checks can run on macOS. The Docker builder supplies the native build
tools. Select exactly one guest architecture per build.

## Maintained dependencies

The directory layout is:

```text
workspace/
  GuestWeave/
  lib/LibAFL/
```

From `GuestWeave/`, run:

```sh
python3 tools/prepare_dependencies.py
python3 tools/check_libafl_dependency.py
```

The preparation script fetches the exact maintained LibAFL commit recorded in
[`dependencies/libafl-qemu.json`](../dependencies/libafl-qemu.json). The byte-argv
patch is integrated into that commit. Existing directories are verified read-only;
wrong revisions or uncommitted files cause an error. Preserve any local edits and
use another workspace instead of resetting them.

`--checkout /absolute/path` changes the preparation destination, but Cargo path
dependencies still require the layout above for builds. `--source /path/to/repo`
can read the pinned Git object from a local repository instead of the network.

LibAFL's build scripts pin the maintained QEMU bridge and libvharness URLs and
commits. [`linux-runtime.json`](../dependencies/linux-runtime.json) records those
same pins. Verification checks the integrated patch's critical source hashes,
workspace version and the exact native dependency constants. It does not apply
patches or upgrade dependencies. [Third-party provenance](../THIRD_PARTY.md)
records upstream versions and licensing.

## API checks

```sh
cargo test --locked -p fmst-iib-api --features mock
cargo test --locked -p guestweave
cargo run --locked --example pseudo_file --features mock
cargo doc --locked -p guestweave -p fmst-iib-api --no-deps
python3 -m unittest discover -s tools/tests -v
```

Add `--offline` to Cargo commands only when the required crates are already
cached. Workspace resolution needs the local LibAFL manifests even when QEMU is
not compiled. This library is currently consumed through path dependencies.

## Offline delivery

Preparation may use the network. Consumption always runs with networking disabled,
a verified builder image, a fresh native build volume and vendored Cargo sources.
Build the image and prepare from a GuestWeave Git checkout:

```sh
docker build -t guestweave/builder:rust1.98-bookworm docker/builder
python3 tools/offline.py prepare \
  --output "$PWD/dist/offline" \
  --builder-image guestweave/builder:rust1.98-bookworm \
  --export-builder
```

Choose a new output directory; existing deliveries are never overwritten.
Preparation exports exact Git commits from all three maintained dependencies,
verifies the integrated patch, and vendors the main workspace and both independent
examples using their Cargo.lock files. It does not include dependency Git histories.

For local source repositories, supply `--libafl-source`, `--qemu-source` and
`--libvharness-source`. Only the pinned commit's objects are exported; dirty and
untracked source files are not copied. To prepare without networking, also supply
all three repositories, a complete registry cache and `--prepare-offline`:

```sh
python3 tools/offline.py prepare \
  --output /absolute/path/new-offline-delivery \
  --libafl-source /absolute/path/lib/LibAFL \
  --qemu-source /absolute/path/qemu-libafl-bridge \
  --libvharness-source /absolute/path/libvharness \
  --registry-cache /absolute/path/cargo/registry \
  --prepare-offline --export-builder
```

An incomplete registry cache fails preparation; it does not silently enable
networking. Only the supported usermode build is included. The maintained QEMU
snapshot omits upstream Git submodule contents used by systemmode, UI, ROMs and
tests; its Meson wheel is tracked in the source. See that repository's UPSTREAM.md.

The prepared directory contains:

| Path | Contents |
| --- | --- |
| `workspace/GuestWeave/` | Public source and per-file SOURCE-MANIFEST.json |
| `workspace/lib/LibAFL/` | Maintained source with the patch already integrated |
| `sources/` | Framework and native source archives |
| `vendor/`, `workspace/.cargo/config.toml` | Locked Cargo source replacement |
| `DELIVERY.json`, `builder-tools.json` | File hashes, source pins, image ID and build tools |
| `builder-image.tar` | Builder export when `--export-builder` is selected |

Copy the whole delivery to a machine with Docker and the same host architecture.
Load its builder, verify inputs, then run a cold build:

```sh
docker load --input /absolute/path/offline/builder-image.tar
python3 /absolute/path/offline/workspace/GuestWeave/tools/offline.py verify \
  --delivery /absolute/path/offline
python3 /absolute/path/offline/workspace/GuestWeave/tools/offline.py run \
  --delivery /absolute/path/offline \
  --output /absolute/path/new-results-x86 \
  --arch x86_64 --suite native-call
```

`run` uses the recorded image ID, `--pull=never`, `--network=none`, an empty Cargo
home and an absent target. Inputs are read-only; native sources are extracted into
a new writable native Docker volume. Cargo runs with `--frozen`, and Pip's network
access is disabled. Missing or modified inputs fail before building.

Available suites:

| Suite | Check |
| --- | --- |
| `native-call` | Four function/native-call modes in real guests |
| `embedded` | Hook, pseudo-file, descriptor, direct/fork-exec and argv/env contracts |
| `runtime-unit` | Linux runtime unit tests for the chosen architecture |
| `api` | API/Mock unit tests, without building QEMU |
| `harness` | Compatible harness build and loader/library bundle export |

Use `--arch x86_64`, `arm`, `mips` or `mipsbe`, and optionally `--jobs` (default 4).
Each output must be a new directory outside the immutable delivery. Receipts,
build logs and guest evidence remain there, including on failure. The invocation's
container and native volume are cleaned up after completion or interruption.

The exported image binds a concrete build environment. Rebuilding a Dockerfile
against changing base-image tags or Debian package repositories is a separate
preparation step; different environments are not promised to produce identical
ELF bytes. Keep source pins, builder identity and result receipts together.

## Direct Linux and Docker builds

On Linux, after preparing dependencies:

```sh
cargo test --locked -p fmst-iib-runtime --no-default-features --features x86_64
cargo build --locked --release -p fmst-harness-x86
cargo test --locked --release --manifest-path examples/embedded/Cargo.toml
```

For another guest use its feature and a separate target directory. Harness package
names are `fmst-harness-arm`, `fmst-harness-mips` and `fmst-harness-x86`.
Big-endian MIPS uses `-p fmst-harness-mips --no-default-features --features big-endian`.
Do not use `--all-features` or combine architecture features through `--workspace`.

On Docker Desktop, keep Cargo's active target on a native Docker volume rather
than a host bind mount. From the outer `workspace/` directory:

```sh
docker run --rm \
  --mount "type=bind,src=$PWD,dst=/workspace" \
  --mount type=volume,dst=/cargo-target,volume-nocopy \
  --workdir /workspace/GuestWeave \
  guestweave/builder:rust1.98-bookworm \
  cargo test --locked -p fmst-iib-runtime --no-default-features --features x86_64 \
    --target-dir /cargo-target
```

This direct path may fetch Cargo and native sources. Use the offline delivery
entry point when every build input must be prepared in advance. Each concurrent
build needs its own writable target and native source directories.

To export a runtime bundle in the same Linux environment as the build:

```sh
python3 tools/build_runtime_bundle.py \
  --harness /absolute/path/fmst-harness-x86 \
  --bundle /absolute/path/new-bundle
```

This collects the harness, loader and required host libraries. Additional helpers
are caller choices, supplied with repeated `--binary name=/absolute/path` flags.
The bundle retains the harness's existing CLI protocol; it does not retrofit
capabilities into another binary.

## Public source archive

From a Git checkout, maintainers can run:

```sh
python3 tools/package_source.py --output /absolute/path/new-guestweave-source.tar.gz
```

The source packager uses a public-path allowlist in addition to Git ignore rules.
It rejects selected private paths and symlinks, includes actual working-tree
source bytes, and records each hash and mode in SOURCE-MANIFEST.json. Source IDs
bind those bytes, not an assumed clean HEAD. Repeated packaging of identical
inputs produces the same archive hash. A source archive does not include Cargo
vendor, the builder or native dependencies; use `offline.py prepare` for those.

See [support and validation scope](support.md) for the tested configuration, and
[Core integration](integration.md) for application responsibilities.
