# Integrating GuestWeave with Firmenstein

GuestWeave supplies the guest execution layer. Firmenstein Core owns firmware
analysis, planning, intervention generation, process supervision and application
success criteria. Other applications can use the same public framework.

| Interface | GuestWeave | Consumer / Core |
| --- | --- | --- |
| Behavior | Public hook/context and pseudo-file API | Choose and implement target behavior |
| Bindings | Validate manifest, ABI, architecture and loaded-image match | Supply matching ELF evidence and offsets |
| Execution | One `run(RunConfig)` per worker; optional exec launcher | Create, supervise, time out and clean up workers |
| Evidence | Raw trace, load map, ELF identity and exec events | Interpret evidence and decide scenario success |
| Packaging | Harness build and loader/library bundle tool | Supply rootfs, permissions and application helpers |

## Rust integration

Select one architecture feature and use `guestweave::api` to implement behavior.
Link a `StaticManifest` directly or use `Intervention::SharedObject` for an ABI-v4
plugin. Rebuild older plugins and keep the runtime and plugin ABI matched.
The embedded example demonstrates both behavior registration and worker
startup; a separate generation service is not required.

The backend has process-global state. Supervise each invocation as a worker;
observe its exit status and persisted trace even when `run` does not return.
Configure `ExecLauncher` only if worker restart and state handoff are intended.
See the [API](api.md) for the exact restart and environment semantics.

## Existing harness consumers

The `fmst-iib-api`, `fmst-iib-runtime` and `fmst-harness-*` names remain available.
Keep generated plugins, harnesses and their ABI versions matched. Configure the
runtime workspace and `tools/build_runtime_bundle.py` location explicitly instead
of assuming GuestWeave is inside the Core source tree.

`build_runtime_bundle.py` collects a harness's host loader and shared libraries.
Applications can add required helper programs through repeated
`--binary destination=/absolute/source` arguments. GuestWeave does not choose
application helpers or infer capabilities from an unrelated executable.

Build each guest architecture with its own native Linux target directory. Store
framework source identity, dependency pins and the matching consumer version with
execution evidence. A successful framework contract test is separate from a
successful application or firmware scenario.
