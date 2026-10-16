# Third-party sources

GuestWeave's own source is Apache-2.0. Dependencies keep their original license
texts, copyright notices and file-specific terms. A combined runtime includes
code with additional licensing terms; GuestWeave's license does not replace them.

| Dependency | Upstream baseline | Maintained source | Local runtime change |
| --- | --- | --- | --- |
| LibAFL | 0.16.1, `92ad89454765440c7c03b87b11d5dbde753f9633` | [Firmenstein/LibAFL](https://github.com/Firmenstein/LibAFL) | Byte-preserving QEMU argv API; native dependency URL/revision pins |
| QEMU LibAFL bridge | `d7a6067ffc94fbb4caad409d390e099630b71941` | [Firmenstein/qemu-libafl-bridge](https://github.com/Firmenstein/qemu-libafl-bridge) | None in the initial snapshot |
| libvharness | `9a316966ce7aa4bd9f733491511e6ac4be6dd980` | [Firmenstein/libvharness](https://github.com/Firmenstein/libvharness) | None in the initial snapshot |

Current maintained commits are authoritative in
[`libafl-qemu.json`](dependencies/libafl-qemu.json) and
[`linux-runtime.json`](dependencies/linux-runtime.json). Each dependency repository
includes `UPSTREAM.md`, the original README and original license files.

LibAFL's workspace license is `MIT OR Apache-2.0`. QEMU as a whole uses GPLv2,
with additional file/component-specific notices; the bridge's upstream README
also describes its additions. libvharness includes its upstream MIT-style LICENSE
unchanged. Consult those source files for their precise terms.

The LibAFL patch in `patches/` documents the byte-argument extension. It is already
part of the maintained source and must not be applied a second time. Cargo.lock
pins registry dependencies; complete offline deliveries retain their vendored
source and license files. QEMU's tracked Python wheels are retained for its build.

Firmware images, Core-specific extraction tools, runtime traces and user datasets
are not dependencies distributed in this repository.
