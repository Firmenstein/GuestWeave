fn main() {
    println!("cargo:rerun-if-changed=src/diagnostic_sink.c");
    cc::Build::new()
        .file("src/diagnostic_sink.c")
        .compile("fmst_diagnostic_sink");
    // QEMU's generated 128-bit atomic helpers require libatomic on x86_64
    // hosts. Keep the dependency at the final Rust link boundary so lld does
    // not drop it before the static QEMU archive is processed.
    println!("cargo:rustc-link-lib=atomic");
}
