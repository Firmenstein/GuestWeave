//! Build a tiny, freestanding guest and derive bindings from that exact ELF.
use std::{env, fs, path::PathBuf, process::Command};

fn output(command: &mut Command) -> String {
    let result = command.output().expect("start build tool");
    assert!(
        result.status.success(),
        "{command:?}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).expect("tool output is UTF-8")
}

fn build(source: &str, name: &str, prefix: &str, target: &str, emulation: &str, flags: &[&str]) {
    println!("cargo:rerun-if-changed={source}");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let object = out.join(format!("{name}.o"));
    let guest = out.join(name);
    output(
        Command::new("clang")
            .args([
                "-O0",
                "-c",
                "-nostdlib",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-stack-protector",
                "-fno-pic",
            ])
            .arg(format!("--target={target}"))
            .args(flags)
            .args([source, "-o"])
            .arg(&object),
    );
    let rustc = env::var_os("RUSTC").unwrap();
    let sysroot = output(Command::new(&rustc).args(["--print", "sysroot"]));
    let host = env::var("HOST").unwrap();
    let linker = PathBuf::from(sysroot.trim()).join(format!("lib/rustlib/{host}/bin/rust-lld"));
    output(
        Command::new(linker)
            .args([
                "-flavor",
                "gnu",
                "-m",
                emulation,
                "-static",
                "--entry=_start",
                "-o",
            ])
            .arg(&guest)
            .arg(&object),
    );
    let bytes = fs::read(&guest).unwrap();
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    let base = elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|p| p.p_vaddr)
        .min()
        .unwrap();
    let offset = |name| {
        elf.syms
            .iter()
            .find(|s| elf.strtab.get_at(s.st_name) == Some(name))
            .unwrap()
            .st_value
            - base
    };
    fs::write(
        out.join(format!("{prefix}-bindings.rs")),
        format!(
            "const CALL_OFFSET: u64 = {};\nconst RESUME_OFFSET: u64 = {};\n",
            offset(&format!("{prefix}_call")),
            offset(&format!("{prefix}_resume")),
        ),
    )
    .unwrap();
    println!(
        "cargo:rustc-env={}_GUEST={}",
        prefix.to_uppercase(),
        guest.display()
    );
}

fn main() {
    println!("cargo:rerun-if-changed=guest_abi.h");
    let selected: Vec<_> = ["x86_64", "arm", "mips", "mipsbe"]
        .into_iter()
        .filter(|arch| env::var_os(format!("CARGO_FEATURE_{}", arch.to_uppercase())).is_some())
        .collect();
    assert_eq!(
        selected.len(),
        1,
        "select exactly one guest architecture feature"
    );
    let (target, emulation, flags, trace_arch): (&str, &str, &[&str], &str) = match selected[0] {
        "arm" => (
            "armv7-linux-gnueabi",
            "armelf_linux_eabi",
            &["-marm"],
            "arm",
        ),
        "mips" => (
            "mipsel-linux-gnu",
            "elf32ltsmip",
            &["-mno-abicalls", "-G0"],
            "mipsel",
        ),
        "mipsbe" => (
            "mips-linux-gnu",
            "elf32btsmip",
            &["-mno-abicalls", "-G0"],
            "mipsbe",
        ),
        _ => ("x86_64-linux-gnu", "elf_x86_64", &[], "x86_64"),
    };
    println!("cargo:rustc-env=GUESTWEAVE_GUEST_ARCH={trace_arch}");
    build("guest.c", "demo-guest", "demo", target, emulation, flags);
    build(
        "exec_guest.c",
        "exec-guest",
        "exec",
        target,
        emulation,
        flags,
    );
}
