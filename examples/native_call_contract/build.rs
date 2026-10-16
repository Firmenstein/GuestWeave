//! Build one freestanding ET_EXEC guest and derive all addresses from it.
//!
//! The resulting bindings deliberately contain both the link-time function
//! address and the module-relative offset.  The runtime must accept the
//! former when it is already executable and resolve the latter using the
//! loaded image base.
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

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=guest.c");
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

    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let object = out.join("probe-guest.o");
    let guest = out.join("probe-guest");
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
            .args(["guest.c", "-o"])
            .arg(&object),
    );
    let rustc = env::var_os("RUSTC").unwrap();
    let sysroot = output(Command::new(&rustc).args(["--print", "sysroot"]));
    let host = env::var("HOST").unwrap();
    let linker = PathBuf::from(sysroot.trim()).join(format!("lib/rustlib/{host}/bin/rust-lld"));
    output(
        Command::new(&linker)
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

    let initial_bytes = fs::read(&guest).unwrap();
    let initial = goblin::elf::Elf::parse(&initial_bytes).unwrap();
    let initial_base = initial
        .program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|p| p.p_vaddr)
        .min()
        .unwrap();
    let initial_probe = initial
        .syms
        .iter()
        .find(|s| initial.strtab.get_at(s.st_name) == Some("probe"))
        .unwrap()
        .st_value;
    let text_address = initial
        .section_headers
        .iter()
        .find(|s| initial.shdr_strtab.get_at(s.sh_name) == Some(".text"))
        .unwrap()
        .sh_addr;
    output(
        Command::new(&linker)
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
            .arg(&object)
            .arg(format!("--section-start=.text={text_address:#x}"))
            .arg(format!(
                "--section-start=.native_alias={:#x}",
                initial_base + initial_probe
            )),
    );
    let bytes = fs::read(&guest).unwrap();
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    assert_eq!(elf.header.e_type, goblin::elf::header::ET_EXEC);
    let base = elf
        .program_headers
        .iter()
        .filter(|p| p.p_type == goblin::elf::program_header::PT_LOAD)
        .map(|p| p.p_vaddr)
        .min()
        .expect("guest has a PT_LOAD segment");
    let symbol = elf
        .syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some("probe"))
        .expect("guest exports probe");
    let va = symbol.st_value;
    assert_eq!((base, va), (initial_base, initial_probe));
    let pic_va = elf
        .syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some("pic_probe"))
        .unwrap()
        .st_value;
    let offset = va.checked_sub(base).expect("probe is above image base");
    let executable = |addr| {
        elf.program_headers.iter().any(|p| {
            p.p_type == goblin::elf::program_header::PT_LOAD
                && p.p_flags & goblin::elf::program_header::PF_X != 0
                && addr >= p.p_vaddr
                && addr < p.p_vaddr.saturating_add(p.p_memsz)
        })
    };
    assert!(executable(va), "probe must be executable");
    assert!(executable(va + base), "second candidate must be executable");
    assert_ne!(va, offset, "fixture must distinguish VA and module offset");
    assert!(
        !executable(offset),
        "module offset must not itself be executable"
    );
    fs::write(
        out.join("bindings.rs"),
        format!(
            "const ELF_MAP_BASE: u64 = {base};\nconst PROBE_LINK_VA: u64 = {va};\nconst PROBE_OFFSET: u64 = {offset};\nconst PIC_LINK_VA: u64 = {pic_va};\n"
        ),
    )
    .unwrap();
    fs::write(
        out.join("elf-identity.txt"),
        format!(
            "machine={}\ntype=ET_EXEC\nminimum_PT_LOAD_vaddr={base:#x}\nprobe_symbol_vaddr={va:#x}\nprobe_manifest_offset={offset:#x}\nmanifest_offset_is_executable=false\n",
            elf.header.e_machine
        ),
    )
    .unwrap();
    println!("cargo:rustc-env=PROBE_GUEST={}", guest.display());
    println!("cargo:rustc-env=GUESTWEAVE_GUEST_ARCH={trace_arch}");
}
