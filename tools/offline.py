"""Prepare, verify and consume a pinned Linux offline source delivery.

Preparation may fetch source objects and Cargo crates. Consumption always uses
Docker --network=none, a verified image ID and a new native build volume.
Existing checkouts are only read with git archive; working-tree edits and build
caches are never copied into the delivery. See docs/build.md.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid

from package_source import package
from check_libafl_dependency import verify_source

ROOT = Path(__file__).resolve().parents[1]
ARCHES = ("x86_64", "arm", "mips", "mipsbe")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def output(command: list[str], **kwargs) -> str:
    return subprocess.check_output(command, text=True, **kwargs).strip()


def inventory(root: Path) -> dict:
    result = {}
    for path in sorted(root.rglob("*")):
        name = path.relative_to(root).as_posix()
        if name == "DELIVERY.json":
            continue
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            # Keep symlinks as links; reject any escape from this delivery.
            if not path.resolve().is_relative_to(root.resolve()):
                raise ValueError(f"symlink escapes delivery: {name}")
            result[name] = {"link": os.readlink(path)}
        elif stat.S_ISREG(mode):
            result[name] = {"sha256": sha256(path), "size": path.stat().st_size,
                            "executable": bool(mode & 0o111)}
        elif not stat.S_ISDIR(mode):
            raise ValueError(f"unsupported delivery entry: {name}")
    return result


def identity(files: dict) -> str:
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify(delivery: Path) -> dict:
    receipt = json.loads((delivery / "DELIVERY.json").read_text())
    if receipt.get("schema_version") != 1:
        raise ValueError("unsupported offline delivery schema")
    actual = inventory(delivery)
    expected = receipt["files"]
    if actual != expected:
        changed = sorted(k for k in actual.keys() | expected.keys() if actual.get(k) != expected.get(k))
        raise ValueError("delivery files differ: " + ", ".join(changed))
    if identity({k: v for k, v in receipt.items() if k != "delivery_id"}) != receipt["delivery_id"]:
        raise ValueError("delivery identity differs")
    return receipt


def extract(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    destination = destination.resolve()
    with tarfile.open(archive) as stream:
        # Use explicit extraction, including on the host's Python 3.9. Never
        # follow an archive link outside the destination or restore devices.
        for member in stream:
            name = PurePosixPath(member.name)
            path = destination / name
            if name.is_absolute() or ".." in name.parts or not path.resolve().is_relative_to(destination):
                raise ValueError(f"archive path escapes destination: {member.name}")
            path.parent.mkdir(parents=True, exist_ok=True)
            if member.isdir():
                path.mkdir(exist_ok=True)
            elif member.issym():
                if Path(member.linkname).is_absolute() or not (path.parent / member.linkname).resolve().is_relative_to(destination):
                    raise ValueError(f"archive link escapes destination: {member.name}")
                path.symlink_to(member.linkname)
            elif member.isfile():
                with stream.extractfile(member) as source, path.open("xb") as target:
                    shutil.copyfileobj(source, target)
                path.chmod(member.mode & 0o777)
            else:
                raise ValueError(f"unsupported archive entry: {member.name}")


def export_git(name: str, spec: dict, checkout: Path | None, destination: Path, scratch: Path) -> dict:
    if checkout is None:
        checkout = scratch / name
        subprocess.run(["git", "init", "--quiet", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "fetch", "--depth=1", spec["repository"], spec["commit"]], check=True)
    commit = output(["git", "-C", str(checkout), "rev-parse", spec["commit"] + "^{commit}"])
    if commit != spec["commit"]:
        raise ValueError(f"{name}: source commit differs")
    # Pinned QEMU also has legacy gitlinks not present in .gitmodules: meson
    # is supplied as a tracked wheel; dtc/UI/ROM/tests are disabled in usermode.
    tree = output(["git", "-C", str(checkout), "ls-tree", "-r", commit])
    gitlinks = [line.split("\t", 1)[1] for line in tree.splitlines() if line.startswith("160000 ")]
    unused = lambda p: p in {"dtc", "meson", "ui/keycodemapdb"} or p.startswith(("roms/", "tests/"))
    if gitlinks and (name != "qemu" or any(not unused(p) for p in gitlinks)):
        raise ValueError(f"{name}: unhandled source submodules: {gitlinks}")
    raw_tar = scratch / (name + ".tar")
    subprocess.run(["git", "-C", str(checkout), "archive", "--format=tar", "--output=" + str(raw_tar), commit], check=True)
    with raw_tar.open("rb") as source, destination.open("xb") as target:
        with gzip.GzipFile(filename="", mode="wb", fileobj=target, mtime=0) as compressed:
            shutil.copyfileobj(source, compressed)
    return {**spec, "archive_sha256": sha256(destination), "omitted_gitlinks": gitlinks,
            "input": "git archive of pinned commit; working tree ignored"}


def docker_run(image: str, mounts: list[str], command: list[str], *, network: str, log: Path) -> int:
    name = "guestweave-offline-" + uuid.uuid4().hex[:12]
    args = ["docker", "run", "--rm", "--pull=never", "--name", name, "--network", network,
            "--mount", "type=volume,dst=/build,volume-nocopy"]
    for mount in mounts:
        args += ["--mount", mount]
    args += [image, *command]
    with log.open("xb") as stream:
        try:
            return subprocess.run(args, stdout=stream, stderr=subprocess.STDOUT).returncode
        finally:
            # Also remove this invocation's anonymous volume after interruption.
            subprocess.run(["docker", "rm", "--force", "--volumes", name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def prepare(args) -> dict:
    destination = args.output.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    metadata = json.loads((ROOT / "dependencies/libafl-qemu.json").read_text())
    runtime = json.loads((ROOT / "dependencies/linux-runtime.json").read_text())
    image = json.loads(output(["docker", "image", "inspect", args.builder_image]))[0]
    if image["Os"] != "linux":
        raise ValueError("builder must be a Linux image")
    sources = destination / "sources"
    sources.mkdir()
    workspace = destination / "workspace"
    workspace.mkdir()
    source_package = package(ROOT, sources / "guestweave.tar.gz")
    extract(sources / "guestweave.tar.gz", workspace)
    project = workspace / "GuestWeave"
    (workspace / source_package["prefix"]).rename(project)
    source_specs = {"libafl": {k: metadata[k] for k in ("repository", "commit")}, **runtime["sources"]}
    records = {}
    with tempfile.TemporaryDirectory(prefix="guestweave-source-") as temporary:
        scratch = Path(temporary)
        for name, spec in source_specs.items():
            records[name] = export_git(name, spec, getattr(args, name + "_source"), sources / (name + ".tar.gz"), scratch)
        libafl = workspace / "lib/LibAFL"
        extract(sources / "libafl.tar.gz", libafl)
        verify_source(libafl, project / "dependencies/libafl-qemu.json")
        records["libafl"]["patch_status"] = "integrated"
        records["libafl"]["patch_sha256"] = metadata["patch_sha256"]
    mounts = [f"type=bind,src={destination},dst=/delivery"]
    if args.registry_cache:
        mounts.append(f"type=bind,src={args.registry_cache.resolve(strict=True)},dst=/registry-seed,readonly")
    vendor_command = ["python3", "/delivery/workspace/GuestWeave/tools/offline.py", "_vendor"]
    if args.prepare_offline:
        vendor_command.append("--offline")
    code = docker_run(image["Id"], mounts, vendor_command,
                      network="none" if args.prepare_offline else "bridge", log=destination / "prepare.log")
    if code:
        raise RuntimeError(f"Cargo source preparation failed ({code}); see {destination / 'prepare.log'}")
    builder = {"image_id": image["Id"], "os": image["Os"], "architecture": image["Architecture"],
               "tools": json.loads((destination / "builder-tools.json").read_text())}
    if not builder["tools"]["rustc"].startswith("rustc " + runtime["rust_version"] + " "):
        raise ValueError("builder Rust version differs from runtime dependency contract")
    if args.export_builder:
        subprocess.run(["docker", "image", "save", "--output", str(destination / "builder-image.tar"), image["Id"]], check=True)
        builder["archive"] = "builder-image.tar"
    files = inventory(destination)
    receipt = {"schema_version": 1, "files": files,
               "guestweave_source_id": source_package["source_id"], "sources": records,
               "builder": builder, "architectures": list(ARCHES), "scope": runtime["scope"]}
    receipt["delivery_id"] = identity(receipt)
    write_json(destination / "DELIVERY.json", receipt)
    verify(destination)
    return {"status": "prepared", "delivery": str(destination), "delivery_id": receipt["delivery_id"],
            "image_id": image["Id"], "builder_exported": args.export_builder}


def vendor(offline: bool) -> None:
    delivery = Path("/delivery")
    env = os.environ.copy()
    env["CARGO_HOME"] = "/build/cargo-home"
    env["RUSTUP_TOOLCHAIN"] = "1.98.0"
    env["CARGO_NET_OFFLINE"] = "true" if offline else "false"
    Path(env["CARGO_HOME"]).mkdir()
    if Path("/registry-seed").exists():
        shutil.copytree("/registry-seed", Path(env["CARGO_HOME"]) / "registry")
    project = delivery / "workspace/GuestWeave"
    command = ["cargo", "vendor", "--locked", "--versioned-dirs", "--manifest-path", str(project / "Cargo.toml")]
    for example in ("embedded", "native_call_contract"):
        command += ["--sync", str(project / "examples" / example / "Cargo.toml")]
    command.append(str(delivery / "vendor"))
    config = subprocess.check_output(command, env=env, text=True)
    config_dir = delivery / "workspace/.cargo"
    config_dir.mkdir()
    (config_dir / "config.toml").write_text(config + "\n[net]\noffline = true\n")
    tools = {name: output(cmd, env=env) for name, cmd in {
        "rustc": ["rustc", "--version"], "cargo": ["cargo", "--version"],
        "clang": ["clang", "--version"], "cmake": ["cmake", "--version"],
        "python": ["python3", "--version"], "packages": ["dpkg-query", "-W"]}.items()}
    write_json(delivery / "builder-tools.json", tools)


def consume(args) -> dict:
    delivery = args.delivery.resolve(strict=True)
    receipt = verify(delivery)
    image_id = receipt["builder"]["image_id"]
    try:
        image = json.loads(output(["docker", "image", "inspect", image_id], stderr=subprocess.DEVNULL))[0]
    except subprocess.CalledProcessError as error:
        raise ValueError("builder image missing; load the recorded builder-image.tar with docker load") from error
    if image["Id"] != image_id or image["Architecture"] != receipt["builder"]["architecture"]:
        raise ValueError("builder identity differs")
    evidence = args.output.resolve()
    if evidence.is_relative_to(delivery):
        raise ValueError("build output must be outside the immutable delivery")
    evidence.mkdir(parents=True, exist_ok=False)
    command = ["python3", "/delivery/workspace/GuestWeave/tools/offline.py", "_build",
               "--arch", args.arch, "--suite", args.suite, "--jobs", str(args.jobs)]
    start = time.monotonic()
    result = {"delivery_id": receipt["delivery_id"], "guestweave_source_id": receipt["guestweave_source_id"],
              "builder_image_id": image_id, "network": "none", "fresh_native_volume": True,
              "arch": args.arch, "suite": args.suite, "jobs": args.jobs, "command": command,
              "status": "running"}
    write_json(evidence / "receipt.json", result)
    try:
        code = docker_run(image_id, [f"type=bind,src={delivery},dst=/delivery,readonly",
                                    f"type=bind,src={evidence},dst=/evidence"], command,
                          network="none", log=evidence / "build.log")
        result.update(returncode=code, status="passed" if code == 0 else "failed")
    except BaseException:
        result["status"] = "interrupted"
        raise
    finally:
        result["elapsed_seconds"] = round(time.monotonic() - start, 3)
        write_json(evidence / "receipt.json", result)
    return result


def build(args) -> None:
    delivery, work, evidence = Path("/delivery"), Path("/build"), Path("/evidence")
    if any(work.iterdir()):
        raise ValueError("build volume must be empty")
    env = os.environ.copy()
    env.update(CARGO_HOME=str(work / "cargo-home"), CARGO_TARGET_DIR=str(work / "target"),
               CARGO_NET_OFFLINE="true", RUSTUP_TOOLCHAIN="1.98.0", PIP_NO_INDEX="1",
               LIBAFL_QEMU_DIR=str(work / "qemu"), VHARNESS_DIR=str(work / "libvharness"),
               GUESTWEAVE_TEST_OUTPUT=str(evidence / "guest"))
    for name in ("LIBAFL_QEMU_CLONE_DIR", "LIBAFL_QEMU_GIT_URL", "LIBAFL_QEMU_GIT_REV", "LIBAFL_QEMU_NO_BUILD"):
        env.pop(name, None)
    Path(env["CARGO_HOME"]).mkdir()
    for name in ("qemu", "libvharness"):
        extract(delivery / "sources" / (name + ".tar.gz"), work / name)
    project = delivery / "workspace/GuestWeave"
    command = ["cargo", "test", "--frozen", "--release", "--jobs", str(args.jobs)]
    if args.suite in ("native-call", "embedded"):
        example = "native_call_contract" if args.suite == "native-call" else "embedded"
        command += ["--manifest-path", str(project / "examples" / example / "Cargo.toml"),
                    "--no-default-features", "--features", args.arch]
    elif args.suite == "runtime-unit":
        command += ["-p", "fmst-iib-runtime", "--lib", "--no-default-features", "--features", args.arch]
    elif args.suite == "api":
        command += ["-p", "fmst-iib-api", "--features", "mock"]
    else:
        command[1] = "build"
        package_name = {"arm": "arm", "mips": "mips", "mipsbe": "mips", "x86_64": "x86"}[args.arch]
        command += ["-p", "fmst-harness-" + package_name]
        if args.arch == "mipsbe":
            command += ["--no-default-features", "--features", "big-endian"]
    if command[1] == "test":
        command += ["--", "--nocapture"]
    write_json(evidence / "build-inputs.json", {"command": command, "environment": {
        k: env[k] for k in ("CARGO_HOME", "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "RUSTUP_TOOLCHAIN",
                           "LIBAFL_QEMU_DIR", "VHARNESS_DIR", "PIP_NO_INDEX")},
        "initial_cargo_home_empty": not any(Path(env["CARGO_HOME"]).iterdir()),
        "initial_target_absent": not Path(env["CARGO_TARGET_DIR"]).exists(),
        "qemu_build_absent": not (work / "qemu/build").exists()})
    subprocess.run(command, cwd=project, env=env, check=True)
    if args.suite == "harness":
        subprocess.run(["python3", str(project / "tools/build_runtime_bundle.py"), "--harness",
                        str(work / "target/release" / ("fmst-harness-" + package_name)),
                        "--bundle", str(evidence / "runtime-bundle")], check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest="action", required=True)
    prep = subs.add_parser("prepare", help="create a new delivery; may use network")
    prep.add_argument("--output", type=Path, required=True)
    prep.add_argument("--builder-image", default="guestweave/builder:rust1.98-bookworm")
    for name in ("libafl", "qemu", "libvharness"):
        prep.add_argument("--" + name + "-source", type=Path, help="read pinned commit from this existing Git repository")
    prep.add_argument("--registry-cache", type=Path, help="optional Cargo registry directory used only during preparation")
    prep.add_argument("--prepare-offline", action="store_true", help="disable vendor preparation network (all Git sources must also be supplied)")
    prep.add_argument("--export-builder", action="store_true", help="include docker-save image for transfer to an offline host")
    check = subs.add_parser("verify")
    check.add_argument("--delivery", type=Path, required=True)
    for name in ("run", "_build"):
        run = subs.add_parser(name)
        if name == "run":
            run.add_argument("--delivery", type=Path, required=True)
            run.add_argument("--output", type=Path, required=True)
        run.add_argument("--arch", choices=ARCHES, required=True)
        run.add_argument("--suite", choices=("native-call", "embedded", "runtime-unit", "api", "harness"), default="native-call")
        run.add_argument("--jobs", type=int, default=4)
    vendor_parser = subs.add_parser("_vendor")
    vendor_parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            if args.prepare_offline and any(getattr(args, name + "_source") is None for name in ("libafl", "qemu", "libvharness")):
                raise ValueError("--prepare-offline requires all three --*-source repositories")
            result = prepare(args)
        elif args.action == "verify":
            receipt = verify(args.delivery)
            result = {"status": "verified", "delivery_id": receipt["delivery_id"]}
        elif args.action == "run":
            if args.jobs < 1:
                raise ValueError("--jobs must be positive")
            result = consume(args)
        elif args.action == "_vendor":
            vendor(args.offline)
            return 0
        else:
            build(args)
            return 0
        print(json.dumps(result, indent=2))
        return 0 if result.get("status") != "failed" else 1
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
