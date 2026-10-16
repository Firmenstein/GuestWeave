"""Create a reproducible source archive from this checkout, excluding Git-ignored outputs.

The archive contains GuestWeave only. Its pinned LibAFL checkout is prepared
separately as documented in docs/build.md; no Firmenstein or local build cache
is distributed. Working-tree bytes, including pending source edits, are bound
by the embedded SOURCE-MANIFEST.json, not presented as the Git HEAD contents.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import uuid


PUBLIC_FILES = {
    ".gitignore", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml",
    "README.md", "LICENSE", "THIRD_PARTY.md",
    "docs/api.md", "docs/abi.md", "docs/interventions.md", "docs/build.md",
    "docs/support.md", "docs/integration.md",
    "assets/brand/logo.svg", "assets/brand/logo-dark.svg",
    "assets/brand/logo.png", "assets/brand/logo-dark.png",
}
PUBLIC_TREES = {"src", "fmst-iib-api", "fmst-iib-runtime", "harness-arm",
                "harness-mips", "harness-x86", "examples", "tools", "dependencies",
                "patches", "docker", "skills"}
PRIVATE_PARTS = {".git", ".codex", ".claude", ".agents", ".vscode", ".idea",
                 "target", "tmp", "dist", "__pycache__", "AGENTS.md"}


def public_path(name: str) -> bool:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or any(p in PRIVATE_PARTS for p in path.parts):
        return False
    if any(p.startswith(".") for p in path.parts) and name != ".gitignore":
        return False
    if path.name.lower() == "ida.reg" or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx", ".hexlic", ".log", ".pyc", ".pyo"}:
        return False
    return name in PUBLIC_FILES or bool(path.parts and path.parts[0] in PUBLIC_TREES)


def package(source: Path, output: Path) -> dict[str, object]:
    source = source.resolve(strict=True)
    output = output.resolve()
    if output.exists():
        raise FileExistsError(output)
    names = subprocess.run(
        ["git", "-C", str(source), "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "."],
        check=True, capture_output=True,
    ).stdout.split(b"\0")
    files = {}
    contents = {}
    for raw in sorted(set(names) - {b""}):
        name = os.fsdecode(raw)
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"invalid source path: {name}")
        path = source / name
        if not path.exists() and not path.is_symlink():
            continue  # A tracked file deleted in the current working tree.
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"source must be a regular file, not a link: {name}")
        if not public_path(name):
            raise ValueError(f"file is outside the public source policy: {name}")
        content = path.read_bytes()
        mode = 0o755 if metadata.st_mode & 0o111 else 0o644
        contents[name] = content
        files[name] = {"sha256": hashlib.sha256(content).hexdigest(), "size": len(content), "mode": mode}
    required = {"Cargo.toml", "Cargo.lock", "README.md", "LICENSE", "docs/api.md",
        "docs/build.md", "skills/intervention-engineering/SKILL.md", "dependencies/libafl-qemu.json",
        "dependencies/linux-runtime.json", "tools/offline.py", "tools/prepare_dependencies.py", "docker/builder/Dockerfile"}
    if required - files.keys():
        raise ValueError(f"missing source files: {sorted(required - files.keys())}")
    source_id = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    version = re.search(r'^version\s*=\s*"([0-9][0-9A-Za-z.+-]*)"',
        contents["Cargo.toml"].decode(), re.M).group(1)
    prefix = f"guestweave-{version}"
    receipt = {"schema_version": 1, "package": "guestweave", "version": version,
        "source_id": source_id, "files": files,
        "dependency": json.loads(contents["dependencies/libafl-qemu.json"])}
    contents["SOURCE-MANIFEST.json"] = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_name(output.name + ".partial-" + uuid.uuid4().hex)
    with partial.open("xb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, content in sorted(contents.items()):
                info = tarfile.TarInfo(f"{prefix}/{name}")
                info.size = len(content)
                info.mode = files[name]["mode"] if name in files else 0o644
                archive.addfile(info, io.BytesIO(content))
    # Never overwrite another delivery, including one created during packaging.
    os.link(partial, output)
    partial.unlink()
    return {"archive": str(output), "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "source_id": source_id, "source_files": len(files), "prefix": prefix}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(package(Path(__file__).resolve().parents[1], args.output), indent=2))


if __name__ == "__main__":
    main()
