"""Read-only verification of the maintained LibAFL snapshot and integrated patch."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def git(checkout: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(checkout), *args], text=True).strip()


def verify_source(checkout: Path, metadata_path: Path) -> dict:
    """Validate critical source bytes, including in a Git-free offline export."""
    metadata = json.loads(metadata_path.read_text())
    if metadata.get("schema_version") != 2 or metadata.get("patch_status") != "integrated":
        raise ValueError("expected schema 2 with an integrated LibAFL patch")
    patch = metadata_path.parent.parent / metadata["patch_file"]
    if hashlib.sha256(patch.read_bytes()).hexdigest() != metadata["patch_sha256"]:
        raise ValueError("documented LibAFL patch hash differs")
    for name, expected in metadata["source_sha256"].items():
        path = checkout / name
        if not path.resolve().is_relative_to(checkout.resolve()):
            raise ValueError("source hash path escapes checkout")
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f"maintained source differs: {name}")
    text = (checkout / "Cargo.toml").read_text()
    match = re.search(r'(?ms)^\[workspace\.package\]\s*.*?^version\s*=\s*"([^"]+)"', text)
    if not match or match.group(1) != metadata["version"]:
        raise ValueError("LibAFL workspace version differs")
    runtime = json.loads((metadata_path.parent / "linux-runtime.json").read_text())
    for name, file, url_constant, rev_constant in (
        ("qemu", "crates/libafl_qemu/libafl_qemu_build/src/build.rs", "LIBAFL_QEMU_GIT_URL", "LIBAFL_QEMU_GIT_REV"),
        ("libvharness", "crates/libafl_qemu/libvharness_sys/build.rs", "LIBVHARNESS_URL", "LIBVHARNESS_COMMIT"),
    ):
        source = (checkout / file).read_text()
        for constant, field in ((url_constant, "repository"), (rev_constant, "commit")):
            match = re.search(r'\bconst\s+' + constant + r'\s*:\s*&str\s*=\s*"([^"]+)"', source)
            if not match or match.group(1) != runtime["sources"][name][field]:
                raise ValueError(f"{name} {field} disagrees with LibAFL build script")
    return metadata


def verify(checkout: Path, metadata_path: Path) -> dict:
    checkout = checkout.resolve(strict=True)
    metadata = verify_source(checkout, metadata_path)
    if Path(git(checkout, "rev-parse", "--show-toplevel")).resolve() != checkout:
        raise ValueError("dependency must have its own Git repository")
    commit = git(checkout, "rev-parse", "HEAD")
    if commit != metadata["commit"]:
        raise ValueError(f"LibAFL commit differs: expected {metadata['commit']}, got {commit}")
    if git(checkout, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("LibAFL checkout has uncommitted files; preserve them and use a clean checkout")
    return {"status": "passed", "commit": commit, "version": metadata["version"],
            "repository": metadata["repository"], "patch_status": "integrated",
            "patch_sha256": metadata["patch_sha256"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, default=ROOT.parent / "lib/LibAFL")
    parser.add_argument("--metadata", type=Path, default=ROOT / "dependencies/libafl-qemu.json")
    args = parser.parse_args()
    try:
        result = verify(args.checkout, args.metadata.resolve(strict=True))
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
