"""Fetch the pinned maintained LibAFL into a new directory, or verify an existing one.

Existing directories are never reset, patched or overwritten. Native QEMU and
libvharness dependencies are pinned in this LibAFL's build scripts; offline
preparation exports them separately with tools/offline.py.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from check_libafl_dependency import ROOT, verify


def prepare(destination: Path, source: str | None = None) -> dict:
    metadata_path = ROOT / "dependencies/libafl-qemu.json"
    metadata = json.loads(metadata_path.read_text())
    if destination.exists() or destination.is_symlink():
        return verify(destination, metadata_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".guestweave-dependency-", dir=destination.parent) as tmp:
        checkout = Path(tmp) / "LibAFL"
        subprocess.run(["git", "init", "--quiet", str(checkout)], check=True)
        subprocess.run(["git", "-C", str(checkout), "remote", "add", "origin", metadata["repository"]], check=True)
        subprocess.run(["git", "-C", str(checkout), "fetch", "--depth=1", source or "origin", metadata["commit"]], check=True)
        subprocess.run(["git", "-C", str(checkout), "checkout", "--quiet", "--detach", "FETCH_HEAD"], check=True)
        result = verify(checkout, metadata_path)
        if destination.exists() or destination.is_symlink():
            raise FileExistsError(destination)
        checkout.rename(destination)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, default=ROOT.parent / "lib/LibAFL")
    parser.add_argument("--source", help="optional local Git repository containing the pinned commit")
    args = parser.parse_args()
    try:
        result = prepare(args.checkout.absolute(), args.source)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(json.dumps({"status": "failed", "error": str(error)}, indent=2))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
