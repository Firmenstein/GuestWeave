"""Build the Linux host-runtime bundle used by the firmware container."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from pathlib import Path
from collections.abc import Mapping

_LOADER_RE = re.compile(r"Requesting program interpreter:\s*([^\]]+)")
_LDD_ARROW_RE = re.compile(r"^\s*\S+\s+=>\s+(/\S+)\s+")
_LDD_DIRECT_RE = re.compile(r"^\s*(/\S+)\s+")


def _stdout(command: list[str]) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def _interpreter_path(binary: Path) -> str:
    match = _LOADER_RE.search(_stdout(["readelf", "-l", str(binary)]))
    if match is None:
        raise RuntimeError(f"cannot locate ELF interpreter for {binary}")
    return match.group(1)


def _loader(binary: Path) -> Path:
    return Path(_interpreter_path(binary)).resolve(strict=True)


def _dependencies(binary: Path, loader: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for line in _stdout(["ldd", str(binary)]).splitlines():
        if "=> not found" in line:
            raise RuntimeError(f"missing runtime dependency for {binary}: {line.strip()}")
        match = _LDD_ARROW_RE.match(line) or _LDD_DIRECT_RE.match(line)
        if match is None:
            continue
        path = Path(match.group(1))
        if not path.is_file() or path.resolve() == loader:
            continue
        resolved = path.resolve()
        existing = found.get(path.name)
        if existing is not None and existing != resolved:
            raise RuntimeError(f"runtime library basename collision: {path.name}")
        found[path.name] = resolved
    return found


def _parse_binary(value: str) -> tuple[str, Path]:
    """Parse one explicit ``destination=source`` host binary declaration."""
    name, separator, source = value.partition("=")
    if (not separator or not name or not source or Path(name).name != name
            or not Path(source).is_absolute()):
        raise argparse.ArgumentTypeError(
            "--binary must use a simple destination name and a source path: name=/path"
        )
    return name, Path(source)


def build_bundle(
    harness: Path,
    bundle: Path,
    *,
    binaries: Mapping[str, Path] | None = None,
) -> None:
    """Build a host runtime bundle.

    The framework owns only the harness and its ELF runtime dependencies.
    Consumers that need controller-owned host helpers must pass them explicitly;
    no application command or probe is inferred here.
    """
    bundle.mkdir(parents=True, exist_ok=True)
    library_dir = bundle / "lib"
    library_dir.mkdir(parents=True, exist_ok=True)
    loader = _loader(harness)
    shutil.copy2(loader, bundle / "ld.so")
    # The host harness may be built for Linux/ARM64 or Linux/amd64.  The
    # child host exec must expose the copied loader at the exact PT_INTERP
    # path embedded in that harness; a fixed ARM64 destination breaks the
    # otherwise supported amd64 builder.
    (bundle / "host-interpreter.path").write_text(
        f"{_interpreter_path(harness)}\n",
        encoding="utf-8",
    )
    declared = {name: Path(path).resolve(strict=True) for name, path in (binaries or {}).items()}
    if "harness" in declared:
        raise ValueError("the destination name 'harness' is reserved")
    executable_paths = [harness, *declared.values()]
    dependencies: dict[str, Path] = {}
    for binary in executable_paths:
        if _loader(binary) != loader:
            raise RuntimeError(f"runtime executable uses a different ELF loader: {binary}")
        for name, dependency in _dependencies(binary, loader).items():
            existing = dependencies.get(name)
            if existing is not None and existing != dependency:
                raise RuntimeError(f"runtime library basename collision: {name}")
            dependencies[name] = dependency
    shutil.copy2(harness, bundle / harness.name)
    for name, binary in declared.items():
        shutil.copy2(binary, bundle / name)
    for name, dependency in sorted(dependencies.items()):
        shutil.copy2(dependency, library_dir / name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--harness", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument(
        "--binary", action="append", default=[], type=_parse_binary,
        metavar="NAME=PATH",
        help="explicitly include a host executable under NAME (repeatable)",
    )
    args = parser.parse_args()
    build_bundle(
        args.harness.resolve(strict=True), args.bundle.resolve(),
        binaries=dict(args.binary),
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
