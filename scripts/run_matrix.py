#!/usr/bin/env python3
"""Runs the HkdfGuard interop matrix on this host: builds every driver, has each producer write a
release (pipeline-encrypted secrets plus a key file wrapped by the native hkdfguard tool), then has
every consumer read every release. Prints a producer x consumer grid and exits non-zero if any cell
fails.

Standard library only, so it runs before any driver's dependencies are installed:

    python scripts/run_matrix.py                 # build, then run everything
    python scripts/run_matrix.py --skip-build    # reuse the last build
    python scripts/run_matrix.py --producers go --consumers dotnet,java

The service's KEK must already be provisioned on this host (see the README).
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVERS = ROOT / "drivers"
FIXTURES = ROOT / "fixtures" / "secrets.json"
DEFAULT_SERVICE = "com.hkdfguard.integration.test.221"  # the test KEK every port's provisioning script creates
PRODUCERS = ["go", "node", "python"]
CONSUMERS = ["dotnet", "go", "java", "node", "python"]
WINDOWS = sys.platform == "win32"


@dataclass
class Cell:
    ok: bool
    summary: str
    output: str


def tool(name: str) -> str:
    """The full path of a command on PATH (npm and mvnw are .cmd scripts on Windows)."""
    found = shutil.which(name)
    if found is None:
        sys.exit(f"{name} is not on PATH")
    return found


def java() -> str:
    home = os.environ.get("JAVA_HOME")
    return str(Path(home, "bin", "java")) if home else tool("java")


def default_cli() -> str:
    if WINDOWS:
        return r"C:\Program Files\HkdfGuard\v1\hkdfguard.exe"
    return shutil.which("hkdfguard") or "/usr/bin/hkdfguard"


def run(command: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")


def build(repos: Path, drivers: set[str]) -> None:
    """Builds each driver against the sibling checkouts in `repos`."""
    mvnw = repos / "hkdfguard-java" / ("mvnw.cmd" if WINDOWS else "mvnw")
    steps: dict[str, list[tuple[list[str], Path]]] = {
        "go": [([tool("go"), "build", "-o", str(DRIVERS / "go" / "bin" / ("interop.exe" if WINDOWS else "interop")), "."], DRIVERS / "go")],
        "node": [
            # A fresh checkout needs its workspace installed; an existing one is left as it is.
            *([] if (repos / "hkdfguard-node" / "node_modules").is_dir() else [([tool("npm"), "ci", "--no-audit", "--no-fund"], repos / "hkdfguard-node")]),
            ([tool("npm"), "run", "build"], repos / "hkdfguard-node"),
            ([tool("npm"), "install", "--no-audit", "--no-fund"], DRIVERS / "node"),
        ],
        "python": [([tool("uv"), "sync", "--project", str(DRIVERS / "python")], ROOT)],
        "dotnet": [([tool("dotnet"), "build", str(DRIVERS / "dotnet" / "HkdfGuard.Interop.csproj"), "-c", "Release",
                     "-o", str(DRIVERS / "dotnet" / "out"), "-nologo", "-v", "q"], ROOT)],
        "java": [
            ([str(mvnw), "-q", "-B", "install", "-DskipTests"], repos / "hkdfguard-java"),
            ([str(mvnw), "-q", "-B", "-f", str(DRIVERS / "java" / "pom.xml"), "package"], ROOT),
        ],
    }
    for driver in sorted(drivers):
        for command, cwd in steps[driver]:
            print(f"build {driver}: {Path(command[0]).stem} {' '.join(command[1:3])} (in {cwd.name})", flush=True)
            result = run(command, cwd)
            if result.returncode != 0:
                sys.exit(f"building the {driver} driver failed:\n{result.stdout}{result.stderr}")


def command_for(driver: str) -> list[str]:
    """How to invoke a driver; every driver takes the same arguments after this."""
    return {
        "go": [str(DRIVERS / "go" / "bin" / ("interop.exe" if WINDOWS else "interop"))],
        "node": [tool("node"), str(DRIVERS / "node" / "interop.cjs")],
        "python": [tool("uv"), "run", "--no-sync", "--project", str(DRIVERS / "python"), "python", str(DRIVERS / "python" / "interop.py")],
        "dotnet": [tool("dotnet"), str(DRIVERS / "dotnet" / "out" / "HkdfGuard.Interop.dll")],
        "java": [java(), "--enable-native-access=ALL-UNNAMED", "-cp",
                 os.pathsep.join([str(DRIVERS / "java" / "target" / "classes"), str(DRIVERS / "java" / "target" / "lib" / "*")]),
                 "io.github.runsecure.hkdfguard.interop.Main"],
    }[driver]


def work_directory() -> Path:
    """A fresh folder the native library will accept key files from.

    Windows refuses an 8.3 short name anywhere in a key file's path, and %TEMP% can be one, so the
    path is expanded. Linux refuses a key file under any group- or world-writable directory, sticky
    or not, so never /tmp: a private folder under $XDG_RUNTIME_DIR or ~/.cache instead.
    """
    if sys.platform.startswith("linux"):
        base = Path(os.environ.get("XDG_RUNTIME_DIR") or Path.home() / ".cache" / "hkdfguard-interop")
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix="hkdfguard-interop-", dir=base)).resolve()
    return Path(os.path.realpath(tempfile.mkdtemp(prefix="hkdfguard-interop-")))


def produce(driver: str, service: str, cli: str, directory: Path) -> Cell:
    result = run(command_for(driver) + ["produce", "--service", service, "--fixtures", str(FIXTURES), "--dir", str(directory), "--cli", cli])
    return Cell(result.returncode == 0, last_line(result), result.stdout + result.stderr)


def consume(driver: str, service: str, directory: Path) -> Cell:
    result = run(command_for(driver) + ["consume", "--service", service, "--fixtures", str(FIXTURES), "--dir", str(directory)])
    return Cell(result.returncode == 0, last_line(result), result.stdout + result.stderr)


def last_line(result: subprocess.CompletedProcess[str]) -> str:
    lines = [line for line in (result.stdout + result.stderr).splitlines() if line.startswith(("OK", "FAIL"))]
    return lines[-1] if lines else f"exit {result.returncode}"


def grid(producers: list[str], consumers: list[str], cells: dict[tuple[str, str], Cell]) -> str:
    header = "| producer \\ consumer | " + " | ".join(consumers) + " |"
    rule = "| --- |" + " :---: |" * len(consumers)
    rows = ["| " + p + " | " + " | ".join(("pass" if cells[p, c].ok else "**FAIL**") if (p, c) in cells else "-" for c in consumers) + " |"
            for p in producers]
    return "\n".join([header, rule, *rows])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--service", default=os.environ.get("HKDFGUARD_TEST_SERVICE") or DEFAULT_SERVICE)
    parser.add_argument("--cli", default=os.environ.get("HKDFGUARD_CLI") or default_cli(), help="the native hkdfguard tool")
    parser.add_argument("--repos", type=Path, default=ROOT.parent, help="the folder holding the sibling hkdfguard-* checkouts")
    parser.add_argument("--producers", default=",".join(PRODUCERS))
    parser.add_argument("--consumers", default=",".join(CONSUMERS))
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--keep", action="store_true", help="keep the releases folder for inspection")
    args = parser.parse_args()

    producers = [p for p in args.producers.split(",") if p]
    consumers = [c for c in args.consumers.split(",") if c]
    unknown = (set(producers) - set(PRODUCERS)) | (set(consumers) - set(CONSUMERS))
    if unknown:
        parser.error(f"unknown driver(s): {', '.join(sorted(unknown))}")
    if not Path(args.cli).is_file():
        parser.error(f"the native hkdfguard tool is not at {args.cli}; pass --cli or set HKDFGUARD_CLI")

    if not args.skip_build:
        build(args.repos.resolve(), set(producers) | set(consumers))

    work = work_directory()
    print(f"service {args.service}, releases in {work}", flush=True)
    cells: dict[tuple[str, str], Cell] = {}
    failures: list[str] = []
    started = time.monotonic()
    try:
        for p in producers:
            made = produce(p, args.service, args.cli, work / p)
            print(f"produce {p}: {made.summary}", flush=True)
            if not made.ok:
                failures.append(f"### produce {p}\n{made.output}")
                continue
            for c in consumers:
                cells[p, c] = consume(c, args.service, work / p)
                print(f"  {c} <- {p}: {cells[p, c].summary}", flush=True)
                if not cells[p, c].ok:
                    failures.append(f"### {c} reading the {p} release\n{cells[p, c].output}")
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    table = grid(producers, consumers, cells)
    print(f"\n{table}\n\n{len(cells)} cells in {time.monotonic() - started:.0f}s")
    for failure in failures:
        print(f"\n{failure}")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"## HkdfGuard interop ({sys.platform})\n\n{table}\n\n" + "\n\n".join(f"```\n{x}\n```" for x in failures) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
