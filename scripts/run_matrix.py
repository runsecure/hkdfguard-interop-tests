#!/usr/bin/env python3
"""Runs the HkdfGuard interop matrix on this host: builds every driver, has each producer write a
release (pipeline-encrypted secrets plus a key file wrapped by one key wrapper), then has every
consumer read every release with its own port of the same wrapper. Each consumer also reads each
configured remote secret store through its own port of that store's cache. Prints a producer x
consumer grid per wrapper, a wrapper x producer grid checking that every producer lays out its secrets
pipeline JSON byte for byte as the .NET port does, a store x consumer grid for the caches, and exits
non-zero if any cell fails.

Standard library only, so it runs before any driver's dependencies are installed:

    python scripts/run_matrix.py                 # build, then run every configured wrapper and cache
    python scripts/run_matrix.py --skip-build    # reuse the last build
    python scripts/run_matrix.py --producers go --consumers dotnet,java
    python scripts/run_matrix.py --wrappers awskms,googlekms --settings ../hkdfguard-dotnet/aws.runsettings

The native wrapper needs the service's KEK provisioned on this host; the network wrappers and caches
need the HKDFGUARD_TEST_* settings each port's own integration tests read (see the README).
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DRIVERS = ROOT / "drivers"
FIXTURES = ROOT / "fixtures" / "secrets.json"
DEFAULT_SERVICE = "com.hkdfguard.integration.test.221"  # the test KEK every port's provisioning script creates
PRODUCERS = ["dotnet", "go", "java", "node", "python"]
CONSUMERS = ["dotnet", "go", "java", "node", "python"]
WINDOWS = sys.platform == "win32"

# Each key wrapper, and the settings without which it can't run. The native wrapper needs only the
# KEK on this host. The network wrappers read the same variables as each port's integration tests.
WRAPPERS: dict[str, list[str]] = {
    "native": [],
    "awskms": ["HKDFGUARD_TEST_AWS_KMS_KEY_ID"],
    "azurekeyvault": ["HKDFGUARD_TEST_AZURE_WRAP_KEY_ID", "HKDFGUARD_TEST_AZURE_SIGN_KEY_ID"],
    "googlekms": ["HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME"],
    "hashicorpvault": ["HKDFGUARD_TEST_VAULT_TRANSIT_KEY", "HKDFGUARD_TEST_VAULT_TOKEN"],
}

# Each remote secret cache, and its settings. The expected JSON is required: a cache read is only
# checked against what the store is known to hold, never just for being non-empty.
CACHES: dict[str, list[str]] = {
    "awssecretsmanager": ["HKDFGUARD_TEST_AWS_SECRET_NAME", "HKDFGUARD_TEST_AWS_SECRET_JSON"],
    "azurekeyvault": ["HKDFGUARD_TEST_AZURE_SECRET_ID", "HKDFGUARD_TEST_AZURE_SECRET_JSON"],
    "googlesecretmanager": ["HKDFGUARD_TEST_GOOGLE_SECRET_NAME", "HKDFGUARD_TEST_GOOGLE_SECRET_JSON"],
    "hashicorpvault": ["HKDFGUARD_TEST_VAULT_SECRET_NAME", "HKDFGUARD_TEST_VAULT_SECRET_JSON", "HKDFGUARD_TEST_VAULT_TOKEN"],
}


# A value in a producer's secrets pipeline JSON, masked before its layout is compared, since every
# producer's ciphertext differs.
ENCRYPTED_VALUE = re.compile(r'"(enc::v[0-9]+::)[A-Za-z0-9+/]*=*"')


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


def read_settings(path: Path) -> dict[str, str]:
    """The HKDFGUARD_TEST_* (and AWS_PROFILE/AWS_REGION) settings in a .NET runsettings file or a
    NAME=value properties file - the files each port's integration tests already read - so the
    matrix reuses them rather than asking for the same values again."""
    text = path.read_text(encoding="utf-8-sig")
    if text.lstrip().startswith("<"):
        variables = ElementTree.fromstring(text).find("./RunConfiguration/EnvironmentVariables")
        found = {e.tag: (e.text or "").strip() for e in (variables if variables is not None else [])}
    else:
        found = {}
        for line in text.splitlines():
            line = line.strip()
            if line and not line.startswith(("#", "!")) and "=" in line:
                name, value = line.split("=", 1)
                found[name.strip()] = value.strip()
    return {k: v for k, v in found.items() if v and re.fullmatch(r"HKDFGUARD_TEST_\w+|AWS_PROFILE|AWS_REGION", k)}


def run(command: list[str], cwd: Path | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")


def build(repos: Path, drivers: set[str]) -> None:
    """Builds each driver against the sibling checkouts in `repos`."""
    mvnw = repos / "hkdfguard-java" / ("mvnw.cmd" if WINDOWS else "mvnw")
    steps: dict[str, list[tuple[list[str], Path]]] = {
        "go": [([tool("go"), "build", "-o", str(DRIVERS / "go" / "bin" / ("interop.exe" if WINDOWS else "interop")), "."], DRIVERS / "go")],
        "node": [
            # A fresh checkout needs its workspace installed; an existing one is left as it is.
            *([] if (repos / "hkdfguard-node" / "node_modules").is_dir() else [([tool("npm"), "ci", "--no-audit", "--no-fund"], repos / "hkdfguard-node")]),
            ([tool("npm"), "run", "build"], repos / "hkdfguard-node"),
            # ci and --locked install exactly what the committed lockfiles pin, and fail if a lockfile
            # no longer matches its manifest, rather than resolving dependencies afresh.
            ([tool("npm"), "ci", "--no-audit", "--no-fund"], DRIVERS / "node"),
        ],
        "python": [([tool("uv"), "sync", "--locked", "--project", str(DRIVERS / "python")], ROOT)],
        "dotnet": [
            ([tool("dotnet"), "restore", str(DRIVERS / "dotnet" / "HkdfGuard.Interop.csproj"), "--locked-mode", "-v", "q"], ROOT),
            ([tool("dotnet"), "build", str(DRIVERS / "dotnet" / "HkdfGuard.Interop.csproj"), "--no-restore", "-c", "Release",
              "-o", str(DRIVERS / "dotnet" / "out"), "-nologo", "-v", "q"], ROOT),
        ],
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


def long_path(path: str) -> str:
    """`path` with any 8.3 short name expanded: %TEMP% can be one (C:\\Users\\RUNNER~1\\...), and
    the native library refuses a key file whose path holds one."""
    size = ctypes.windll.kernel32.GetLongPathNameW(path, None, 0)
    if size == 0:
        return path
    buffer = ctypes.create_unicode_buffer(size)
    ctypes.windll.kernel32.GetLongPathNameW(path, buffer, size)
    return buffer.value


def work_directory() -> Path:
    """A fresh folder every wrapper will accept key files from.

    Windows: under the temp folder by its long path, made with a plain mkdir so it inherits the
    temp folder's ACL. tempfile.mkdtemp's 0o700 gives it a protected DACL with an OWNER RIGHTS entry,
    which the network wrappers' key file check refuses. Linux refuses a key file under any group- or
    world-writable directory, sticky or not, so never /tmp: a private folder under $XDG_RUNTIME_DIR
    or ~/.cache instead.
    """
    if WINDOWS:
        directory = Path(long_path(os.path.realpath(tempfile.gettempdir()))) / f"hkdfguard-interop-{uuid.uuid4().hex}"
        directory.mkdir()
        return directory
    if sys.platform.startswith("linux"):
        base = Path(os.environ.get("XDG_RUNTIME_DIR") or Path.home() / ".cache" / "hkdfguard-interop")
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        return Path(tempfile.mkdtemp(prefix="hkdfguard-interop-", dir=base)).resolve()
    return Path(os.path.realpath(tempfile.mkdtemp(prefix="hkdfguard-interop-")))


def release_directory(work: Path, wrapper: str, producer: str) -> Path:
    """The folder one producer writes one wrapper's release to, made here so every producer gets
    the same permissions (see work_directory)."""
    directory = work / wrapper / producer
    directory.mkdir(parents=True, **({} if WINDOWS else {"mode": 0o700}))
    return directory


def invoke(driver: str, arguments: list[str], env: dict[str, str]) -> Cell:
    result = run(command_for(driver) + arguments, env=env)
    return Cell(result.returncode == 0, last_line(result), result.stdout + result.stderr)


def last_line(result: subprocess.CompletedProcess[str]) -> str:
    lines = [line for line in (result.stdout + result.stderr).splitlines() if line.startswith(("OK", "FAIL"))]
    return lines[-1] if lines else f"exit {result.returncode}"


def fenced(text: str) -> str:
    """`text` as a Markdown code block whose fence is longer than any backtick run inside it, so
    driver output can't close the block early and have the rest rendered as Markdown."""
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{text}\n{fence}"


def grid(corner: str, rows: list[str], consumers: list[str], cells: dict[tuple[str, str], Cell]) -> str:
    header = f"| {corner} | " + " | ".join(consumers) + " |"
    rule = "| --- |" + " :---: |" * len(consumers)
    lines = ["| " + r + " | " + " | ".join(("pass" if cells[r, c].ok else "**FAIL**") if (r, c) in cells else "-" for c in consumers) + " |"
             for r in rows]
    return "\n".join([header, rule, *lines])


def expected_pipeline_json(fixtures: dict) -> dict[str, str]:
    """Each pipeline JSON file as every producer must write it, its values masked: laid out as .NET's
    Utf8JsonWriter writes it indented with relaxed escaping. That is one member per line, in ordinal
    file-name order, indented two spaces, a space after each colon, lines ended as the platform ends
    them (CRLF on Windows), no line ending after the closing brace, no byte order mark, and {} for no
    secrets."""
    version = f"enc::v{fixtures['keyVersion']}::"
    names = sorted(s["fileName"] for s in fixtures["pipeline"]["secrets"])  # ASCII names: code point order is ordinal
    members = [f'  "{name}": "{version}<base64>"' for name in names]
    full = "{" + os.linesep + ("," + os.linesep).join(members) + os.linesep + "}"
    return {"secrets.json": full, "secrets.stream.json": full, "secrets.empty.json": "{}"}


def check_pipeline_json(directory: Path, expected: dict[str, str]) -> Cell:
    """Whether a producer's pipeline JSON files are laid out byte for byte as expected. Only masked
    text is ever reported: the values are ciphertext, but none of it is needed to say what differs."""
    problems = []
    for name, want in expected.items():
        try:
            got = ENCRYPTED_VALUE.sub(r'"\1<base64>"', (directory / "pipeline" / name).read_bytes().decode("utf-8"))
        except (OSError, UnicodeDecodeError) as e:
            problems.append(f"{name}: {type(e).__name__}: {e}")
            continue
        if got != want:
            # Split on LF only, so a CR where there should be none, or none where there should be one,
            # shows in the line reported.
            wanted, lines = want.split("\n"), got.split("\n")
            line = next((i for i, (a, b) in enumerate(zip(wanted, lines)) if a != b), min(len(wanted), len(lines)))
            problems.append(f"{name} differs at line {line + 1}: expected {wanted[line] if line < len(wanted) else '<end>'!r}, "
                            f"got {lines[line] if line < len(lines) else '<end>'!r}")
    return Cell(not problems, "OK" if not problems else f"FAIL {problems[0]}", "\n".join(problems))


def system_tar_present() -> bool:
    """Whether the tar every driver unpacks the pipeline's archive with is here: Windows' own bsdtar,
    else the tar on PATH."""
    if WINDOWS:
        return Path(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "tar.exe").is_file()
    return shutil.which("tar") is not None


def selected(requested: str | None, known: dict[str, list[str]], env: dict[str, str], what: str,
             parser: argparse.ArgumentParser) -> tuple[list[str], list[str]]:
    """The wrappers or caches to run, and a note for each configured-out one. Named explicitly, a
    missing setting is an error; by default, an unconfigured one is skipped and said so, never
    reported as passed."""
    if requested is not None:
        names = [n for n in requested.split(",") if n]
        unknown = set(names) - set(known)
        if unknown:
            parser.error(f"unknown {what}(s): {', '.join(sorted(unknown))}")
        for name in names:
            if missing := [v for v in known[name] if not env.get(v)]:
                parser.error(f"{what} {name} needs {', '.join(missing)}: set them, or pass --settings")
        return names, []
    names, skipped = [], []
    for name, variables in known.items():
        if missing := [v for v in variables if not env.get(v)]:
            skipped.append(f"skip {what} {name}: {', '.join(missing)} not set")
        else:
            names.append(name)
    return names, skipped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--service", default=os.environ.get("HKDFGUARD_TEST_SERVICE") or DEFAULT_SERVICE)
    parser.add_argument("--cli", default=os.environ.get("HKDFGUARD_CLI") or default_cli(), help="the native hkdfguard tool")
    parser.add_argument("--repos", type=Path, default=ROOT.parent, help="the folder holding the sibling hkdfguard-* checkouts")
    parser.add_argument("--producers", default=",".join(PRODUCERS))
    parser.add_argument("--consumers", default=",".join(CONSUMERS))
    parser.add_argument("--wrappers", help=f"key wrappers to run (default: every configured one of {', '.join(WRAPPERS)})")
    parser.add_argument("--caches", help=f"remote caches to run (default: every configured one of {', '.join(CACHES)}); '' for none")
    parser.add_argument("--settings", type=Path, action="append", default=[],
                        help="a .runsettings or .test.properties file of HKDFGUARD_TEST_* settings; repeatable. The environment wins")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--keep", action="store_true", help="keep the releases folder for inspection")
    args = parser.parse_args()

    producers = [p for p in args.producers.split(",") if p]
    consumers = [c for c in args.consumers.split(",") if c]
    unknown = (set(producers) - set(PRODUCERS)) | (set(consumers) - set(CONSUMERS))
    if unknown:
        parser.error(f"unknown driver(s): {', '.join(sorted(unknown))}")

    # Settings go to the drivers' environment only; their values are never printed.
    env = dict(os.environ)
    for path in args.settings:
        for name, value in read_settings(path).items():
            env.setdefault(name, value)
    wrappers, skipped = selected(args.wrappers, WRAPPERS, env, "wrapper", parser)
    caches, skipped_caches = selected(args.caches, CACHES, env, "cache", parser)
    if "native" in wrappers and not Path(args.cli).is_file():
        parser.error(f"the native hkdfguard tool is not at {args.cli}; pass --cli or set HKDFGUARD_CLI, or leave native out of --wrappers")
    if not wrappers:
        parser.error("no key wrapper to run")
    if not system_tar_present():
        parser.error("the system tar is missing: every driver unpacks the secrets pipeline's archive with it")
    expected_json = expected_pipeline_json(json.loads(FIXTURES.read_text(encoding="utf-8")))
    for note in skipped + skipped_caches:
        print(note, flush=True)

    if not args.skip_build:
        build(args.repos.resolve(), set(producers) | set(consumers))

    work = work_directory()
    print(f"service {args.service}, releases in {work}", flush=True)
    cells: dict[str, dict[tuple[str, str], Cell]] = {w: {} for w in wrappers}
    layout_cells: dict[tuple[str, str], Cell] = {}  # (wrapper, producer): its pipeline JSON's layout
    cache_cells: dict[tuple[str, str], Cell] = {}
    failures: list[str] = []
    readable: dict[str, Path] = {}  # per consumer, a release it read, to build its cache's key ring over
    started = time.monotonic()
    try:
        for w in wrappers:
            for p in producers:
                directory = release_directory(work, w, p)
                made = invoke(p, ["produce", "--wrapper", w, "--service", args.service, "--fixtures", str(FIXTURES),
                                  "--dir", str(directory), "--cli", args.cli], env)
                print(f"produce {w} {p}: {made.summary}", flush=True)
                if not made.ok:
                    failures.append(f"### produce {w} {p}\n{made.output}")
                    continue
                layout = layout_cells[w, p] = check_pipeline_json(directory, expected_json)
                print(f"  pipeline JSON {w} {p}: {layout.summary}", flush=True)
                if not layout.ok:
                    failures.append(f"### pipeline JSON written by {p} for {w}\n{layout.output}")
                for c in consumers:
                    cell = cells[w][p, c] = invoke(c, ["consume", "--wrapper", w, "--service", args.service,
                                                        "--fixtures", str(FIXTURES), "--dir", str(directory)], env)
                    print(f"  {c} <- {w} {p}: {cell.summary}", flush=True)
                    if cell.ok:
                        readable.setdefault(c, directory)
                    else:
                        failures.append(f"### {c} reading the {w} {p} release\n{cell.output}")

        for s in caches:
            for c in consumers:
                if c not in readable:
                    failures.append(f"### {c} reading {s}\nno release {c} could read to build a key ring over")
                    continue
                directory = readable[c]
                cell = cache_cells[s, c] = invoke(c, ["cache", "--store", s, "--wrapper", directory.parent.name, "--service",
                                                      args.service, "--fixtures", str(FIXTURES), "--dir", str(directory)], env)
                print(f"cache {s} {c}: {cell.summary}", flush=True)
                if not cell.ok:
                    failures.append(f"### {c} reading {s}\n{cell.output}")
    finally:
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)

    tables = [f"#### {w}\n\n" + grid("producer \\ consumer", producers, consumers, cells[w]) for w in wrappers]
    tables.append("#### pipeline JSON layout\n\n" + grid("wrapper \\ producer", wrappers, producers, layout_cells))
    if caches:
        tables.append("#### remote caches\n\n" + grid("store \\ consumer", caches, consumers, cache_cells))
    report = "\n\n".join(tables)
    count = sum(len(c) for c in cells.values()) + len(layout_cells) + len(cache_cells)
    print(f"\n{report}\n\n{count} cells in {time.monotonic() - started:.0f}s")
    for note in skipped + skipped_caches:
        print(note)
    for failure in failures:
        print(f"\n{failure}")
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"## HkdfGuard interop ({sys.platform})\n\n{report}\n\n" + "\n".join(skipped + skipped_caches) + "\n\n"
                    + "\n\n".join(fenced(x) for x in failures) + "\n")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
