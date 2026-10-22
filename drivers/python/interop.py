"""The Python driver for the HkdfGuard interop matrix: it produces a release (pipeline encryption plus a
key file wrapped by the native hkdfguard tool) and consumes any driver's release. See the repository
README for the contract every driver follows."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from hkdfguard.abstractions import ArrayUtility, ProtectedConfigurationPurpose
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory, AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DefaultFormatProvider, KeyRing, KeyRingBuilder
from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1

RELEASE_FILE = "release.json"
KEY_FILE = "dek.wrapped"
KEY_SIZE = 32
FORMAT = re.compile(r"^(enc::v\d+::)(.+)$", re.DOTALL)


def produce(service: str, fixtures: dict[str, Any], directory: Path, cli: str) -> None:
    """Does what a release pipeline does: encrypts every fixture under a fresh pipeline key, writes the
    values, and hands the key to the native tool on standard input to wrap into the key file."""
    pipeline = AesGcmPipelineDataProtector(DefaultFormatProvider(), fixtures["keyVersion"])
    raw = bytearray(KEY_SIZE)
    try:
        values = {s["identifier"]: pipeline.encrypt(s["plaintext"], s["identifier"]) for s in fixtures["secrets"]}

        # Test only: a hash of the DEK, so every consumer can prove it unwrapped this same key.
        key_base64 = pipeline.get_key_as_base64()
        decoded = base64.b64decode(key_base64)
        raw[:] = decoded
        dek_sha256 = hashlib.sha256(raw).hexdigest()

        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        wrap = subprocess.run([cli, "wrap", "-kf", str(directory / KEY_FILE), "-sn", service, "--dek-stdin"],
                              input=bytes(key_base64), capture_output=True)
        if wrap.returncode != 0:
            output = (wrap.stdout + wrap.stderr).decode(errors="replace").strip()
            raise RuntimeError(f"hkdfguard wrap exited {wrap.returncode}: {output}")

        release = {"producer": "python", "service": service, "keyVersion": fixtures["keyVersion"], "dekSha256": dek_sha256, "values": values}
        path = directory / RELEASE_FILE
        path.write_text(json.dumps(release, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(path, 0o600)
        print(f"OK produced {len(values)} secrets in {directory}")
    finally:
        ArrayUtility.zero_memory(raw)
        pipeline.close()


def consume(service: str, fixtures: dict[str, Any], directory: Path) -> bool:
    """Reads a release as an application would: builds a ring over the native KEK with the key file,
    then reveals every value through the configuration purpose of its key."""
    release = json.loads((directory / RELEASE_FILE).read_text(encoding="utf-8"))
    wrapper = NativeHkdfKeyWrapperV1(service)
    checks = Checker()
    with (KeyRingBuilder()
          .with_service_name(service)
          .with_key_wrapper(wrapper)
          .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
          .with_key_refresh_interval(60)
          .with_key_file(release["keyVersion"], directory / KEY_FILE)
          .build()) as ring:
        for s in fixtures["secrets"]:
            value = release["values"].get(s["identifier"])
            if value is None:
                checks.fail(f"{s['identifier']}: missing from the release")
                continue
            for name in [s["identifier"], *s.get("alsoReadAs", [])]:
                got, error = attempt(lambda: reveal(ring, name, value))
                checks.check(error is None and got == s["plaintext"], f"{s['identifier']} reads as {name}: {error or 'wrong plaintext'}")
            for name in s.get("mustNotReadAs", []):
                checks.check(attempt(lambda: reveal(ring, name, value))[1] is not None, f"{s['identifier']} must not read as {name}")

        first, second = fixtures["secrets"][0], fixtures["secrets"][1]
        moved = release["values"][first["identifier"]]
        checks.check(attempt(lambda: reveal(ring, second["identifier"], moved))[1] is not None,
                     f"{first['identifier']} moved under {second['identifier']} fails authentication")
        checks.check(attempt(lambda: reveal(ring, first["identifier"], tamper(moved)))[1] is not None,
                     f"{first['identifier']} with a flipped tag bit fails authentication")

    digest, error = attempt(lambda: unwrapped_digest(wrapper, directory / KEY_FILE))
    checks.check(digest == release["dekSha256"], f"the key file unwraps to the producer's DEK: {error or 'digest differs'}")
    return checks.finish(release["producer"])


def reveal(ring: KeyRing, name: str, value: str) -> str:
    protector = ring.create_protector(ProtectedConfigurationPurpose.for_key(name))
    result = bytearray(protector.get_max_decrypted_length(value))
    try:
        return result[:protector.decrypt(value, result)].decode("utf-8")
    finally:
        ArrayUtility.zero_memory(result)


def tamper(value: str) -> str:
    """Flips one bit in the last byte (the GCM tag) of a formatted value."""
    match = FORMAT.match(value)
    if match is None:
        raise ValueError("not an enc::v<version>::<base64> value")
    body = bytearray(base64.b64decode(match.group(2)))
    body[-1] ^= 0x01
    return match.group(1) + base64.b64encode(body).decode("ascii")


def unwrapped_digest(wrapper: NativeHkdfKeyWrapperV1, path: Path) -> str:
    wrapped = wrapper.read_key_file(path)
    raw = bytearray(KEY_SIZE)
    try:
        written = wrapper.unwrap(wrapped, raw)
        return hashlib.sha256(raw[:written]).hexdigest()
    finally:
        ArrayUtility.zero_memory(raw)


def attempt(body: Callable[[], Any]) -> tuple[Any, str | None]:
    try:
        return body(), None
    except Exception as error:  # noqa: BLE001 - any failure is the answer being checked
        return None, f"{type(error).__name__}: {error}"


class Checker:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def check(self, ok: bool, message: str) -> None:
        if ok:
            self.passed += 1
        else:
            self.fail(message)

    def fail(self, message: str) -> None:
        self.failed += 1
        print(f"FAIL {message}")

    def finish(self, producer: str) -> bool:
        if self.failed:
            print(f"FAIL {self.failed} of {self.passed + self.failed} checks failed reading the {producer} release", file=sys.stderr)
            return False
        print(f"OK {self.passed} checks passed reading the {producer} release")
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["produce", "consume"])
    parser.add_argument("--service", required=True)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--dir", required=True, type=Path)
    parser.add_argument("--cli")
    args = parser.parse_args()
    fixtures = json.loads(args.fixtures.read_text(encoding="utf-8"))
    try:
        if args.command == "produce":
            if not args.cli:
                parser.error("produce needs --cli")
            produce(args.service, fixtures, args.dir, args.cli)
            return 0
        return 0 if consume(args.service, fixtures, args.dir) else 1
    except Exception as error:  # noqa: BLE001 - reported, then a failing exit code
        print(f"FAIL {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
