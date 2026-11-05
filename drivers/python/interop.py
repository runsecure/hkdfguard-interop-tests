"""The Python driver for the HkdfGuard interop matrix: it produces a release (pipeline encryption plus a
key file wrapped by one key wrapper, and the secrets pipeline writer's files, JSON and tar archive),
consumes any driver's release with its own port of the same wrapper and caches, and reads a remote
secret store through its cache over that release's key ring. See the repository README for the
contract every driver follows."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
from collections.abc import Buffer, MutableMapping, Sequence
from pathlib import Path
from typing import IO, Any, Callable
from urllib.parse import urlsplit

from hkdfguard.abstractions import (ArrayUtility, AuthenticationTagMismatchError, EncryptedFormatProvider, KeyNotFoundError, KeyWrapper,
                                    PipelineDataProtector, ProtectedConfigurationPurpose, ProtectedReadOnlyCache, WrappedKeyLimits)
from hkdfguard.cache import FilePerSecretCache, ProtectedCache
from hkdfguard.cache.jsonsecretsfile import JsonSecretsFileReadOnlyCache
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory, AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DefaultFormatProvider, KeyRing, KeyRingBuilder
from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1
from hkdfguard.pipeline import SecretPipelineWriter, SecretRequest
from hkdfguard.securefile import KeyFileTrust

RELEASE_FILE = "release.json"
KEY_FILE = "dek.wrapped"
SECRETS_DIR = "secrets"
KEY_SIZE = 32
FORMAT = re.compile(r"^(enc::v\d+::)(.+)$", re.DOTALL)
# The base64 of a 32-byte key: 44 ASCII characters, no line ending.
KEY_BASE64_LENGTH = 44

PIPELINE_DIR = "pipeline"
JSON_SECRETS_FILE = "secrets.json"
STREAM_JSON_SECRETS_FILE = "secrets.stream.json"
EMPTY_JSON_SECRETS_FILE = "secrets.empty.json"
SECRETS_TAR = "secrets.tar"
PIPELINE_FILES_DIR = "files"
PIPELINE_UNPACKED_DIR = "unpacked"
CONSUMER_DIR = "consumed-by-python"

NATIVE = "native"
# The context every port's integration tests bind their key files to, so the matrix runs under the
# IAM, key and token policies already written for those tests.
WRAP_CONTEXT = "hkdfguard.integrationtest"
# The one those tests check a key file is refused under.
OTHER_CONTEXT = "hkdfguard.integrationtest.other"
DEFAULT_VAULT_ADDRESS = "http://127.0.0.1:8200"

# A key no test secret holds.
MISSING_KEY = "hkdfguard-interop-missing"
INTEGER = re.compile(r"^-?[0-9]{1,15}$")


def produce(wrapper_name: str, service: str, fixtures: dict[str, Any], directory: Path, cli: str) -> None:
    """Does what a release pipeline does: encrypts every fixture under a fresh pipeline key, writes the
    values and the secrets pipeline writer's output, and wraps the key into the key file - by having
    write_dek write it into the native tool's standard input, or through a network key wrapper in
    this process."""
    pipeline = AesGcmPipelineDataProtector(DefaultFormatProvider(), fixtures["keyVersion"])
    raw = bytearray(KEY_SIZE)
    try:
        values = {s["identifier"]: pipeline.encrypt(s["plaintext"], s["identifier"]) for s in fixtures["secrets"]}

        read_dek_through_write_dek(pipeline, raw)
        # Test only: a hash of the DEK, so every consumer can prove it unwrapped this same key. Never
        # record anything derived from a DEK beside its key file in a real pipeline.
        dek_sha256 = hashlib.sha256(raw).hexdigest()

        # The matrix creates the folder, so this is a no-op there. Never with mode 0o700 on Windows:
        # Python 3.13+ gives such a folder an owner-only protected ACL, which the network wrappers'
        # key file checks refuse.
        directory.mkdir(**({} if os.name == "nt" else {"mode": 0o700}), parents=True, exist_ok=True)
        write_secret_files(pipeline, fixtures, directory / SECRETS_DIR)
        write_pipeline(pipeline, fixtures["pipeline"], directory)
        path = directory / KEY_FILE
        if wrapper_name == NATIVE:
            wrap_natively(cli, path, service, pipeline)
        else:
            with contextlib.ExitStack() as stack:
                wrapper = new_wrapper(wrapper_name, service, WRAP_CONTEXT, stack)
                wrapped = bytearray(WrappedKeyLimits.MAX_BYTES)
                try:
                    written = wrapper.wrap(raw, wrapped)
                except Exception as error:
                    raise RuntimeError(f"wrapping the pipeline key: {type(error).__name__}: {error}") from error
                with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600), "wb") as file:
                    file.write(wrapped[:written])

        release = {"producer": "python", "wrapper": wrapper_name, "service": service, "keyVersion": fixtures["keyVersion"],
                   "dekSha256": dek_sha256, "values": values}
        release_path = directory / RELEASE_FILE
        release_path.write_text(json.dumps(release, ensure_ascii=False, indent=2), encoding="utf-8")
        os.chmod(release_path, 0o600)
        print(f"OK produced {len(values)} secrets and {len(fixtures['pipeline']['secrets'])} pipeline secrets in {directory}")
    finally:
        ArrayUtility.zero_memory(raw)
        pipeline.close()


def wrap_natively(cli: str, path: Path, service: str, pipeline: AesGcmPipelineDataProtector) -> None:
    """Writes the pipeline key with write_dek straight into the standard input of
    ``hkdfguard wrap --dek-stdin``: never an argument or an environment variable, and never a copy
    here. The pipe is unbuffered, so no buffer of Popen's holds the key either. Closing its input is
    what tells the tool the key is complete."""
    wrap = subprocess.Popen([cli, "wrap", "-kf", str(path), "-sn", service, "--dek-stdin"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
    try:
        pipeline.write_dek(wrap.stdin)
    finally:
        wrap.stdin.close()
    stdout, stderr = wrap.communicate()
    if wrap.returncode != 0:
        output = (stdout + stderr).decode(errors="replace").strip()
        raise RuntimeError(f"hkdfguard wrap exited {wrap.returncode}: {output}")


class _KeyBuffer:
    """A BinaryDestination over a fixed bytearray, as .NET's MemoryStream over a pinned array: what
    is written is copied into it in place, and a write past its end is refused."""

    def __init__(self, buffer: bytearray) -> None:
        self.buffer = buffer
        self.written = 0

    def write(self, data: Buffer, /) -> int:
        view = memoryview(data).cast("B")
        end = self.written + view.nbytes
        if end > len(self.buffer):
            raise ValueError(f"write_dek wrote more than {len(self.buffer)} bytes")
        self.buffer[self.written:end] = view
        self.written = end
        return view.nbytes

    def flush(self) -> None:
        pass


def read_dek_through_write_dek(pipeline: AesGcmPipelineDataProtector, dek: bytearray) -> None:
    """Writes the pipeline key through write_dek, as the wrap tool's --dek-stdin reads it, into a
    buffer here, and decodes it into ``dek``: so every wrapper's key file comes from those bytes, and
    every consumer's DEK check proves them. Checks they are exactly the key's 44 base64 characters as
    ASCII, without a line ending. Decoding leaves the DEK in an immutable bytes object that can't be
    zeroed, as every base64 decode in CPython does; acceptable for a throwaway test key only."""
    ascii_key = bytearray(KEY_BASE64_LENGTH + 2)
    try:
        destination = _KeyBuffer(ascii_key)
        pipeline.write_dek(destination)
        written = destination.written
        key = pipeline.get_key_as_base64()
        if written != KEY_BASE64_LENGTH or memoryview(ascii_key)[:written] != key:
            raise RuntimeError(f"write_dek wrote {written} bytes, not the key's {KEY_BASE64_LENGTH} base64 characters")
        decoded = base64.b64decode(memoryview(ascii_key)[:written], validate=True)
        if len(decoded) != KEY_SIZE:
            raise RuntimeError("The pipeline key isn't 32 bytes.")
        dek[:] = decoded
    finally:
        ArrayUtility.zero_memory(ascii_key)


def consume(wrapper_name: str, service: str, fixtures: dict[str, Any], directory: Path) -> bool:
    """Reads a release as an application would: builds a ring over the wrapper's KEK with the key
    file, then reveals every value through the configuration purpose of its key, and caches it."""
    with contextlib.ExitStack() as stack:
        release, wrapper, ring = open_release(wrapper_name, service, directory, stack)
        checks = Checker()
        for s in fixtures["secrets"]:
            value = release["values"].get(s["identifier"])
            if value is None:
                checks.fail(f"{s['identifier']}: missing from the release")
                continue
            for name in [s["identifier"], *s.get("alsoReadAs", [])]:
                got, error = attempt(lambda: reveal(ring, name, value))
                checks.check(error is None and got == s["plaintext"], f"{s['identifier']} reads as {name}: got {size(got)} bytes, {error}")
            for name in s.get("mustNotReadAs", []):
                checks.check(attempt(lambda: reveal(ring, name, value))[1] is not None, f"{s['identifier']} must not read as {name}")

        first, second = fixtures["secrets"][0], fixtures["secrets"][1]
        moved = release["values"][first["identifier"]]
        checks.check(attempt(lambda: reveal(ring, second["identifier"], moved))[1] is not None,
                     f"{first['identifier']} moved under {second['identifier']} fails authentication")
        tampered, error = attempt(lambda: tamper(moved))
        if error is None:
            checks.check(attempt(lambda: reveal(ring, first["identifier"], tampered))[1] is not None,
                         f"{first['identifier']} with a flipped tag bit fails authentication")
        else:
            checks.fail(f"tampering {first['identifier']}: {error}")

        path = directory / KEY_FILE
        digest, error = attempt(lambda: unwrapped_digest(wrapper, path))
        checks.check(error is None and digest == release["dekSha256"], f"the key file unwraps to the producer's DEK: {error}")

        # A network KEK is shared by every application that may use it, so the context is what keeps
        # one application's key files from another's.
        if wrapper_name != NATIVE:
            with contextlib.ExitStack() as other_stack:
                other, error = attempt(lambda: new_wrapper(wrapper_name, service, OTHER_CONTEXT, other_stack))
                if error is None:
                    checks.check(attempt(lambda: unwrapped_digest(other, path))[1] is not None, "the key file is refused under another context")
                else:
                    checks.fail(f"creating a wrapper with another context: {error}")

        check_cache(checks, ProtectedCache(ring), fixtures)
        check_secret_files(checks, ring, fixtures, directory / SECRETS_DIR)
        check_pipeline(checks, ring, fixtures["pipeline"], directory)
        return checks.finish(f"the {release['producer']} {release['wrapper']} release")


def file_plaintext(fixtures: dict[str, Any], file: dict[str, Any]) -> str:
    """The value ``file`` is written with: its own, or the named secret's."""
    if file.get("plaintextOf"):
        for s in fixtures["secrets"]:
            if s["identifier"] == file["plaintextOf"]:
                return s["plaintext"]
    return file.get("plaintext", "")


def write_secret_files(pipeline: AesGcmPipelineDataProtector, fixtures: dict[str, Any], folder: Path) -> None:
    """Writes the release's secrets folder as a pipeline would for FilePerSecretCache: one file per
    secret, holding its value encrypted under the pipeline key for the file's own name."""
    # Never with mode 0o700 on Windows, as for the release's folder.
    folder.mkdir(**({} if os.name == "nt" else {"mode": 0o700}), parents=True, exist_ok=True)
    written: dict[str, bytes] = {}
    for file in fixtures["files"]:
        if file.get("empty"):
            contents = b""
        elif file.get("copyOf"):
            contents = written[file["copyOf"]]
        else:
            try:
                contents = pipeline.encrypt(file_plaintext(fixtures, file), file["name"]).encode("ascii")
            except Exception as error:
                raise RuntimeError(f"encrypting the file {file['name']}: {type(error).__name__}: {error}") from error
            if file.get("trailingNewline"):
                contents += b"\n"
        written[file["name"]] = contents
        with os.fdopen(os.open(folder / file["name"], os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600), "wb") as out:
            out.write(contents)


def check_secret_files(checks: Checker, ring: KeyRing, fixtures: dict[str, Any], folder: Path) -> None:
    """Reads the release's secrets folder through a FilePerSecretCache over the release's ring: each
    file reads as its value, is missing, or is refused as its fixture expects, and a name no file can
    answer - one that isn't a file name in the folder - is missing."""
    trust, error = attempt(key_file_trust)
    if error is not None:
        checks.fail(f"files: trusting this account: {error}")
        return
    files, error = attempt(lambda: FilePerSecretCache(folder, trust, ring, DefaultFormatProvider()))
    if error is not None:
        checks.fail(f"files: opening the secrets folder: {error}")
        return
    for file in fixtures["files"]:
        name, expect = file["name"], file["expect"]
        got: str | None = None
        failure: Exception | None = None
        try:
            got = read_cache(files, name)
        except Exception as caught:  # noqa: BLE001 - any failure is the answer being checked
            failure = caught
        error = None if failure is None else f"{type(failure).__name__}: {failure}"
        if expect == "value":
            checks.check(failure is None and got == file_plaintext(fixtures, file), f"files: {name} reads as its value: got {size(got)} bytes, {error}")
        elif expect == "missing":
            checks.check(failure is None and got == "", f"files: {name} is missing: got {size(got)} bytes, {error}")
        elif expect == "refused":
            checks.check(isinstance(failure, AuthenticationTagMismatchError), f"files: {name} fails authentication: {error}")
        else:
            checks.fail(f"files: {name} expects {expect!r}, which isn't value, missing or refused")
    for name in fixtures["missingFiles"]:
        got, error = attempt(lambda: read_cache(files, name))
        checks.check(error is None and got == "", f"files: {name} is missing: got {size(got)} bytes, {error}")


# The secrets pipeline half of a release: every fixture in the fixtures' pipeline section is pulled
# through the port's real SecretPipelineWriter base, over an in-memory store, and written in each of
# the writer's layouts to D/pipeline. A consumer reads them back with its own port's caches over the
# release's key ring. See the README's driver contract.

STORE_NAME = re.compile(r"[A-Za-z0-9/_.\-]+")


class InMemorySecretPipelineWriter(SecretPipelineWriter):
    """A SecretPipelineWriter over an in-memory store: each store name maps to its value's exact
    text, handed to the writer as UTF-8 in a bytearray zeroed after. Names match exactly, and a store
    name is 1 or more ASCII letters, digits, '/', '_', '.' and '-'. There is no default key."""

    def __init__(self, protector: PipelineDataProtector, secret_names: Sequence[str], store: dict[str, str]) -> None:
        self._store = store
        super().__init__(protector, secret_names, lambda name: STORE_NAME.fullmatch(name) is not None)

    def _read_secret(self, name: str, requests: Sequence[SecretRequest], values: MutableMapping[str, str]) -> None:
        text = self._store.get(name)
        if text is not None:
            # The fixture's text is already an immutable str; only this copy of its bytes is the writer's.
            secret = bytearray(text, "utf-8")
            try:
                self._protect_secret(secret, requests, values)
            finally:
                ArrayUtility.zero_memory(secret)


def write_pipeline(pipeline: AesGcmPipelineDataProtector, fixtures: dict[str, Any], directory: Path) -> None:
    """Writes the release's pipeline folder. The writers use the release's own pipeline protector, so
    every value decrypts under the release's key ring, and they never close it."""
    store: dict[str, str] = fixtures["store"]
    secrets: list[dict[str, Any]] = fixtures["secrets"]
    for s in secrets:
        if SecretPipelineWriter.get_file_name(s["name"]) != s["fileName"]:
            raise RuntimeError(f"pipeline: {s['name']}'s file name isn't {s['fileName']}")
    for names in fixtures["refused"]:
        try:
            InMemorySecretPipelineWriter(pipeline, names, store).close()
        except ValueError:
            continue
        raise RuntimeError(f"pipeline: the writer accepted [{', '.join(names)}]")

    folder = directory / PIPELINE_DIR
    # Never with mode 0o700 on Windows, as for the release's folder.
    folder.mkdir(**({} if os.name == "nt" else {"mode": 0o700}), parents=True, exist_ok=True)
    file_names = [s["fileName"] for s in secrets]
    with InMemorySecretPipelineWriter(pipeline, [s["name"] for s in secrets], store) as writer:
        writer.pull_secrets()
        if sorted(writer.protected_secrets) != sorted(file_names):
            raise RuntimeError("pipeline: the writer's protected secrets aren't the fixtures' file names")

        writer.write_json_secrets(folder / JSON_SECRETS_FILE)
        with open(folder / STREAM_JSON_SECRETS_FILE, "wb") as stream:
            writer.write_json_secrets_to_stream(stream)
        writer.write_protected_secret_files(folder / PIPELINE_FILES_DIR)
        with open(folder / SECRETS_TAR, "wb") as stream:
            writer.write_protected_secret_files_to_stream(stream)

        # As a deployment would: the archive straight into a tar process's standard input.
        unpacked = folder / PIPELINE_UNPACKED_DIR
        unpacked.mkdir(**({} if os.name == "nt" else {"mode": 0o700}), exist_ok=True)
        untar(unpacked, writer.write_protected_secret_files_to_stream)
        difference = compare_folders(folder / PIPELINE_FILES_DIR, unpacked, file_names)
        if difference is not None:
            raise RuntimeError(f"pipeline: the archive piped to tar unpacked differently: {difference}")

    with InMemorySecretPipelineWriter(pipeline, fixtures["missing"], store) as missing:
        try:
            missing.pull_secrets()
        except KeyNotFoundError:
            pass
        else:
            raise RuntimeError("pipeline: pulling secrets the store holds no value for succeeded")
        if len(missing.protected_secrets) != 0:
            raise RuntimeError(f"pipeline: pulling only missing secrets kept {len(missing.protected_secrets)}")
        missing.write_json_secrets(folder / EMPTY_JSON_SECRETS_FILE)


def check_pipeline(checks: Checker, ring: KeyRing, fixtures: dict[str, Any], directory: Path) -> None:
    """Reads the release's pipeline folder as a deployed application would: secrets.json through a
    JsonSecretsFileReadOnlyCache over the release's ring, tampered copies of it refused whole, and
    secrets.tar unpacked by the system tar and read through a FilePerSecretCache."""
    folder = directory / PIPELINE_DIR
    trust = key_file_trust()
    format_provider = DefaultFormatProvider()
    json_path = folder / JSON_SECRETS_FILE
    secrets: list[dict[str, Any]] = fixtures["secrets"]

    cache, error = attempt(lambda: JsonSecretsFileReadOnlyCache(json_path, trust, ring, format_provider))
    if error is not None:
        checks.fail(f"pipeline: opening {JSON_SECRETS_FILE}: {error}")
    else:
        for s in secrets:
            for name in [s["fileName"], *s.get("alsoReadAs", [])]:
                got, error = attempt(lambda: read_cache(cache, name))
                checks.check(error is None and got == s["plaintext"],
                             f"pipeline: {JSON_SECRETS_FILE} reads {s['name']} as {name}: got {size(got)} bytes, {error or 'wrong plaintext'}")
        for name in [*fixtures["missingLookups"], *fixtures["invalidLookups"]]:
            got, error = attempt(lambda: read_cache(cache, name))
            checks.check(error is None and got == "", f"pipeline: {JSON_SECRETS_FILE} has no {name}: got {size(got)} bytes, {error}")

    same, error = attempt(lambda: (folder / STREAM_JSON_SECRETS_FILE).read_bytes() == json_path.read_bytes())
    checks.check(error is None and same, f"pipeline: {STREAM_JSON_SECRETS_FILE} is {JSON_SECRETS_FILE} byte for byte: {error or 'it differs'}")

    empty_path = folder / EMPTY_JSON_SECRETS_FILE
    empty, error = attempt(lambda: empty_path.read_bytes() == b"{}")
    checks.check(error is None and empty, f"pipeline: {EMPTY_JSON_SECRETS_FILE} is {{}}: {error or 'it is not'}")
    first = secrets[0]["fileName"]
    nothing, error = read_from_new_cache(empty_path, trust, ring, format_provider, first)
    checks.check(error is None and nothing == "", f"pipeline: {EMPTY_JSON_SECRETS_FILE} has no {first}: got {size(nothing)} bytes, {describe(error)}")

    work = folder / CONSUMER_DIR
    if work.exists():
        shutil.rmtree(work)
    # Never with mode 0o700 on Windows, as for the release's folder.
    work.mkdir(**({} if os.name == "nt" else {"mode": 0o700}), parents=True)
    check_tampered(checks, ring, format_provider, trust, json_path, work)
    check_archive(checks, ring, fixtures, trust, folder, work)


def check_tampered(checks: Checker, ring: KeyRing, format_provider: EncryptedFormatProvider, trust: KeyFileTrust, json_path: Path, work: Path) -> None:
    """Two copies of secrets.json, each changed one way, must each be refused whole: a lookup of a
    member the change didn't touch fails authentication too."""
    try:
        members = json.loads(json_path.read_bytes().decode("utf-8"), object_pairs_hook=list)
        if not isinstance(members, list) or not all(isinstance(value, str) for _, value in members):
            raise ValueError("it isn't an object of strings")
    except Exception as error:  # noqa: BLE001 - reported as the check's failure
        checks.fail(f"pipeline: parsing {JSON_SECRETS_FILE} to tamper with it: {describe(error)}")
        return
    if len(members) < 3:
        checks.fail(f"pipeline: {JSON_SECRETS_FILE} holds {len(members)} members, too few to tamper with")
        return
    untouched = members[-1][0]

    swapped = list(members)
    swapped[0], swapped[1] = (members[0][0], members[1][1]), (members[1][0], members[0][1])
    got, error = read_from_new_cache(write_members(work / "swapped.json", swapped), trust, ring, format_provider, untouched)
    checks.check(isinstance(error, AuthenticationTagMismatchError),
                 f"pipeline: {JSON_SECRETS_FILE} with two values swapped is refused whole: got {size(got)} bytes, {describe(error)}")

    tampered, tamper_error = attempt(lambda: tamper(members[0][1]))
    if tamper_error is not None:
        checks.fail(f"pipeline: tampering {members[0][0]}: {tamper_error}")
        return
    flipped = list(members)
    flipped[0] = (members[0][0], tampered)
    got, error = read_from_new_cache(write_members(work / "flipped.json", flipped), trust, ring, format_provider, untouched)
    checks.check(isinstance(error, AuthenticationTagMismatchError),
                 f"pipeline: {JSON_SECRETS_FILE} with a flipped tag bit is refused whole: got {size(got)} bytes, {describe(error)}")


def check_archive(checks: Checker, ring: KeyRing, fixtures: dict[str, Any], trust: KeyFileTrust, folder: Path, work: Path) -> None:
    """Unpacks secrets.tar with the system tar, from its standard input, into a fresh folder: it must
    hold exactly the files write_protected_secret_files wrote, byte for byte, each reading through a
    FilePerSecretCache as its value."""
    unpacked = work / PIPELINE_UNPACKED_DIR
    try:
        unpacked.mkdir(**({} if os.name == "nt" else {"mode": 0o700}))
        with open(folder / SECRETS_TAR, "rb") as archive:
            untar(unpacked, lambda destination: shutil.copyfileobj(archive, destination))
    except Exception as error:  # noqa: BLE001 - reported as the check's failure
        checks.fail(f"pipeline: unpacking {SECRETS_TAR}: {describe(error)}")
        return

    names = [s["fileName"] for s in fixtures["secrets"]]
    entries = sorted(os.listdir(unpacked))
    checks.check(entries == sorted(names), f"pipeline: {SECRETS_TAR} holds exactly the secrets' files: it holds {len(entries)}, not {len(names)}")

    files, error = attempt(lambda: FilePerSecretCache(unpacked, trust, ring, DefaultFormatProvider()))
    if error is not None:
        checks.fail(f"pipeline: opening the unpacked folder: {error}")
        return
    for s in fixtures["secrets"]:
        difference = compare_folders(folder / PIPELINE_FILES_DIR, unpacked, [s["fileName"]])
        got, error = attempt(lambda: read_cache(files, s["fileName"]))
        why = difference or f"got {size(got)} bytes, {error or 'wrong plaintext'}"
        checks.check(difference is None and error is None and got == s["plaintext"],
                     f"pipeline: {SECRETS_TAR}'s {s['fileName']} is the written file and reads as its value: {why}")


def tar_path() -> str:
    """The system tar: Windows' own bsdtar, else the tar on PATH."""
    if os.name == "nt":
        return str(Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "tar.exe")
    return "tar"


def untar(folder: Path, write: Callable[[IO[bytes]], object]) -> None:
    """Runs the system tar, with its arguments in a list and no shell, to unpack an archive from its
    standard input into ``folder``: ``write`` writes the archive, and the input is closed afterwards.
    The archive holds only encrypted values, so Popen's buffered pipe is fine here."""
    tar = subprocess.Popen([tar_path(), "-x", "--no-same-owner", "-f", "-", "-C", str(folder)],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        write(tar.stdin)
    finally:
        try:
            tar.stdin.close()
        finally:
            stdout, stderr = tar.communicate()
    if tar.returncode != 0:
        raise RuntimeError(f"tar exited {tar.returncode}: {(stdout + stderr).decode(errors='replace').strip()}")


def compare_folders(expected: Path, actual: Path, names: list[str]) -> str | None:
    """None if each named file in ``actual`` is the one in ``expected`` byte for byte, else what differs."""
    for name in names:
        path = actual / name
        if not path.is_file():
            return f"{name} is missing"
        try:
            if path.read_bytes() != (expected / name).read_bytes():
                return f"{name} differs"
        except OSError as error:
            return f"{name}: {describe(error)}"
    return None


def read_from_new_cache(path: Path, trust: KeyFileTrust, ring: KeyRing, format_provider: EncryptedFormatProvider,
                        name: str) -> tuple[str | None, Exception | None]:
    """A lookup through a new JsonSecretsFileReadOnlyCache over ``path``, so nothing an earlier cache
    loaded is reused: what it read, or the exception it raised."""
    try:
        return read_cache(JsonSecretsFileReadOnlyCache(path, trust, ring, format_provider), name), None
    except Exception as error:  # noqa: BLE001 - any failure is the answer being checked
        return None, error


def write_members(path: Path, members: list[tuple[str, str]]) -> Path:
    """Writes ``members`` as a JSON object, in their order. The layout is this driver's own: the cache
    reads any valid JSON object."""
    lines = [f"  {json.dumps(name, ensure_ascii=False)}: {json.dumps(value, ensure_ascii=False)}" for name, value in members]
    path.write_bytes(("{\n" + ",\n".join(lines) + "\n}").encode("utf-8"))
    return path


def describe(error: BaseException | None) -> str | None:
    return None if error is None else f"{type(error).__name__}: {error}"


def open_release(wrapper_name: str, service: str, directory: Path, stack: contextlib.ExitStack) -> tuple[dict[str, Any], KeyWrapper, KeyRing]:
    """Reads ``directory``'s release and builds a ring over its key file with this port of the
    release's wrapper; ``stack`` closes the ring, then the wrapper."""
    release = json.loads((directory / RELEASE_FILE).read_text(encoding="utf-8"))
    if release.get("wrapper") != wrapper_name:
        raise ValueError(f"the release was wrapped with {release.get('wrapper')!r}, not {wrapper_name!r}")
    wrapper = new_wrapper(wrapper_name, service, WRAP_CONTEXT, stack)
    try:
        ring = (KeyRingBuilder()
                .with_service_name(service)
                .with_key_wrapper(wrapper)
                .with_crypto_provider_factory(AesGcmCryptoProviderFactory())
                .with_key_refresh_interval(60)
                .with_key_file(release["keyVersion"], directory / KEY_FILE)
                .build())
    except Exception as error:
        raise RuntimeError(f"building the key ring: {type(error).__name__}: {error}") from error
    return release, wrapper, stack.enter_context(ring)


def check_cache(checks: Checker, protected: ProtectedCache, fixtures: dict[str, Any]) -> None:
    """Stores every fixture in a protected cache over the release's ring and reads it back: names that
    differ in ASCII case share an entry, names that differ in non-ASCII case don't, and an empty value,
    or a second value under an existing name, is refused."""
    for s in fixtures["secrets"]:
        # add zeroes the buffer it is given.
        _, error = attempt(lambda: protected.add(s["identifier"], bytearray(s["plaintext"].encode("utf-8"))))
        if s["plaintext"] == "":
            checks.check(error is not None and error.startswith("ValueError: An empty value"), f"cache: an empty {s['identifier']} is refused: {error}")
            continue
        if error is not None:
            checks.fail(f"cache: adding {s['identifier']}: {error}")
            continue
        for name in [s["identifier"], *s.get("alsoReadAs", [])]:
            got, error = attempt(lambda: read_cache(protected, name))
            checks.check(error is None and got == s["plaintext"], f"cache: {s['identifier']} reads as {name}: got {size(got)} bytes, {error}")
        for name in s.get("mustNotReadAs", []):
            got, error = attempt(lambda: read_cache(protected, name))
            checks.check(error is None and got == "", f"cache: {s['identifier']} is missing as {name}: got {size(got)} bytes, {error}")
        if s.get("alsoReadAs"):
            _, error = attempt(lambda: protected.add(s["alsoReadAs"][0], bytearray(b"again")))
            checks.check(error is not None and error.startswith("ValueError: ") and "already been added" in error,
                         f"cache: adding {s['identifier']} again as {s['alsoReadAs'][0]} is refused: {error}")


def read_cache(protected: ProtectedReadOnlyCache, name: str) -> str:
    """The value cached under ``name``, or "" if there is none."""
    length = protected.find_max_decrypted_length(name)
    if length is None:
        return ""
    result = bytearray(length)
    try:
        return result[:protected.decrypt(name, result)].decode("utf-8")
    finally:
        ArrayUtility.zero_memory(result)


def read_store(store: str, wrapper_name: str, service: str, directory: Path) -> bool:
    """Reads the secret the HKDFGUARD_TEST_* settings name for ``store`` through this port's cache over
    the release's key ring, and compares what it reads with the JSON object the settings say the
    secret holds. No value read is ever printed: a failure says only which check failed."""
    with contextlib.ExitStack() as stack:
        release, _, ring = open_release(wrapper_name, service, directory, stack)
        checks = Checker()
        if store == "awssecretsmanager":
            name, expected = secret_settings("HKDFGUARD_TEST_AWS_SECRET_NAME", "HKDFGUARD_TEST_AWS_SECRET_JSON")
            import botocore.session
            from hkdfguard.cache.awssecretsmanager import AwsSecretsManagerSecretCache

            client = botocore.session.get_session().create_client("secretsmanager")
            stack.callback(client.close)
            check_json_secret(checks, AwsSecretsManagerSecretCache(client, ring), name, expected)
        elif store == "azurekeyvault":
            secret_id, expected = secret_settings("HKDFGUARD_TEST_AZURE_SECRET_ID", "HKDFGUARD_TEST_AZURE_SECRET_JSON")
            vault, name = azure_secret_id(secret_id)
            from hkdfguard.cache.azurekeyvault import AzureKeyVaultSecretCache

            credential = azure_credential()
            stack.callback(credential.close)
            secrets = stack.enter_context(AzureKeyVaultSecretCache(vault, credential, ring))
            check_json_secret(checks, secrets, name, expected)
            # Key Vault matches secret names ignoring case, and so does its cache.
            got, error = attempt(lambda: read_cache(secrets, name.upper()))
            checks.check(error is None and holds(got, expected),
                         f"{store}: the secret's name in upper case reads the same secret: got {size(got)} bytes, {error}")
            if os.environ.get("HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS") == "true":
                for key in sorted(expected):
                    want, comparable = as_cached(expected[key])
                    if comparable:
                        got, error = attempt(lambda: read_cache(secrets, key))
                        checks.check(error is None and got == want, f"{store}: the secret {key} reads as expected: got {size(got)} bytes, {error}")
        elif store == "googlesecretmanager":
            resource, expected = secret_settings("HKDFGUARD_TEST_GOOGLE_SECRET_NAME", "HKDFGUARD_TEST_GOOGLE_SECRET_JSON")
            parts = resource.split("/")
            if len(parts) != 4 or parts[0] != "projects" or parts[2] != "secrets":
                raise ValueError("HKDFGUARD_TEST_GOOGLE_SECRET_NAME isn't projects/{project}/secrets/{secret}")
            from hkdfguard.cache.googlesecretmanager import GoogleSecretManagerSecretCache

            secrets = stack.enter_context(GoogleSecretManagerSecretCache.create(parts[1], ring))
            check_json_secret(checks, secrets, parts[3], expected)
        elif store == "hashicorpvault":
            name, expected = secret_settings("HKDFGUARD_TEST_VAULT_SECRET_NAME", "HKDFGUARD_TEST_VAULT_SECRET_JSON")
            token = setting("HKDFGUARD_TEST_VAULT_TOKEN")
            from hkdfguard.cache.hashicorpvault import HashiCorpVaultSecretCache, HashiCorpVaultSecretCacheOptions
            from hkdfguard.integration.hashicorpvault import StaticVaultToken

            # The cache holds the token only protected by the ring, and never follows a redirect: one
            # could send the token elsewhere.
            protector = ring.create_protector(HashiCorpVaultSecretCache.TOKEN_PURPOSE)
            provider = StaticVaultToken.protect(protector, token)
            del token
            options = HashiCorpVaultSecretCacheOptions(ssl_context=vault_ssl_context())
            secrets = stack.enter_context(HashiCorpVaultSecretCache(os.environ.get("HKDFGUARD_TEST_VAULT_ADDR") or "https://127.0.0.1:8200",
                                                                    provider, protector, ring, options=options))
            check_keys(checks, secrets, name.split("#", 1)[0], expected)
        else:
            raise ValueError(f"unknown store {store!r}")
        return checks.finish(f"{store} through the {release['producer']} {release['wrapper']} release's ring")


def check_json_secret(checks: Checker, secrets: ProtectedReadOnlyCache, name: str, expected: dict[str, Any]) -> None:
    """Checks a secret holding a JSON object: read whole, it holds the expected members, and each
    member reads as "name#key"."""
    got, error = attempt(lambda: read_cache(secrets, name))
    checks.check(error is None and holds(got, expected), f"the whole secret holds the expected members: got {size(got)} bytes, {error}")
    check_keys(checks, secrets, name, expected)


def check_keys(checks: Checker, secrets: ProtectedReadOnlyCache, name: str, expected: dict[str, Any]) -> None:
    """Checks each expected member reads as "name#key", and that a key matches only exactly."""
    keys = sorted(expected)
    for key in keys:
        want, comparable = as_cached(expected[key])
        if comparable:
            got, error = attempt(lambda: read_cache(secrets, f"{name}#{key}"))
            checks.check(error is None and got == want, f"#{key} reads as expected: got {size(got)} bytes, {error}")
    for key in keys:
        swapped = swap_ascii_case(key)
        if swapped != key and swapped not in expected:
            got, error = attempt(lambda: read_cache(secrets, f"{name}#{swapped}"))
            checks.check(error is None and got == "", f"#{key}, in another ASCII case, is missing: got {size(got)} bytes, {error}")
            break
    got, error = attempt(lambda: read_cache(secrets, f"{name}#{MISSING_KEY}"))
    checks.check(error is None and got == "", f"#{MISSING_KEY} is missing: got {size(got)} bytes, {error}")


class JsonNumber(str):
    """A JSON number as its exact text: json's parse_int and parse_float hooks keep it so."""


def parse_json(text: str) -> Any:
    return json.loads(text, parse_int=JsonNumber, parse_float=JsonNumber)


def as_cached(member: Any) -> tuple[str, bool]:
    """A member as every port's cache caches it: a string as its text, true or false as its JSON text.
    An integer is compared as its JSON text too; any other number, null, an object or an array isn't
    compared, since not every port's JSON reader keeps a number's exact text."""
    if isinstance(member, JsonNumber):
        return (str(member), True) if INTEGER.match(member) else ("", False)
    if isinstance(member, str):
        return member, True
    if member is True or member is False:
        return ("true" if member else "false"), True
    return "", False


def holds(value: str | None, expected: dict[str, Any]) -> bool:
    """Whether ``value`` is a JSON object with exactly the expected member names, each comparable
    member holding what's expected."""
    try:
        got = parse_json(value) if value is not None else None
    except ValueError:
        return False
    if not isinstance(got, dict) or len(got) != len(expected):
        return False
    for key, member in expected.items():
        if key not in got:
            return False
        want, comparable = as_cached(member)
        if comparable and as_cached(got[key])[0] != want:
            return False
    return True


def secret_settings(name_variable: str, json_variable: str) -> tuple[str, dict[str, Any]]:
    name = setting(name_variable)
    try:
        expected = parse_json(setting(json_variable))
    except ValueError:
        expected = None
    if not isinstance(expected, dict):
        raise ValueError(f"{json_variable} isn't a JSON object")
    return name, expected


def azure_secret_id(secret_id: str) -> tuple[str, str]:
    """Splits https://{vault}.vault.azure.net/secrets/{name} into the vault's URL and the secret's name."""
    invalid = ValueError("HKDFGUARD_TEST_AZURE_SECRET_ID isn't https://{vault}.vault.azure.net/secrets/{name}")
    try:
        url = urlsplit(secret_id)
    except ValueError:
        raise invalid from None
    parts = url.path.strip("/").split("/")
    if url.scheme != "https" or len(parts) != 2 or parts[0] != "secrets":
        raise invalid
    return f"https://{url.netloc}/", parts[1]


def swap_ascii_case(text: str) -> str:
    return "".join(c.swapcase() if c.isascii() else c for c in text)


def new_wrapper(name: str, service: str, context: str, stack: contextlib.ExitStack) -> KeyWrapper:
    """This port's wrapper named ``name``, over the KEK the HKDFGUARD_TEST_* settings name and bound to
    ``context``; the native one is over the service's KEK on this host. ``stack`` closes it and
    whatever client it was built over. A network wrapper reads key files only from where this account
    is trusted to have written them, since the matrix writes and reads them as one account (see
    key_file_trust). Each cloud SDK is imported only when its wrapper (or, in read_store, its cache)
    is used, so a run doesn't load every SDK."""
    if name == NATIVE:
        return NativeHkdfKeyWrapperV1(service)
    trust = key_file_trust()
    if name == "awskms":
        key = setting("HKDFGUARD_TEST_AWS_KMS_KEY_ID")
        import botocore.session
        from hkdfguard.keywrapping.awskms import AwsKmsKeyWrapper

        client = botocore.session.get_session().create_client("kms")
        stack.callback(client.close)
        return AwsKmsKeyWrapper(client, key, {"purpose": context}, key_file_trust=trust)
    if name == "azurekeyvault":
        wrap_key = setting("HKDFGUARD_TEST_AZURE_WRAP_KEY_ID")
        sign_key = setting("HKDFGUARD_TEST_AZURE_SIGN_KEY_ID")
        from hkdfguard.keywrapping.azurekeyvault import AzureKeyVaultKeyWrapper

        credential = azure_credential()
        stack.callback(credential.close)
        return stack.enter_context(AzureKeyVaultKeyWrapper(wrap_key, sign_key, credential, context, key_file_trust=trust))
    if name == "googlekms":
        key = setting("HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME")
        from google.cloud import kms
        from hkdfguard.keywrapping.googlekms import GoogleKmsKeyWrapper

        client = stack.enter_context(kms.KeyManagementServiceClient())
        return GoogleKmsKeyWrapper(client, key, context, key_file_trust=trust)
    if name == "hashicorpvault":
        key = setting("HKDFGUARD_TEST_VAULT_TRANSIT_KEY")
        token = setting("HKDFGUARD_TEST_VAULT_TOKEN")
        from hkdfguard.integration.hashicorpvault import StaticVaultTokenSource
        from hkdfguard.keywrapping.hashicorpvault import HashiCorpVaultTransitKeyWrapper, HashiCorpVaultTransitKeyWrapperOptions

        options = HashiCorpVaultTransitKeyWrapperOptions(mount_path=os.environ.get("HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT") or "transit",
                                                         ssl_context=vault_ssl_context())
        return stack.enter_context(HashiCorpVaultTransitKeyWrapper(os.environ.get("HKDFGUARD_TEST_VAULT_ADDR") or DEFAULT_VAULT_ADDRESS, key,
                                                                   StaticVaultTokenSource(token), context, key_file_trust=trust, options=options))
    raise ValueError(f"unknown wrapper {name!r}")


def azure_credential() -> Any:
    """azure-identity's default chain (az login on a developer host), without its shared token cache:
    Go's chain has none, and one unreadable cache file (an empty msal.cache.cae, say)
    makes it fail the whole chain rather than fall through to az login."""
    from azure.identity import DefaultAzureCredential

    return DefaultAzureCredential(exclude_shared_token_cache_credential=True)


def vault_ssl_context() -> ssl.SSLContext | None:
    """A context trusting the CA HKDFGUARD_TEST_VAULT_CACERT names, and only it, if set; otherwise
    None, for the system's trust store. VAULT_* variables are ignored."""
    ca_certificate = os.environ.get("HKDFGUARD_TEST_VAULT_CACERT")
    return ssl.create_default_context(cafile=ca_certificate) if ca_certificate else None


def key_file_trust() -> KeyFileTrust:
    """Trusts this account to have written the key files it reads, as well as Administrators (or
    root): the matrix writes and reads every key file as one account. Never trust an application's own
    account outside a test or developer host."""
    if os.name != "nt":
        return KeyFileTrust(unix_user_ids=[os.geteuid()])
    whoami = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "whoami.exe"
    output = subprocess.run([str(whoami), "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True).stdout
    sid = output.strip().rsplit(",", 1)[-1].strip().strip('"')
    if not sid.startswith("S-1-"):
        raise RuntimeError("whoami didn't print this account's SID")
    return KeyFileTrust(windows_principals=[sid])


def setting(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ValueError(f"{name} is not set")
    return value


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


def unwrapped_digest(wrapper: KeyWrapper, path: Path) -> str:
    wrapped = wrapper.read_key_file(path)
    raw = bytearray(WrappedKeyLimits.MAX_BYTES)
    try:
        written = wrapper.unwrap(wrapped, raw)
        return hashlib.sha256(raw[:written]).hexdigest()
    finally:
        ArrayUtility.zero_memory(raw)


def size(text: str | None) -> int:
    """The length in UTF-8 of a value read, the only thing a message says about it."""
    return len(text.encode("utf-8")) if text else 0


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

    def finish(self, what: str) -> bool:
        if self.failed:
            print(f"FAIL {self.failed} of {self.passed + self.failed} checks failed reading {what}", file=sys.stderr)
            return False
        print(f"OK {self.passed} checks passed reading {what}")
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["produce", "consume", "cache"])
    parser.add_argument("--wrapper", default=NATIVE, help="the key wrapper: native, awskms, azurekeyvault, googlekms or hashicorpvault")
    parser.add_argument("--store", help="the remote secret store to read (cache only)")
    parser.add_argument("--service", required=True)
    parser.add_argument("--fixtures", required=True, type=Path)
    parser.add_argument("--dir", required=True, type=Path)
    parser.add_argument("--cli")
    args = parser.parse_args()
    if args.command == "produce" and not args.cli:
        parser.error("produce needs --cli")
    if args.command == "cache" and not args.store:
        parser.error("cache needs --store")
    try:
        fixtures = json.loads(args.fixtures.read_text(encoding="utf-8"))
        if args.command == "produce":
            produce(args.wrapper, args.service, fixtures, args.dir, args.cli)
            return 0
        if args.command == "cache":
            return 0 if read_store(args.store, args.wrapper, args.service, args.dir) else 1
        return 0 if consume(args.wrapper, args.service, fixtures, args.dir) else 1
    except Exception as error:  # noqa: BLE001 - reported, then a failing exit code
        print(f"FAIL {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
