"""The Python driver for the HkdfGuard interop matrix: it produces a release (pipeline encryption plus a
key file wrapped by one key wrapper), consumes any driver's release with its own port of the same
wrapper, and reads a remote secret store through its cache over that release's key ring. See the
repository README for the contract every driver follows."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import re
import ssl
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from hkdfguard.abstractions import ArrayUtility, KeyWrapper, ProtectedConfigurationPurpose, ProtectedReadOnlyCache, WrappedKeyLimits
from hkdfguard.cache import ProtectedCache
from hkdfguard.cryptoprovider.aesgcm256 import AesGcmCryptoProviderFactory, AesGcmPipelineDataProtector
from hkdfguard.dataencryptionkey import DefaultFormatProvider, KeyRing, KeyRingBuilder
from hkdfguard.keywrapping.v1 import NativeHkdfKeyWrapperV1
from hkdfguard.securefile import KeyFileTrust

RELEASE_FILE = "release.json"
KEY_FILE = "dek.wrapped"
KEY_SIZE = 32
FORMAT = re.compile(r"^(enc::v\d+::)(.+)$", re.DOTALL)

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
    values, and wraps the key into the key file - by handing it to the native tool on standard input,
    or through a network key wrapper in this process."""
    pipeline = AesGcmPipelineDataProtector(DefaultFormatProvider(), fixtures["keyVersion"])
    raw = bytearray(KEY_SIZE)
    try:
        values = {s["identifier"]: pipeline.encrypt(s["plaintext"], s["identifier"]) for s in fixtures["secrets"]}

        # Test only: a hash of the DEK, so every consumer can prove it unwrapped this same key. Never
        # record anything derived from a DEK beside its key file in a real pipeline. Decoding also
        # leaves the DEK in an immutable bytes object that can't be zeroed, as every base64 decode in
        # CPython does; acceptable for a throwaway test key only.
        key_base64 = pipeline.get_key_as_base64()
        raw[:] = base64.b64decode(key_base64)
        dek_sha256 = hashlib.sha256(raw).hexdigest()

        # The matrix creates the folder, so this is a no-op there. Never with mode 0o700 on Windows:
        # Python 3.13+ gives such a folder an owner-only protected ACL, which the network wrappers'
        # key file checks refuse.
        directory.mkdir(**({} if os.name == "nt" else {"mode": 0o700}), parents=True, exist_ok=True)
        path = directory / KEY_FILE
        if wrapper_name == NATIVE:
            # The protector's own read-only view goes to stdin as it is: no copy of the key is made here.
            wrap = subprocess.run([cli, "wrap", "-kf", str(path), "-sn", service, "--dek-stdin"],
                                  input=key_base64, capture_output=True)
            if wrap.returncode != 0:
                output = (wrap.stdout + wrap.stderr).decode(errors="replace").strip()
                raise RuntimeError(f"hkdfguard wrap exited {wrap.returncode}: {output}")
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
        print(f"OK produced {len(values)} secrets in {directory}")
    finally:
        ArrayUtility.zero_memory(raw)
        pipeline.close()


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
        return checks.finish(f"the {release['producer']} {release['wrapper']} release")


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
