# hkdfguard-interop-tests

Cross-language tests for HkdfGuard. A release written by one port must be readable by every other
port. A release is a set of pipeline-encrypted secrets plus the key file holding their DEK, wrapped
by one of five key wrappers:

| Wrapper | KEK | Key file written by |
| --- | --- | --- |
| `native` | The service's KEK in this host's TPM, Secure Enclave or Platform Crypto Provider | The native `hkdfguard wrap` tool |
| `awskms` | A symmetric AWS KMS key | The producer's `AwsKmsKeyWrapper` |
| `azurekeyvault` | An RSA wrapping key and an EC P-256 signing key in Azure Key Vault | The producer's `AzureKeyVaultKeyWrapper` |
| `googlekms` | A symmetric Google Cloud KMS key | The producer's `GoogleKmsKeyWrapper` |
| `hashicorpvault` | A HashiCorp Vault transit key | The producer's `HashiCorpVaultTransitKeyWrapper` |

Each port's own repository already tests its pipeline, its wrappers and its caches in that one
language. This repository tests what no single port can: that a key file any port wraps under a
network KEK, with the same context, unwraps in every other port (the ports promise byte-for-byte
identical formats), and that every port's caches agree on the same names, values and refusals.

```
producer (dotnet | go | java | node | python)   consumer (dotnet | go | java | node | python)
-------------------------------------------     -------------------------------------------------
pipeline protector generates a 32-byte DEK
encrypts every fixture -> release.json    ───>  builds a KeyRing over its own port of the wrapper
encrypts each file fixture for its name         reveals every value under its configuration purpose
  -> secrets/<name>, one file per secret        runs the negative checks
wraps the DEK -> dek.wrapped                    unwraps dek.wrapped, compares the DEK's hash
  native: hkdfguard wrap --dek-stdin            refuses dek.wrapped under another context
  others: the port's wrapper, in process        caches every value in a ProtectedCache over the ring
                                                reads secrets/ through a FilePerSecretCache over it
                                         ───>  cache: reads each remote secret store through its
                                                own port of that store's cache, over the same ring
```

## Running it

Check out the ports as siblings of this repository. The drivers build against those checkouts:

```
HkdfGuard/
  hkdfguard-dotnet/  hkdfguard-go/  hkdfguard-java/  hkdfguard-node/  hkdfguard-python/
  hkdfguard-interop-tests/
```

Toolchains: .NET 10 SDK, Go (the version in `drivers/go/go.mod`), JDK 25 or later, Node 22 or later,
and [uv](https://docs.astral.sh/uv/). Then:

```sh
python scripts/run_matrix.py                 # build every driver, then every configured wrapper and cache
python scripts/run_matrix.py --skip-build    # reuse the last build
python scripts/run_matrix.py --producers node --consumers java,dotnet
python scripts/run_matrix.py --wrappers native,awskms --caches ''
python scripts/run_matrix.py --keep          # keep the releases folder to inspect
```

The script prints a producer × consumer grid for each wrapper and a store × consumer grid for the
remote caches, and exits 1 if any cell fails, with each failing driver's output after the grids:

```
#### awskms

| producer \ consumer | dotnet | go | java | node | python |
| --- | :---: | :---: | :---: | :---: | :---: |
| dotnet | pass | pass | pass | pass | pass |
| go | pass | pass | pass | pass | pass |
| ...

#### remote caches

| store \ consumer | dotnet | go | java | node | python |
| --- | :---: | :---: | :---: | :---: | :---: |
| awssecretsmanager | pass | pass | pass | pass | pass |
| ...
```

### Which wrappers and caches run

By default the matrix runs `native` and every network wrapper and remote cache whose settings are
present, and prints a `skip …` line, naming the missing settings, for each one that isn't. A skipped
wrapper or cache is never reported as passed. Name them with `--wrappers` and `--caches` to require
them: a missing setting is then an error.

The settings are the `HKDFGUARD_TEST_*` variables every port's own integration tests read, so set
up each service as that port's how-to describes (for example `hkdfguard-dotnet/docs/how-to/`), then
either export the variables or pass the files you already have. `--settings` reads a .NET
`.runsettings` file or a `NAME=value` `.test.properties` file, is repeatable, and never overrides
the environment:

```sh
python scripts/run_matrix.py \
  --settings ../hkdfguard-dotnet/aws.runsettings --settings ../hkdfguard-dotnet/azure.runsettings \
  --settings ../hkdfguard-dotnet/google.runsettings --settings ../hkdfguard-dotnet/vault.runsettings
```

| Runs | Needs |
| --- | --- |
| `native` | The HkdfGuard native package and the test service (below) |
| `awskms` | `HKDFGUARD_TEST_AWS_KMS_KEY_ID`, and AWS credentials and region through the SDKs' default chain |
| `azurekeyvault` | `HKDFGUARD_TEST_AZURE_WRAP_KEY_ID`, `HKDFGUARD_TEST_AZURE_SIGN_KEY_ID`, and `az login` |
| `googlekms` | `HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME`, and `gcloud auth application-default login` |
| `hashicorpvault` | `HKDFGUARD_TEST_VAULT_TRANSIT_KEY`, `HKDFGUARD_TEST_VAULT_TOKEN`; optionally `HKDFGUARD_TEST_VAULT_ADDR` (default `http://127.0.0.1:8200`), `HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT` (default `transit`), `HKDFGUARD_TEST_VAULT_CACERT` |
| `awssecretsmanager` cache | `HKDFGUARD_TEST_AWS_SECRET_NAME`, `HKDFGUARD_TEST_AWS_SECRET_JSON` |
| `azurekeyvault` cache | `HKDFGUARD_TEST_AZURE_SECRET_ID`, `HKDFGUARD_TEST_AZURE_SECRET_JSON`; optionally `HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS=true` |
| `googlesecretmanager` cache | `HKDFGUARD_TEST_GOOGLE_SECRET_NAME`, `HKDFGUARD_TEST_GOOGLE_SECRET_JSON` |
| `hashicorpvault` cache | `HKDFGUARD_TEST_VAULT_SECRET_NAME`, `HKDFGUARD_TEST_VAULT_SECRET_JSON`, `HKDFGUARD_TEST_VAULT_TOKEN`; optionally `HKDFGUARD_TEST_VAULT_ADDR` (default `https://127.0.0.1:8200`), `HKDFGUARD_TEST_VAULT_CACERT` |

Every wrapper binds its key files to the context `hkdfguard.integrationtest` (for AWS, the
encryption context `purpose` = `hkdfguard.integrationtest`), the one the ports' own integration
tests use, so the matrix runs under the key, IAM and token policies already written for them. The
caches are read-only: the matrix never creates, changes or deletes a key or a secret.

> **Security:** the matrix passes settings to the drivers' environment only and never prints them,
> nor any value it reads from a secret store. Keep tokens and access keys out of the settings files
> as each port's how-to says: credentials come from the SDKs' own chains (`aws configure`,
> `az login`, `gcloud auth application-default login`). The one exception is the short-lived Vault
> dev-server token, which those how-tos put in `vault.runsettings`.

### The native wrapper

You need the HkdfGuard native package installed and a provisioned test service. Every port's
provisioning script creates `com.hkdfguard.integration.test.221`, which is the default. Set
`HKDFGUARD_TEST_SERVICE` or pass `--service` to use another. Leave `native` out of `--wrappers` to
run the network wrappers on a host without it.

The matrix runs every role as one account: it wraps key files and then reads them back. The native
library's default **production** security model refuses exactly that, by design: an application may
not read a key file it could have written itself. So run the matrix on a development or CI host in
the **developer** model:

- **Windows:** `SecurityModel` = `1` under `HKLM\Software\Policies\HkdfGuard`. Each driver process
  then logs event 1005 when it reads a key file, which is expected here.
- **Linux:** `security_model = "developer"` in `/etc/hkdfguard/policy.toml`.

Never switch a production host to the developer model to make these tests pass. Under the
production model the matrix can only run as a deployer writing to a deployer-owned folder, which
is a different test.

The network wrappers apply the same rule in each port's own code: by default they read a key file
only if Administrators (or root) alone could have written it. Each driver passes a `KeyFileTrust`
naming its own account (its SID on Windows, its uid elsewhere), which is acceptable only on a test or
developer host. **Never trust an application's own account in production.**

The native tool defaults to `C:\Program Files\HkdfGuard\v1\hkdfguard.exe` on Windows and `hkdfguard`
on `PATH` elsewhere; set `HKDFGUARD_CLI` or pass `--cli` to change it. Releases go in a fresh folder
every wrapper accepts key files from. On Windows that is a folder made under the temp folder by its
long path, inheriting its ACL: `tempfile.mkdtemp`'s owner-only ACL is refused by the network
wrappers. On Linux it is a private folder under `$XDG_RUNTIME_DIR` or `~/.cache`, never `/tmp`. The
folder is removed afterwards unless you pass `--keep`.

## What each consumer checks

Every secret in [fixtures/secrets.json](fixtures/secrets.json) is checked, 33 checks per native
release and 34 per network one:

- Each value decrypts to its fixture's plaintext under its key's configuration purpose. That
  includes an empty value, non-ASCII text and emoji, and a 3,000-byte value close to the
  4,096-character format limit.
- `alsoReadAs`: keys that differ only in ASCII case read the same value.
- `mustNotReadAs`: keys that differ in non-ASCII case (`Café` vs `CAFÉ`) fail authentication.
- A value moved under another key fails authentication.
- A value with one bit of its GCM tag flipped fails authentication.
- The key file, read and unwrapped directly through the consumer's wrapper, gives the same DEK the
  producer generated. The producer records a SHA-256 of its DEK in `release.json` for this check.
- Network wrappers only: the key file is refused by the same wrapper bound to another context,
  `hkdfguard.integrationtest.other`.
- Then every value is added to a `ProtectedCache` over the release's key ring and read back. Each
  reads under its identifier and its `alsoReadAs` names (the cache ignores ASCII case), and is
  missing under its `mustNotReadAs` names. The empty value is refused, since a cache reports a
  missing name as 0 bytes, and adding a value again under another ASCII case is refused.
- Last, the release's `secrets/` folder is read through a `FilePerSecretCache` over the same ring,
  trusting the consumer's own account as the network wrappers do. Each file in the fixtures' `files`
  must be what its `expect` says. `value`: a file encrypted for its own name reads as its plaintext,
  including one with a trailing newline, non-ASCII text, and the 3,000-byte value. `missing`: an
  empty file, and a file whose name starts with `.`, which is no secret's name. `refused`: a copy of
  another secret's file fails authentication, since every value is bound to its file name. Each of
  `missingFiles`, names no file can answer such as `ConnectionStrings:Admin` and `../release.json`,
  is missing without anything outside the folder being read.

**Don't copy the DEK hash into a real pipeline.** Nothing derived from a DEK belongs beside its
key file: a hash lets anyone holding the file confirm a guessed or leaked key, and it tells an
attacker which key a stolen copy belongs to. It's acceptable here only because each run's DEK is
random, used once, and deleted with the releases folder.

### Remote caches

Each consumer then reads each configured secret store through its own port of that store's cache,
over the key ring of a release it read, and compares what it reads with the store's
`HKDFGUARD_TEST_*_SECRET_JSON`, the JSON object the secret is expected to hold:

- AWS Secrets Manager, Azure Key Vault and Google Secret Manager: the secret, read whole, is a JSON
  object with exactly the expected members. Each member reads as `name#key`.
- HashiCorp Vault: each expected key of the KV secret at `HKDFGUARD_TEST_VAULT_SECRET_NAME`'s path
  reads as `path#key`.
- Every store: a key in another ASCII case, and a key the secret doesn't hold, are missing (keys
  match exactly).
- Azure Key Vault only: the secret's name in upper case reads the same secret (Key Vault ignores
  case in names), and with `HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS=true`, each member also reads as a
  secret of its own, named by its key.

A string member is compared as its text, and `true`, `false` or an integer as its JSON text, the
way every port caches them. Other numbers, `null`, objects and arrays aren't compared member by
member, since not every port's JSON reader keeps a number's exact text.

## The driver contract

Each driver lives in `drivers/<language>` and takes the same arguments. `--wrapper` is one of
`native` (the default), `awskms`, `azurekeyvault`, `googlekms` or `hashicorpvault`; `--store` is
one of `awssecretsmanager`, `azurekeyvault`, `googlesecretmanager` or `hashicorpvault`:

```
produce [--wrapper W] --service S --fixtures F --dir D --cli PATH
consume [--wrapper W] --service S --fixtures F --dir D
cache --store C [--wrapper W] --service S --fixtures F --dir D
```

`produce` writes these to `D`, which the matrix creates first:
- `release.json`, holding `producer`, `wrapper`, `service`, `keyVersion`, `dekSha256` and `values`
  (identifier to `enc::v<version>::<base64>`)
- `dek.wrapped`, the key file
- `secrets/`, one file per entry of the fixtures' `files`, named by its `name`. It holds, encrypted
  by the same pipeline protector for that name, its `plaintext` or the `plaintext` of the secret
  `plaintextOf` names, followed by a newline when `trailingNewline` is set. If `empty` is set the file
  is empty, and if `copyOf` is set it is a byte-for-byte copy of that earlier file. On Windows,
  create the folder without an owner-only ACL, as the matrix does for `D`.

For `native`, the producer creates the key file by piping the pipeline key's base64 to
`hkdfguard wrap -kf D/dek.wrapped -sn S --dek-stdin`, never as an argument or environment variable.
For every other wrapper, it decodes the pipeline key, wraps it with its own port of the wrapper,
writes the wrapped bytes as the key file and zeroes its copy of the key.

`consume` refuses a release whose `wrapper` isn't its `--wrapper`. `cache` builds its key ring over
`D`'s release exactly as `consume` does. Each wrapper and cache is built from the settings above,
with credentials from the SDK's default chain. Every network wrapper is given a `KeyFileTrust`
naming the driver's own account.

`consume` and `cache` print `FAIL <check>` for each failed check and end with one `OK …` or
`FAIL …` line. Neither prints a value it decrypts or reads.

Exit codes for all three:

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | A check failed |
| 2 | Usage error |

## Develop or published packages

The drivers reference the sibling checkouts: Go `replace` directives, Node `file:` links, uv path
sources, .NET `ProjectReference`s, and the Java `0.9.1` that `mvnw install` puts in the
local repository. To test published packages instead, replace those references with version numbers.
Each driver's manifest says where.

Third-party dependencies are pinned by committed lockfiles: `drivers/go/go.sum`,
`drivers/node/package-lock.json`, `drivers/python/uv.lock` and `drivers/dotnet/packages.lock.json`.
The matrix installs with `npm ci`, `uv sync --locked` and `dotnet restore --locked-mode`, which fail
rather than re-resolve when a lockfile no longer matches its manifest. When a port adds or changes a
dependency, refresh the lockfile on purpose and review the diff: `npm install` in `drivers/node`,
`uv lock --project drivers/python`, `go mod tidy` in `drivers/go`, or
`dotnet restore drivers/dotnet/HkdfGuard.Interop.csproj --force-evaluate`.

## CI

[.github/workflows/interop.yml](.github/workflows/interop.yml) checks out every port side by side at
one ref (default `develop`) and runs the matrix. Key files only open on the host that wrapped them,
so the whole matrix runs in one job. That job needs a self-hosted runner labelled `hkdfguard-interop`
with the native package installed and the test service provisioned. The workflow is manual-dispatch
only until such a runner exists.

The job builds and runs five other repositories' code, at a ref the caller chooses, on a host that
holds a KEK. Set it up so that code is never trusted more than it has to be:

- **Register the runner with `--ephemeral`**, so each job gets a fresh runner and nothing a build
  leaves behind (`~/.m2`, caches, a modified toolchain) reaches the next one. Give the host no other
  job and no other service's KEK: the test KEK is the only one it should ever hold.
- **Create the `hkdfguard-interop` environment** in this repository's settings with a
  required-reviewers rule. The job runs inside it, so every dispatch waits for a reviewer, and the
  secrets below exist only for that job.
- **If the port repositories are private**, add `HKDFGUARD_PORTS_TOKEN` to that environment: a
  fine-grained token with read-only *Contents* on the five port repositories and nothing else. The
  workflow hands it to the checkout steps only and no checkout keeps it in `.git/config`, so the
  ports' build scripts never see it. Public ports need no token.
- **Optionally set the `HKDFGUARD_TEST_SERVICE` variable** if the runner's test KEK is not
  `com.hkdfguard.integration.test.221`.
- **To run the network wrappers and caches**, set their `HKDFGUARD_TEST_*` settings (see
  [Which wrappers and caches run](#which-wrappers-and-caches-run)) as variables of the
  `hkdfguard-interop` environment. They are key and secret identifiers, not credentials. Sign the
  runner host in to each cloud through its SDK's own chain, with an identity that holds only the
  test policies from each port's how-to: an instance role or IAM Roles Anywhere for AWS, a managed
  identity for Azure, a service account for Google. Never store a cloud credential in the
  repository or its secrets. The workflow passes no Vault settings: a Vault token is a credential,
  and a dev server's lasts a day.

The `ref` input must be a branch or tag name. The workflow refuses pull-request refs
(`refs/pull/N/head` is where a fork's PR lands in the base repository) and bare commit SHAs (a
fork's PR commits are fetchable by SHA), because either would run a contributor's build scripts on
the KEK host. To test a contributor's change, merge it to a branch first.
