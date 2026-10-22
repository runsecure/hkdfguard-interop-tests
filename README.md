# hkdfguard-interop-tests

Cross-language tests for HkdfGuard. A release written by one port must be readable by every other
port on the same host. A release is a set of pipeline-encrypted secrets plus the key file wrapped
by the native `hkdfguard` tool.

Each port's own repository already tests its pipeline, wrap and read path in that one language.
This repository tests what no single port can: that Go, Node and Python pipelines produce values and
key files that .NET, Go, Java, Node and Python applications all read.

```
producer (go | node | python)                  consumer (dotnet | go | java | node | python)
------------------------------------------     ----------------------------------------------
pipeline protector generates a 32-byte DEK
encrypts every fixture -> release.json   ───>  builds a KeyRing over the native KEK + key file
hkdfguard wrap --dek-stdin -> dek.wrapped      reveals every value under its configuration purpose
                                               runs the negative checks
                                               unwraps dek.wrapped, compares the DEK's hash
```

## Running it

You need the HkdfGuard native package installed and a provisioned test service. Every port's
provisioning script creates `com.hkdfguard.integration.test.221`, which is the default. Set
`HKDFGUARD_TEST_SERVICE` or pass `--service` to use another.

Check out the ports as siblings of this repository. The drivers build against those checkouts:

```
HkdfGuard/
  hkdfguard-dotnet/  hkdfguard-go/  hkdfguard-java/  hkdfguard-node/  hkdfguard-python/
  hkdfguard-interop-tests/
```

Toolchains: .NET 10 SDK, Go (the version in `drivers/go/go.mod`), JDK 25 or later, Node 22 or later,
and [uv](https://docs.astral.sh/uv/). Then:

```sh
python scripts/run_matrix.py                 # build every driver, then run the full matrix
python scripts/run_matrix.py --skip-build    # reuse the last build
python scripts/run_matrix.py --producers node --consumers java,dotnet
python scripts/run_matrix.py --keep          # keep the releases folder to inspect
```

The script prints a producer × consumer grid and exits 1 if any cell fails, with each failing driver's
output after the grid:

| producer \ consumer | dotnet | go | java | node | python |
| --- | :---: | :---: | :---: | :---: | :---: |
| go | pass | pass | pass | pass | pass |
| node | pass | pass | pass | pass | pass |
| python | pass | pass | pass | pass | pass |

The native tool defaults to `C:\Program Files\HkdfGuard\v1\hkdfguard.exe` on Windows and `hkdfguard`
on `PATH` elsewhere; set `HKDFGUARD_CLI` or pass `--cli` to change it. Releases go in a fresh folder
the native library accepts key files from: on Windows, the temp folder by its long path; on Linux, a
private folder under `$XDG_RUNTIME_DIR` or `~/.cache`, never `/tmp`. The folder is removed afterwards
unless you pass `--keep`.

## What each consumer checks

Every secret in [fixtures/secrets.json](fixtures/secrets.json) is checked, 13 checks per release:

- Each value decrypts to its fixture's plaintext under its key's configuration purpose. That
  includes an empty value, non-ASCII text and emoji, and a 3,000-byte value close to the
  4,096-character format limit.
- `alsoReadAs`: keys that differ only in ASCII case read the same value.
- `mustNotReadAs`: keys that differ in non-ASCII case (`Café` vs `CAFÉ`) fail authentication.
- A value moved under another key fails authentication.
- A value with one bit of its GCM tag flipped fails authentication.
- The key file, unwrapped directly through the native wrapper, gives the same DEK the producer
  generated. The producer records a SHA-256 of its DEK in `release.json` for this check. That is
  acceptable only because these are throwaway test keys.

## The driver contract

Each driver lives in `drivers/<language>` and takes the same arguments:

```
produce --service S --fixtures F --dir D --cli PATH
consume --service S --fixtures F --dir D
```

`produce` writes two files to `D`:
- `release.json`, holding `producer`, `service`, `keyVersion`, `dekSha256` and `values` (identifier
  to `enc::v<version>::<base64>`)
- `dek.wrapped`, the key file

The producer creates the key file by piping the pipeline key's base64 to
`hkdfguard wrap -kf D/dek.wrapped -sn S --dek-stdin`, never as an argument or environment variable.

`consume` prints `FAIL <check>` for each failed check and ends with one `OK …` or `FAIL …` line.

Exit codes for both:

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | A check failed |
| 2 | Usage error |

Producers today are Go, Node and Python. To add .NET or Java as a producer, implement `produce` in
that driver and add the language to `PRODUCERS` in [scripts/run_matrix.py](scripts/run_matrix.py).

## Develop or published packages

The drivers reference the sibling checkouts: Go `replace` directives, Node `file:` links, uv path
sources, .NET `ProjectReference`s, and the Java `1.0.0-SNAPSHOT` that `mvnw install` puts in the
local repository. To test published packages instead, replace those references with version numbers.
Each driver's manifest says where.

## CI

[.github/workflows/interop.yml](.github/workflows/interop.yml) checks out every port side by side at
one ref (default `develop`) and runs the matrix. Key files only open on the host that wrapped them,
so the whole matrix runs in one job. That job needs a self-hosted runner labelled `hkdfguard-interop`
with the native package installed and the test service provisioned. If the port repositories are
private, also add a `HKDFGUARD_PORTS_TOKEN` secret that can read them. The workflow is
manual-dispatch only until such a runner exists.
