'use strict';
// The Node.js driver for the HkdfGuard interop matrix: it produces a release (pipeline encryption plus
// a key file wrapped by one key wrapper), consumes any driver's release with its own port of the same
// wrapper, and reads a remote secret store through its cache over that release's key ring. See the
// repository README for the contract every driver follows.

const { execFileSync, spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { parseArgs } = require('node:util');
const { KMSClient } = require('@aws-sdk/client-kms');
const { SecretsManagerClient } = require('@aws-sdk/client-secrets-manager');
const { DefaultAzureCredential } = require('@azure/identity');
const { KeyManagementServiceClient } = require('@google-cloud/kms');
const { AlreadyExistsError, configurationPurpose, MAX_WRAPPED_KEY_BYTES, wipe } = require('@runsecure/hkdfguard-abstractions');
const { EmptyValueError, ProtectedCache } = require('@runsecure/hkdfguard-cache');
const { AwsSecretsManagerSecretCache } = require('@runsecure/hkdfguard-cache-awssecretsmanager');
const { AzureKeyVaultSecretCache } = require('@runsecure/hkdfguard-cache-azurekeyvault');
const { GoogleSecretManagerSecretCache } = require('@runsecure/hkdfguard-cache-googlesecretmanager');
const { HashiCorpVaultSecretCache, StaticVaultToken } = require('@runsecure/hkdfguard-cache-hashicorpvault');
const { AesGcmCryptoProviderFactory, AesGcmPipelineDataProtector, KEY_SIZE } = require('@runsecure/hkdfguard-cryptoprovider-aesgcm256');
const { buildKeyRing, DefaultFormatProvider } = require('@runsecure/hkdfguard-dek');
const { AwsKmsKeyWrapper } = require('@runsecure/hkdfguard-keywrapping-awskms');
const { AzureKeyVaultKeyWrapper } = require('@runsecure/hkdfguard-keywrapping-azurekeyvault');
const { GoogleKmsKeyWrapper } = require('@runsecure/hkdfguard-keywrapping-googlekms');
const { HashiCorpVaultTransitKeyWrapper, StaticVaultTokenSource } = require('@runsecure/hkdfguard-keywrapping-hashicorpvault');
const { NativeKeyWrapperV1 } = require('@runsecure/hkdfguard-keywrapping-native-v1');
const { KeyFileTrust } = require('@runsecure/hkdfguard-securefile');

const RELEASE_FILE = 'release.json';
const KEY_FILE = 'dek.wrapped';
const FORMAT = /^(enc::v\d+::)(.+)$/s;
const NATIVE = 'native';

// The context every port's integration tests bind their key files to, so the matrix runs under the
// IAM, key and token policies already written for those tests.
const WRAP_CONTEXT = 'hkdfguard.integrationtest';
// The one those tests check a key file is refused under.
const OTHER_CONTEXT = 'hkdfguard.integrationtest.other';

const DEFAULT_VAULT_ADDRESS = 'http://127.0.0.1:8200';
const DEFAULT_VAULT_CACHE_ADDRESS = 'https://127.0.0.1:8200';

// A key no test secret holds.
const MISSING_KEY = 'hkdfguard-interop-missing';
const INTEGER = /^-?[0-9]{1,15}$/;

function usage() {
  console.error('usage: interop.cjs produce [--wrapper W] --service S --fixtures F --dir D --cli PATH');
  console.error('       interop.cjs consume [--wrapper W] --service S --fixtures F --dir D');
  console.error('       interop.cjs cache --store C [--wrapper W] --service S --fixtures F --dir D');
  process.exit(2);
}

/**
 * Does what a release pipeline does: encrypts every fixture under a fresh pipeline key, writes the
 * values, and wraps the key into the key file - by handing it to the native tool on standard input,
 * or through a network key wrapper in this process.
 */
async function produce(wrapperName, service, fixtures, dir, cli) {
  const pipeline = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), fixtures.keyVersion);
  const raw = new Uint8Array(KEY_SIZE);
  try {
    const encoder = new TextEncoder();
    const values = Object.fromEntries(fixtures.secrets.map((s) => [s.identifier, pipeline.encrypt(encoder.encode(s.plaintext), s.identifier)]));

    // Test only: a hash of the DEK, so every consumer can prove it unwrapped this same key. Never
    // record anything derived from a DEK beside its key file in a real pipeline. Node has no
    // buffer-to-buffer base64 decode, so the key also passes through an immutable string that can't
    // be zeroed; acceptable for a throwaway test key only. The tool itself gets the base64 buffer.
    const base64 = pipeline.keyBase64();
    const n = Buffer.from(Buffer.from(base64.buffer, base64.byteOffset, base64.byteLength).toString('latin1'), 'base64').copy(raw);
    if (n !== KEY_SIZE) throw new Error(`decoding the pipeline key: ${n} bytes`);
    const dekSha256 = createHash('sha256').update(raw).digest('hex');

    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const path = join(dir, KEY_FILE);
    if (wrapperName === NATIVE) {
      const wrap = spawnSync(cli, ['wrap', '-kf', path, '-sn', service, '--dek-stdin'], { input: base64 });
      if (wrap.error) throw wrap.error;
      if (wrap.status !== 0) throw new Error(`hkdfguard wrap exited ${wrap.status}: ${`${wrap.stdout}${wrap.stderr}`.trim()}`);
    } else {
      const w = newWrapper(wrapperName, service, WRAP_CONTEXT);
      try {
        const wrapped = new Uint8Array(MAX_WRAPPED_KEY_BYTES);
        let length;
        try {
          length = await w.wrapper.wrap(raw, wrapped);
        } catch (error) {
          throw new Error(`wrapping the pipeline key: ${message(error)}`);
        }
        writeFileSync(path, wrapped.subarray(0, length), { mode: 0o600 });
      } finally {
        await w.close();
      }
    }

    const release = { producer: 'node', wrapper: wrapperName, service, keyVersion: fixtures.keyVersion, dekSha256, values };
    writeFileSync(join(dir, RELEASE_FILE), JSON.stringify(release, null, 2), { mode: 0o600 });
    console.log(`OK produced ${Object.keys(values).length} secrets in ${dir}`);
  } finally {
    wipe(raw);
    pipeline.close();
  }
}

/**
 * Reads a release as an application would: builds a ring over the wrapper's KEK with the key file,
 * then reveals every value through the configuration purpose of its key, and caches it.
 */
async function consume(wrapperName, service, fixtures, dir) {
  const { release, wrapper, ring } = await openRelease(wrapperName, service, dir);
  const checks = checker();
  try {
    for (const s of fixtures.secrets) {
      const value = release.values[s.identifier];
      if (value === undefined) {
        checks.fail(`${s.identifier}: missing from the release`);
        continue;
      }
      for (const name of [s.identifier, ...(s.alsoReadAs ?? [])]) {
        const { got, error } = await attempt(() => reveal(ring, name, value));
        checks.check(error === undefined && got === s.plaintext, `${s.identifier} reads as ${name}: ${error ?? `got ${got?.length} characters`}`);
      }
      for (const name of s.mustNotReadAs ?? []) {
        checks.check((await attempt(() => reveal(ring, name, value))).error !== undefined, `${s.identifier} must not read as ${name}`);
      }
    }

    const [first, second] = fixtures.secrets;
    checks.check((await attempt(() => reveal(ring, second.identifier, release.values[first.identifier]))).error !== undefined,
      `${first.identifier} moved under ${second.identifier} fails authentication`);
    checks.check((await attempt(() => reveal(ring, first.identifier, tamper(release.values[first.identifier])))).error !== undefined,
      `${first.identifier} with a flipped tag bit fails authentication`);

    const path = join(dir, KEY_FILE);
    const { got: digest, error: unwrapError } = await attempt(() => unwrappedDigest(wrapper.wrapper, path));
    checks.check(digest === release.dekSha256, `the key file unwraps to the producer's DEK: ${unwrapError ?? 'digest differs'}`);

    // A network KEK is shared by every application that may use it, so the context is what keeps
    // one application's key files from another's.
    if (wrapperName !== NATIVE) {
      const { got: other, error } = await attempt(() => newWrapper(wrapperName, service, OTHER_CONTEXT));
      if (error === undefined) {
        try {
          checks.check((await attempt(() => unwrappedDigest(other.wrapper, path))).error !== undefined, 'the key file is refused under another context');
        } finally {
          await other.close();
        }
      } else {
        checks.fail(`creating a wrapper with another context: ${error}`);
      }
    }

    await checkCache(checks, new ProtectedCache(ring), fixtures);
  } finally {
    await ring.close();
    await wrapper.close();
  }
  checks.finish(`the ${release.producer} ${release.wrapper} release`);
}

/**
 * Reads dir's release and builds a ring over its key file with this port of the release's wrapper.
 * The wrapper is returned with the ring, both the caller's to close.
 */
async function openRelease(wrapperName, service, dir) {
  const release = JSON.parse(readFileSync(join(dir, RELEASE_FILE), 'utf8'));
  if (release.wrapper !== wrapperName) {
    throw new Error(`the release was wrapped with ${JSON.stringify(release.wrapper)}, not ${JSON.stringify(wrapperName)}`);
  }
  const wrapper = newWrapper(wrapperName, service, WRAP_CONTEXT);
  try {
    const ring = await buildKeyRing({
      keyWrapper: wrapper.wrapper,
      cryptoProviderFactory: new AesGcmCryptoProviderFactory(),
      keyRefreshInterval: 60,
      keyFiles: { [release.keyVersion]: join(dir, KEY_FILE) },
    });
    return { release, wrapper, ring };
  } catch (error) {
    await wrapper.close();
    throw new Error(`building the key ring: ${message(error)}`);
  }
}

/**
 * Stores every fixture in a protected cache over the release's ring and reads it back: names that
 * differ in ASCII case share an entry, names that differ in non-ASCII case don't, and an empty value,
 * or a second value under an existing name, is refused.
 */
async function checkCache(checks, cache, fixtures) {
  const encoder = new TextEncoder();
  for (const s of fixtures.secrets) {
    const { error: added } = await attempt(() => cache.add(s.identifier, encoder.encode(s.plaintext)), true);
    if (s.plaintext === '') {
      checks.check(added instanceof EmptyValueError, `cache: an empty ${s.identifier} is refused: ${message(added)}`);
      continue;
    }
    if (added !== undefined) {
      checks.fail(`cache: adding ${s.identifier}: ${message(added)}`);
      continue;
    }
    for (const name of [s.identifier, ...(s.alsoReadAs ?? [])]) {
      const { got, error } = await attempt(() => readCache(cache, name));
      checks.check(error === undefined && got === s.plaintext, `cache: ${s.identifier} reads as ${name}: ${error ?? `got ${got?.length} characters`}`);
    }
    for (const name of s.mustNotReadAs ?? []) {
      const { got, error } = await attempt(() => readCache(cache, name));
      checks.check(error === undefined && got === '', `cache: ${s.identifier} is missing as ${name}: ${error ?? `got ${got?.length} characters`}`);
    }
    if ((s.alsoReadAs ?? []).length > 0) {
      const { error } = await attempt(() => cache.add(s.alsoReadAs[0], encoder.encode('again')), true);
      checks.check(error instanceof AlreadyExistsError, `cache: adding ${s.identifier} again as ${s.alsoReadAs[0]} is refused: ${message(error)}`);
    }
  }
}

/** The value cached under name, or '' if there is none. */
async function readCache(cache, name) {
  const size = await cache.maxDecryptedLength(name);
  if (size === undefined) return '';
  const result = new Uint8Array(size);
  try {
    const n = await cache.decrypt(name, result);
    return new TextDecoder('utf-8', { fatal: true }).decode(result.subarray(0, n));
  } finally {
    wipe(result);
  }
}

/**
 * Reads the secret the HKDFGUARD_TEST_* settings name for store through this port's cache over the
 * release's key ring, and compares what it reads with the JSON object the settings say the secret
 * holds. No value read is ever printed: a failure says only which check failed.
 */
async function readStore(store, wrapperName, service, dir) {
  const { release, wrapper, ring } = await openRelease(wrapperName, service, dir);
  const checks = checker();
  try {
    if (store === 'awssecretsmanager') {
      const { name, expected } = secretSettings('HKDFGUARD_TEST_AWS_SECRET_NAME', 'HKDFGUARD_TEST_AWS_SECRET_JSON');
      const client = new SecretsManagerClient({});
      try {
        await checkJsonSecret(checks, new AwsSecretsManagerSecretCache(client, ring), name, expected);
      } finally {
        client.destroy();
      }
    } else if (store === 'azurekeyvault') {
      const { name: id, expected } = secretSettings('HKDFGUARD_TEST_AZURE_SECRET_ID', 'HKDFGUARD_TEST_AZURE_SECRET_JSON');
      const { vaultUrl, name } = azureSecretId(id);
      const secrets = new AzureKeyVaultSecretCache(vaultUrl, new DefaultAzureCredential(), ring);
      await checkJsonSecret(checks, secrets, name, expected);
      // Key Vault matches secret names ignoring case, and so does its cache.
      const { got, error } = await attempt(() => readCache(secrets, name.toUpperCase()));
      checks.check(error === undefined && holds(got, expected),
        `${store}: the secret's name in upper case reads the same secret: ${error ?? `got ${got.length} characters`}`);
      if (process.env.HKDFGUARD_TEST_AZURE_SEPARATE_SECRETS === 'true') {
        for (const key of sortedKeys(expected)) {
          const want = asCached(expected[key]);
          if (want !== undefined) {
            const { got: member, error: failed } = await attempt(() => readCache(secrets, key));
            checks.check(failed === undefined && member === want,
              `${store}: the secret ${key} reads as expected: ${failed ?? `got ${member.length} characters`}`);
          }
        }
      }
    } else if (store === 'googlesecretmanager') {
      const { name: resource, expected } = secretSettings('HKDFGUARD_TEST_GOOGLE_SECRET_NAME', 'HKDFGUARD_TEST_GOOGLE_SECRET_JSON');
      const parts = resource.split('/');
      if (parts.length !== 4 || parts[0] !== 'projects' || parts[2] !== 'secrets') {
        throw new Error("HKDFGUARD_TEST_GOOGLE_SECRET_NAME isn't projects/{project}/secrets/{secret}");
      }
      const secrets = GoogleSecretManagerSecretCache.create(parts[1], ring);
      try {
        await checkJsonSecret(checks, secrets, parts[3], expected);
      } finally {
        await secrets.close();
      }
    } else if (store === 'hashicorpvault') {
      const { name, expected } = secretSettings('HKDFGUARD_TEST_VAULT_SECRET_NAME', 'HKDFGUARD_TEST_VAULT_SECRET_JSON');
      // The token is protected as soon as it is read, under the purpose the cache decrypts it with.
      const protector = ring.createProtector(HashiCorpVaultSecretCache.TOKEN_PURPOSE);
      const token = StaticVaultToken.protect(protector, setting('HKDFGUARD_TEST_VAULT_TOKEN'));
      const secrets = new HashiCorpVaultSecretCache(process.env.HKDFGUARD_TEST_VAULT_ADDR || DEFAULT_VAULT_CACHE_ADDRESS, token, protector, ring,
        vaultTls());
      try {
        await checkKeys(checks, secrets, name.split('#', 1)[0], expected);
      } finally {
        secrets.close();
      }
    } else {
      throw new Error(`unknown store ${JSON.stringify(store)}`);
    }
  } finally {
    await ring.close();
    await wrapper.close();
  }
  checks.finish(`${store} through the ${release.producer} ${release.wrapper} release's ring`);
}

/** Checks a secret holding a JSON object: read whole, it holds the expected members, and each member reads as "name#key". */
async function checkJsonSecret(checks, secrets, name, expected) {
  const { got, error } = await attempt(() => readCache(secrets, name));
  checks.check(error === undefined && holds(got, expected), `the whole secret holds the expected members: ${error ?? `got ${got.length} characters`}`);
  await checkKeys(checks, secrets, name, expected);
}

/** Checks each expected member reads as "name#key", and that a key matches only exactly. */
async function checkKeys(checks, secrets, name, expected) {
  const keys = sortedKeys(expected);
  for (const key of keys) {
    const want = asCached(expected[key]);
    if (want !== undefined) {
      const { got, error } = await attempt(() => readCache(secrets, `${name}#${key}`));
      checks.check(error === undefined && got === want, `#${key} reads as expected: ${error ?? `got ${got.length} characters`}`);
    }
  }
  for (const key of keys) {
    const swapped = swapAsciiCase(key);
    if (swapped !== key && !Object.hasOwn(expected, swapped)) {
      const { got, error } = await attempt(() => readCache(secrets, `${name}#${swapped}`));
      checks.check(error === undefined && got === '', `#${key}, in another ASCII case, is missing: ${error ?? `got ${got.length} characters`}`);
      break;
    }
  }
  const { got, error } = await attempt(() => readCache(secrets, `${name}#${MISSING_KEY}`));
  checks.check(error === undefined && got === '', `#${MISSING_KEY} is missing: ${error ?? `got ${got.length} characters`}`);
}

/** A JSON number as the text it was written as, so an integer is compared exactly. */
class JsonNumber {
  constructor(text) {
    this.text = text;
  }
}

/** Parses JSON text, keeping every number as a JsonNumber of its source text. */
function parseJson(text) {
  return JSON.parse(text, (_key, value, context) => (typeof value === 'number' ? new JsonNumber(context?.source ?? String(value)) : value));
}

function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value) && !(value instanceof JsonNumber);
}

/**
 * A member as every port's cache caches it: a string as its text, true or false as its JSON text. An
 * integer is compared as its JSON text too; any other number, null, an object or an array isn't
 * compared (undefined), since not every port's JSON reader keeps a number's exact text.
 */
function asCached(value) {
  if (typeof value === 'string') return value;
  if (typeof value === 'boolean') return String(value);
  if (value instanceof JsonNumber && INTEGER.test(value.text)) return value.text;
  return undefined;
}

/** Whether value is a JSON object with exactly the expected member names, each comparable member holding what's expected. */
function holds(value, expected) {
  let got;
  try {
    got = parseJson(value);
  } catch {
    return false;
  }
  if (!isObject(got) || Object.keys(got).length !== Object.keys(expected).length) return false;
  for (const [key, member] of Object.entries(expected)) {
    if (!Object.hasOwn(got, key)) return false;
    const want = asCached(member);
    if (want !== undefined && asCached(got[key]) !== want) return false;
  }
  return true;
}

function secretSettings(nameVariable, jsonVariable) {
  const name = setting(nameVariable);
  let expected;
  try {
    expected = parseJson(setting(jsonVariable));
  } catch {
    expected = undefined;
  }
  // Never quoting it: it holds the secret's values.
  if (!isObject(expected)) throw new Error(`${jsonVariable} isn't a JSON object`);
  return { name, expected };
}

/** Splits https://{vault}.vault.azure.net/secrets/{name} into the vault's URL and the secret's name. */
function azureSecretId(id) {
  const invalid = new Error("HKDFGUARD_TEST_AZURE_SECRET_ID isn't https://{vault}.vault.azure.net/secrets/{name}");
  let url;
  try {
    url = new URL(id);
  } catch {
    throw invalid;
  }
  if (url.protocol !== 'https:') throw invalid;
  const parts = url.pathname.replace(/^\/+|\/+$/g, '').split('/');
  if (parts.length !== 2 || parts[0] !== 'secrets') throw invalid;
  return { vaultUrl: `https://${url.host}/`, name: parts[1] };
}

function sortedKeys(object) {
  return Object.keys(object).sort();
}

function swapAsciiCase(text) {
  return text.replace(/[A-Za-z]/g, (c) => (c <= 'Z' ? c.toLowerCase() : c.toUpperCase()));
}

/**
 * This port's wrapper named name, over the KEK the HKDFGUARD_TEST_* settings name and bound to
 * context; the native one is over the service's KEK on this host. A network wrapper reads key files
 * only from where this account is trusted to have written them, since the matrix writes and reads
 * them as one account (see keyFileTrust). Returns the wrapper and a close() that releases whatever
 * client it was built over.
 */
function newWrapper(name, service, context) {
  if (name === NATIVE) return { wrapper: NativeKeyWrapperV1.create(service), close: async () => {} };
  const keyFileTrust = currentAccountTrust();
  if (name === 'awskms') {
    const key = setting('HKDFGUARD_TEST_AWS_KMS_KEY_ID');
    const client = new KMSClient({});
    try {
      const wrapper = new AwsKmsKeyWrapper(client, key, { encryptionContext: { purpose: context }, keyFileTrust });
      return { wrapper, close: async () => client.destroy() };
    } catch (error) {
      client.destroy();
      throw error;
    }
  }
  if (name === 'azurekeyvault') {
    const wrapKey = setting('HKDFGUARD_TEST_AZURE_WRAP_KEY_ID');
    const signKey = setting('HKDFGUARD_TEST_AZURE_SIGN_KEY_ID');
    const wrapper = new AzureKeyVaultKeyWrapper(wrapKey, signKey, new DefaultAzureCredential(), { context, keyFileTrust });
    return { wrapper, close: async () => {} };
  }
  if (name === 'googlekms') {
    const key = setting('HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME');
    const client = new KeyManagementServiceClient();
    try {
      const wrapper = new GoogleKmsKeyWrapper(client, key, { context, keyFileTrust });
      return { wrapper, close: () => client.close() };
    } catch (error) {
      void client.close();
      throw error;
    }
  }
  if (name === 'hashicorpvault') {
    const key = setting('HKDFGUARD_TEST_VAULT_TRANSIT_KEY');
    const token = new StaticVaultTokenSource(setting('HKDFGUARD_TEST_VAULT_TOKEN'));
    try {
      const wrapper = new HashiCorpVaultTransitKeyWrapper(process.env.HKDFGUARD_TEST_VAULT_ADDR || DEFAULT_VAULT_ADDRESS, key, token, {
        context,
        mountPath: process.env.HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT || undefined,
        keyFileTrust,
        ...vaultTls(),
      });
      return {
        wrapper,
        close: async () => {
          wrapper.close();
          token.close();
        },
      };
    } catch (error) {
      token.close();
      throw error;
    }
  }
  throw new Error(`unknown wrapper ${JSON.stringify(name)}`);
}

/** The TLS option trusting the CA HKDFGUARD_TEST_VAULT_CACERT names, and only it, if set; Node's trust store otherwise. */
function vaultTls() {
  const ca = process.env.HKDFGUARD_TEST_VAULT_CACERT;
  return ca ? { tls: { serverCertificateFile: ca } } : {};
}

/**
 * Trusts this account to have written the key files it reads, as well as Administrators (or root):
 * the matrix writes and reads every key file as one account. Never trust an application's own
 * account outside a test or developer host.
 */
function currentAccountTrust() {
  if (process.platform !== 'win32') return new KeyFileTrust({ unixUserIds: [process.geteuid()] });
  // whoami by its full path, never one found on PATH: "DOMAIN\name","S-1-5-21-..."
  const whoami = join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'whoami.exe');
  const output = execFileSync(whoami, ['/user', '/fo', 'csv', '/nh'], { encoding: 'utf8' }).trim();
  const sid = output.slice(output.lastIndexOf(',') + 1).replace(/"/g, '');
  if (!sid.startsWith('S-1-')) throw new Error(`whoami reported no SID: ${output}`);
  return new KeyFileTrust({ windowsPrincipals: [sid] });
}

function setting(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

function reveal(ring, name, value) {
  const protector = ring.createProtector(configurationPurpose(name));
  const result = new Uint8Array(protector.maxDecryptedLength(value));
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(result.subarray(0, protector.decrypt(value, result)));
  } finally {
    wipe(result);
  }
}

/** Flips one bit in the last byte (the GCM tag) of a formatted value. */
function tamper(value) {
  const match = FORMAT.exec(value);
  if (match === null) throw new Error('not an enc::v<version>::<base64> value');
  const body = Buffer.from(match[2], 'base64');
  body[body.length - 1] ^= 0x01;
  return match[1] + body.toString('base64');
}

async function unwrappedDigest(wrapper, path) {
  const wrapped = await wrapper.readKeyFile(path);
  const raw = new Uint8Array(Math.max(KEY_SIZE, MAX_WRAPPED_KEY_BYTES));
  try {
    const n = await wrapper.unwrap(wrapped, raw);
    return createHash('sha256').update(raw.subarray(0, n)).digest('hex');
  } finally {
    wipe(raw);
  }
}

/**
 * Runs body, sync or async: what it returned, or the message of what it threw (the error itself when
 * keepError is set, for checks on its class).
 */
async function attempt(body, keepError = false) {
  try {
    return { got: await body() };
  } catch (error) {
    return { error: keepError ? error : message(error) };
  }
}

function message(error) {
  if (error === undefined) return 'no error';
  return error instanceof Error ? error.message : String(error);
}

function checker() {
  let passed = 0;
  let failed = 0;
  const fail = (text) => {
    failed++;
    console.log(`FAIL ${text}`);
  };
  return {
    fail,
    check(ok, text) {
      if (ok) passed++;
      else fail(text);
    },
    finish(what) {
      if (failed > 0) {
        console.error(`FAIL ${failed} of ${passed + failed} checks failed reading ${what}`);
        process.exit(1);
      }
      console.log(`OK ${passed} checks passed reading ${what}`);
    },
  };
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  let options;
  try {
    ({ values: options } = parseArgs({
      args: rest,
      options: {
        wrapper: { type: 'string', default: NATIVE },
        store: { type: 'string' },
        service: { type: 'string' },
        fixtures: { type: 'string' },
        dir: { type: 'string' },
        cli: { type: 'string' },
      },
    }));
  } catch {
    usage();
  }
  if (!options.service || !options.fixtures || !options.dir) usage();
  const fixtures = JSON.parse(readFileSync(options.fixtures, 'utf8'));
  if (command === 'produce' && options.cli) await produce(options.wrapper, options.service, fixtures, options.dir, options.cli);
  else if (command === 'consume') await consume(options.wrapper, options.service, fixtures, options.dir);
  else if (command === 'cache' && options.store) await readStore(options.store, options.wrapper, options.service, options.dir);
  else usage();
}

main().catch((error) => {
  console.error('FAIL', error instanceof Error ? error.message : error);
  process.exit(1);
});
