'use strict';
// The Node.js driver for the HkdfGuard interop matrix: it produces a release (pipeline encryption plus
// a key file wrapped by the native hkdfguard tool) and consumes any driver's release. See the
// repository README for the contract every driver follows.

const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');
const { mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { parseArgs } = require('node:util');
const { configurationPurpose, MAX_WRAPPED_KEY_BYTES, wipe } = require('@runsecure/hkdfguard-abstractions');
const { AesGcmCryptoProviderFactory, AesGcmPipelineDataProtector, KEY_SIZE } = require('@runsecure/hkdfguard-cryptoprovider-aesgcm256');
const { buildKeyRing, DefaultFormatProvider } = require('@runsecure/hkdfguard-dek');
const { NativeKeyWrapperV1 } = require('@runsecure/hkdfguard-keywrapping-native-v1');

const RELEASE_FILE = 'release.json';
const KEY_FILE = 'dek.wrapped';
const FORMAT = /^(enc::v\d+::)(.+)$/s;

function usage() {
  console.error('usage: interop.cjs produce --service S --fixtures F --dir D --cli PATH');
  console.error('       interop.cjs consume --service S --fixtures F --dir D');
  process.exit(2);
}

/**
 * Does what a release pipeline does: encrypts every fixture under a fresh pipeline key, writes the
 * values, and hands the key to the native tool on standard input to wrap into the key file.
 */
function produce(service, fixtures, dir, cli) {
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
    const wrap = spawnSync(cli, ['wrap', '-kf', join(dir, KEY_FILE), '-sn', service, '--dek-stdin'], { input: base64 });
    if (wrap.error) throw wrap.error;
    if (wrap.status !== 0) throw new Error(`hkdfguard wrap exited ${wrap.status}: ${`${wrap.stdout}${wrap.stderr}`.trim()}`);

    const release = { producer: 'node', service, keyVersion: fixtures.keyVersion, dekSha256, values };
    writeFileSync(join(dir, RELEASE_FILE), JSON.stringify(release, null, 2), { mode: 0o600 });
    console.log(`OK produced ${Object.keys(values).length} secrets in ${dir}`);
  } finally {
    wipe(raw);
    pipeline.close();
  }
}

/**
 * Reads a release as an application would: builds a ring over the native KEK with the key file, then
 * reveals every value through the configuration purpose of its key.
 */
async function consume(service, fixtures, dir) {
  const release = JSON.parse(readFileSync(join(dir, RELEASE_FILE), 'utf8'));
  const wrapper = NativeKeyWrapperV1.create(service);
  const ring = await buildKeyRing({
    keyWrapper: wrapper,
    cryptoProviderFactory: new AesGcmCryptoProviderFactory(),
    keyRefreshInterval: 60,
    keyFiles: { [release.keyVersion]: join(dir, KEY_FILE) },
  });
  const checks = checker();
  try {
    for (const s of fixtures.secrets) {
      const value = release.values[s.identifier];
      if (value === undefined) {
        checks.fail(`${s.identifier}: missing from the release`);
        continue;
      }
      for (const name of [s.identifier, ...(s.alsoReadAs ?? [])]) {
        const { got, error } = attempt(() => reveal(ring, name, value));
        checks.check(error === undefined && got === s.plaintext, `${s.identifier} reads as ${name}: ${error ?? `got ${got?.length} characters`}`);
      }
      for (const name of s.mustNotReadAs ?? []) {
        checks.check(attempt(() => reveal(ring, name, value)).error !== undefined, `${s.identifier} must not read as ${name}`);
      }
    }

    const [first, second] = fixtures.secrets;
    checks.check(attempt(() => reveal(ring, second.identifier, release.values[first.identifier])).error !== undefined,
      `${first.identifier} moved under ${second.identifier} fails authentication`);
    checks.check(attempt(() => reveal(ring, first.identifier, tamper(release.values[first.identifier]))).error !== undefined,
      `${first.identifier} with a flipped tag bit fails authentication`);

    let digest;
    let unwrapError;
    try {
      digest = await unwrappedDigest(wrapper, join(dir, KEY_FILE));
    } catch (error) {
      unwrapError = error;
    }
    checks.check(digest === release.dekSha256, `the key file unwraps to the producer's DEK: ${unwrapError ?? 'digest differs'}`);
  } finally {
    await ring.close();
  }
  checks.finish(release.producer);
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

function attempt(body) {
  try {
    return { got: body() };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

function checker() {
  let passed = 0;
  let failed = 0;
  const fail = (message) => {
    failed++;
    console.log(`FAIL ${message}`);
  };
  return {
    fail,
    check(ok, message) {
      if (ok) passed++;
      else fail(message);
    },
    finish(producer) {
      if (failed > 0) {
        console.error(`FAIL ${failed} of ${passed + failed} checks failed reading the ${producer} release`);
        process.exit(1);
      }
      console.log(`OK ${passed} checks passed reading the ${producer} release`);
    },
  };
}

async function main() {
  const [command, ...rest] = process.argv.slice(2);
  const { values: options } = parseArgs({
    args: rest,
    options: { service: { type: 'string' }, fixtures: { type: 'string' }, dir: { type: 'string' }, cli: { type: 'string' } },
  });
  if (!options.service || !options.fixtures || !options.dir) usage();
  const fixtures = JSON.parse(readFileSync(options.fixtures, 'utf8'));
  if (command === 'produce' && options.cli) produce(options.service, fixtures, options.dir, options.cli);
  else if (command === 'consume') await consume(options.service, fixtures, options.dir);
  else usage();
}

main().catch((error) => {
  console.error('FAIL', error instanceof Error ? error.message : error);
  process.exit(1);
});
