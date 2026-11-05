'use strict';
// The Node.js driver for the HkdfGuard interop matrix: it produces a release (pipeline encryption plus
// a key file wrapped by one key wrapper, and the secrets pipeline writer's files, JSON and tar
// archive), consumes any driver's release with its own port of the same wrapper and caches, and reads
// a remote secret store through its cache over that release's key ring. See the repository README for
// the contract every driver follows; the .NET driver is the reference this one is ported from.

const { execFileSync, spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const { createReadStream, createWriteStream, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');
const { Writable } = require('node:stream');
const { pipeline: pipeStreams } = require('node:stream/promises');
const { parseArgs } = require('node:util');
const { KMSClient } = require('@aws-sdk/client-kms');
const { SecretsManagerClient } = require('@aws-sdk/client-secrets-manager');
const { DefaultAzureCredential } = require('@azure/identity');
const { KeyManagementServiceClient } = require('@google-cloud/kms');
const {
  AlreadyExistsError, AuthenticationFailedError, configurationPurpose, InvalidArgumentError, MAX_WRAPPED_KEY_BYTES, wipe,
} = require('@runsecure/hkdfguard-abstractions');
const { EmptyValueError, FilePerSecretCache, ProtectedCache } = require('@runsecure/hkdfguard-cache');
const { AwsSecretsManagerSecretCache } = require('@runsecure/hkdfguard-cache-awssecretsmanager');
const { AzureKeyVaultSecretCache } = require('@runsecure/hkdfguard-cache-azurekeyvault');
const { GoogleSecretManagerSecretCache } = require('@runsecure/hkdfguard-cache-googlesecretmanager');
const { HashiCorpVaultSecretCache, StaticVaultToken } = require('@runsecure/hkdfguard-cache-hashicorpvault');
const { JsonSecretsFileReadOnlyCache } = require('@runsecure/hkdfguard-cache-jsonsecretsfile');
const { AesGcmCryptoProviderFactory, AesGcmPipelineDataProtector, KEY_SIZE } = require('@runsecure/hkdfguard-cryptoprovider-aesgcm256');
const { buildKeyRing, DefaultFormatProvider } = require('@runsecure/hkdfguard-dek');
const { AwsKmsKeyWrapper } = require('@runsecure/hkdfguard-keywrapping-awskms');
const { AzureKeyVaultKeyWrapper } = require('@runsecure/hkdfguard-keywrapping-azurekeyvault');
const { GoogleKmsKeyWrapper } = require('@runsecure/hkdfguard-keywrapping-googlekms');
const { HashiCorpVaultTransitKeyWrapper, StaticVaultTokenSource } = require('@runsecure/hkdfguard-keywrapping-hashicorpvault');
const { NativeKeyWrapperV1 } = require('@runsecure/hkdfguard-keywrapping-native-v1');
const { SecretPipelineWriter, SecretsNotFoundError } = require('@runsecure/hkdfguard-pipeline');
const { KeyFileTrust } = require('@runsecure/hkdfguard-securefile');

const RELEASE_FILE = 'release.json';
const KEY_FILE = 'dek.wrapped';
const SECRETS_DIR = 'secrets';
const FORMAT = /^(enc::v\d+::)(.+)$/s;
const NATIVE = 'native';

const PIPELINE_DIR = 'pipeline';
const JSON_SECRETS_FILE = 'secrets.json';
const STREAM_JSON_SECRETS_FILE = 'secrets.stream.json';
const EMPTY_JSON_SECRETS_FILE = 'secrets.empty.json';
const SECRETS_TAR = 'secrets.tar';
const PIPELINE_FILES_DIR = 'files';
const PIPELINE_UNPACKED_DIR = 'unpacked';
const CONSUMER_DIR = 'consumed-by-node';

// The base64 of a 32-byte key: 44 ASCII characters, no line ending.
const KEY_BASE64_LENGTH = 44;

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
 * values and the secrets pipeline writer's output, and wraps the key into the key file - by having
 * writeDek write it into the native tool's standard input, or through a network key wrapper in this
 * process.
 */
async function produce(wrapperName, service, fixtures, dir, cli) {
  const pipeline = new AesGcmPipelineDataProtector(new DefaultFormatProvider(), fixtures.keyVersion);
  const raw = new Uint8Array(KEY_SIZE);
  try {
    const encoder = new TextEncoder();
    const values = Object.fromEntries(fixtures.secrets.map((s) => [s.identifier, pipeline.encrypt(encoder.encode(s.plaintext), s.identifier)]));

    await readDekThroughWriteDek(pipeline, raw);
    // Test only: a hash of the DEK, so every consumer can prove it unwrapped this same key. Never
    // record anything derived from a DEK beside its key file in a real pipeline.
    const dekSha256 = createHash('sha256').update(raw).digest('hex');

    mkdirSync(dir, { recursive: true, mode: 0o700 });
    writeSecretFiles(pipeline, fixtures, join(dir, SECRETS_DIR));
    await writePipeline(pipeline, fixtures.pipeline, dir);
    const path = join(dir, KEY_FILE);
    if (wrapperName === NATIVE) {
      await wrapNatively(cli, path, service, pipeline);
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
    console.log(`OK produced ${Object.keys(values).length} secrets and ${fixtures.pipeline.secrets.length} pipeline secrets in ${dir}`);
  } finally {
    wipe(raw);
    pipeline.close();
  }
}

/**
 * Writes the pipeline key with writeDek straight into the standard input of
 * `hkdfguard wrap --dek-stdin`: never an argument or an environment variable, and never a copy here.
 * Ending its input is what tells the tool the key is complete.
 */
async function wrapNatively(cli, path, service, pipeline) {
  const wrap = spawn(cli, ['wrap', '-kf', path, '-sn', service, '--dek-stdin'], { stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = exitOf(wrap);
  try {
    await pipeline.writeDek(wrap.stdin);
  } finally {
    wrap.stdin.end();
  }
  const { code, output } = await exited;
  if (code !== 0) throw new Error(`hkdfguard wrap exited ${code}: ${output}`);
}

/**
 * Writes the pipeline key through writeDek, as the wrap tool's --dek-stdin reads it, into a buffer
 * of this driver's own, and decodes it into dek: so every wrapper's key file comes from those bytes,
 * and every consumer's DEK check proves them. Checks they are exactly the key's 44 base64 characters
 * as ASCII, the same as keyBase64's, without a line ending. writeDek zeroes its buffer once the write
 * calls back, so this stream copies each chunk before calling back, as a file or a pipe would.
 */
async function readDekThroughWriteDek(pipeline, dek) {
  const ascii = new Uint8Array(KEY_BASE64_LENGTH + 2);
  let written = 0;
  let overflow = false;
  const destination = new Writable({
    write(chunk, _encoding, callback) {
      if (written + chunk.length > ascii.length) overflow = true;
      else ascii.set(chunk, written);
      written += chunk.length;
      callback();
    },
  });
  const key = pipeline.keyBase64();
  try {
    await pipeline.writeDek(destination);
    destination.end();
    let same = !overflow && written === key.length;
    for (let i = 0; same && i < written; i++) same = ascii[i] === key[i];
    if (written !== KEY_BASE64_LENGTH || !same) {
      throw new Error(`writeDek wrote ${written} bytes, not the key's ${KEY_BASE64_LENGTH} base64 characters`);
    }
    // Node has no buffer-to-buffer base64 decode, so the key also passes through an immutable string
    // that can't be zeroed; acceptable for a throwaway test key only.
    const n = Buffer.from(Buffer.from(ascii.buffer, 0, written).toString('latin1'), 'base64').copy(dek);
    if (n !== KEY_SIZE) throw new Error("The pipeline key isn't 32 bytes.");
  } finally {
    wipe(ascii);
    wipe(key);
  }
}

/**
 * A SecretPipelineWriter over an in-memory store: each store name maps to its value's exact text,
 * handed to the base's protectSecret as UTF-8 and zeroed after. Names match exactly, and a store name
 * is 1 or more ASCII letters, digits, '/', '_', '.' and '-'.
 */
class InMemorySecretPipelineWriter extends SecretPipelineWriter {
  #store;

  constructor(protector, secretNames, store) {
    super(protector, secretNames, (name) => /^[A-Za-z0-9/_.-]+$/.test(name));
    this.#store = new Map(Object.entries(store));
  }

  async readSecret(name, requests, values) {
    const text = this.#store.get(name);
    if (text === undefined) return;
    const secret = new TextEncoder().encode(text);
    try {
      this.protectSecret(secret, requests, values);
    } finally {
      wipe(secret);
    }
  }
}

/**
 * Writes the release's pipeline folder: every fixture in the fixtures' pipeline section pulled
 * through this port's real SecretPipelineWriter base, over an in-memory store, and written in each of
 * the writer's layouts. The writers use the release's own pipeline protector, so every value decrypts
 * under the release's key ring, and they never close it.
 */
async function writePipeline(pipeline, fixtures, dir) {
  for (const s of fixtures.secrets) {
    if (SecretPipelineWriter.getFileName(s.name) !== s.fileName) throw new Error(`pipeline: ${s.name}'s file name isn't ${s.fileName}`);
  }
  for (const names of fixtures.refused) {
    let refused;
    try {
      refused = new InMemorySecretPipelineWriter(pipeline, names, fixtures.store);
    } catch (error) {
      if (error instanceof InvalidArgumentError) continue;
      throw error;
    }
    await refused.close();
    throw new Error(`pipeline: the writer accepted [${names.join(', ')}]`);
  }

  const folder = join(dir, PIPELINE_DIR);
  mkdirSync(folder, { recursive: true });
  const writer = new InMemorySecretPipelineWriter(pipeline, fixtures.secrets.map((s) => s.name), fixtures.store);
  try {
    await writer.pullSecrets();
    const kept = [...writer.protectedSecrets.keys()].sort();
    const expected = fixtures.secrets.map((s) => s.fileName).sort();
    if (kept.length !== expected.length || kept.some((name, i) => name !== expected[i])) {
      throw new Error("pipeline: the writer's protected secrets aren't the fixtures' file names");
    }

    await writer.writeJsonSecrets(join(folder, JSON_SECRETS_FILE));
    await writeToFile(join(folder, STREAM_JSON_SECRETS_FILE), (stream) => writer.writeJsonSecretsTo(stream));
    await writer.writeProtectedSecretFiles(join(folder, PIPELINE_FILES_DIR));
    await writeToFile(join(folder, SECRETS_TAR), (stream) => writer.writeProtectedSecretFilesTo(stream));

    // As a deployment would: the archive straight into a tar process's standard input.
    const unpacked = join(folder, PIPELINE_UNPACKED_DIR);
    mkdirSync(unpacked, { recursive: true });
    await untar(unpacked, (stdin) => writer.writeProtectedSecretFilesTo(stdin));
    const difference = compareFolders(join(folder, PIPELINE_FILES_DIR), unpacked, fixtures.secrets.map((s) => s.fileName));
    if (difference !== undefined) throw new Error(`pipeline: the archive piped to tar unpacked differently: ${difference}`);
  } finally {
    await writer.close();
  }

  const missing = new InMemorySecretPipelineWriter(pipeline, fixtures.missing, fixtures.store);
  try {
    let pulled = false;
    try {
      await missing.pullSecrets();
      pulled = true;
    } catch (error) {
      if (!(error instanceof SecretsNotFoundError)) throw error;
    }
    if (pulled) throw new Error('pipeline: pulling secrets the store holds no value for succeeded');
    if (missing.protectedSecrets.size !== 0) throw new Error(`pipeline: pulling only missing secrets kept ${missing.protectedSecrets.size}`);
    await missing.writeJsonSecrets(join(folder, EMPTY_JSON_SECRETS_FILE));
  } finally {
    await missing.close();
  }
}

/** Opens a file to write, has write write into it, then ends it and waits until it is written. */
async function writeToFile(path, write) {
  const stream = createWriteStream(path);
  try {
    await write(stream);
  } catch (error) {
    stream.destroy();
    throw error;
  }
  await new Promise((resolve, reject) => {
    stream.once('error', reject);
    stream.end(resolve);
  });
}

/**
 * Runs the system tar - Windows' own bsdtar, else the tar on PATH - never through a shell, to unpack
 * an archive from its standard input into folder: write writes the archive, and the input is ended
 * afterwards. Requires exit code 0.
 */
async function untar(folder, write) {
  const tar = spawn(tarPath(), ['-x', '--no-same-owner', '-f', '-', '-C', folder], { stdio: ['pipe', 'pipe', 'pipe'] });
  const exited = exitOf(tar);
  try {
    await write(tar.stdin);
  } finally {
    tar.stdin.end();
  }
  const { code, output } = await exited;
  if (code !== 0) throw new Error(`tar exited ${code}: ${output}`);
}

function tarPath() {
  return process.platform === 'win32' ? join(process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'tar.exe') : 'tar';
}

/**
 * The exit code of a child process and what it printed, once it has exited; rejects if it couldn't
 * start. An error writing to its input, such as EPIPE once it has exited, is the writer's to report,
 * and shows in the exit code.
 */
function exitOf(child) {
  let output = '';
  child.stdout.on('data', (chunk) => { output += chunk; });
  child.stderr.on('data', (chunk) => { output += chunk; });
  child.stdin.on('error', () => {});
  const exited = new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('close', (code) => resolve({ code, output: output.trim() }));
  });
  // Awaited once the input is written: a failure to start mustn't be reported unhandled before then.
  exited.catch(() => {});
  return exited;
}

/** undefined if each named file in actual is the one in expected byte for byte, else what differs. */
function compareFolders(expected, actual, names) {
  for (const name of names) {
    const path = join(actual, name);
    if (statSync(path, { throwIfNoEntry: false })?.isFile() !== true) return `${name} is missing`;
    let want;
    try {
      want = readFileSync(join(expected, name));
    } catch (error) {
      return `the written ${name} can't be read: ${describe(error)}`;
    }
    if (!readFileSync(path).equals(want)) return `${name} differs`;
  }
  return undefined;
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
    await checkSecretFiles(checks, ring, fixtures, join(dir, SECRETS_DIR));
    await checkPipeline(checks, ring, fixtures.pipeline, dir);
  } finally {
    await ring.close();
    await wrapper.close();
  }
  checks.finish(`the ${release.producer} ${release.wrapper} release`);
}

/** The value a secrets-folder file is written with: its own plaintext, or the named secret's. */
function filePlaintext(fixtures, file) {
  if (file.plaintextOf) {
    const s = fixtures.secrets.find((secret) => secret.identifier === file.plaintextOf);
    if (s !== undefined) return s.plaintext;
  }
  return file.plaintext ?? '';
}

/**
 * Writes the release's secrets folder as a pipeline would for FilePerSecretCache: one file per
 * secret, holding its value encrypted under the pipeline key for the file's own name. On Windows the
 * folder is created without an owner-only ACL.
 */
function writeSecretFiles(pipeline, fixtures, folder) {
  mkdirSync(folder, process.platform === 'win32' ? { recursive: true } : { recursive: true, mode: 0o700 });
  const encoder = new TextEncoder();
  const written = new Map();
  for (const file of fixtures.files) {
    let contents;
    if (file.empty) {
      contents = Buffer.alloc(0);
    } else if (file.copyOf) {
      contents = written.get(file.copyOf);
      if (contents === undefined) throw new Error(`the file ${file.name} copies ${file.copyOf}, which isn't written before it`);
    } else {
      let value;
      try {
        value = pipeline.encrypt(encoder.encode(filePlaintext(fixtures, file)), file.name);
      } catch (error) {
        throw new Error(`encrypting the file ${file.name}: ${message(error)}`);
      }
      contents = Buffer.from(file.trailingNewline ? `${value}\n` : value, 'utf8');
    }
    written.set(file.name, contents);
    writeFileSync(join(folder, file.name), contents, { mode: 0o600 });
  }
}

/**
 * Reads the release's secrets folder through a FilePerSecretCache over the release's ring: each file
 * reads as its value, is missing, or is refused as its fixture expects, and a name no file can answer
 * - one that isn't a file name in the folder - is missing. No value is ever printed.
 */
async function checkSecretFiles(checks, ring, fixtures, folder) {
  let files;
  try {
    files = new FilePerSecretCache(folder, currentAccountTrust(), ring, new DefaultFormatProvider());
  } catch (error) {
    checks.fail(`files: opening the secrets folder: ${message(error)}`);
    return;
  }
  for (const file of fixtures.files) {
    const { got, error } = await attempt(() => readCache(files, file.name), true);
    if (file.expect === 'value') {
      checks.check(error === undefined && got === filePlaintext(fixtures, file),
        `files: ${file.name} reads as its value: got ${got?.length ?? 0} characters, ${message(error)}`);
    } else if (file.expect === 'missing') {
      checks.check(error === undefined && got === '', `files: ${file.name} is missing: got ${got?.length ?? 0} characters, ${message(error)}`);
    } else if (file.expect === 'refused') {
      checks.check(error instanceof AuthenticationFailedError, `files: ${file.name} fails authentication: ${message(error)}`);
    } else {
      checks.fail(`files: ${file.name} expects ${JSON.stringify(file.expect)}, which isn't value, missing or refused`);
    }
  }
  for (const name of fixtures.missingFiles) {
    const { got, error } = await attempt(() => readCache(files, name), true);
    checks.check(error === undefined && got === '', `files: ${name} is missing: got ${got?.length ?? 0} characters, ${message(error)}`);
  }
}

/**
 * Reads the release's pipeline folder as a deployed application would: secrets.json through a
 * JsonSecretsFileReadOnlyCache over the release's ring, tampered copies of it refused whole, and
 * secrets.tar unpacked by the system tar and read through a FilePerSecretCache. 39 checks, in the
 * README's order; a file that is missing fails its checks, never the driver.
 */
async function checkPipeline(checks, ring, fixtures, dir) {
  const folder = join(dir, PIPELINE_DIR);
  const trust = currentAccountTrust();
  const format = new DefaultFormatProvider();
  const jsonPath = join(folder, JSON_SECRETS_FILE);

  let json;
  try {
    json = new JsonSecretsFileReadOnlyCache(jsonPath, trust, ring, format);
  } catch (error) {
    checks.fail(`pipeline: opening ${JSON_SECRETS_FILE}: ${describe(error)}`);
  }
  if (json !== undefined) {
    for (const s of fixtures.secrets) {
      for (const name of [s.fileName, ...(s.alsoReadAs ?? [])]) {
        const { got, error } = await attempt(() => readCache(json, name), true);
        checks.check(error === undefined && got === s.plaintext,
          `pipeline: ${JSON_SECRETS_FILE} reads ${s.name} as ${name}: got ${bytes(got)} bytes, ${error === undefined ? 'wrong plaintext' : describe(error)}`);
      }
    }
    for (const name of [...fixtures.missingLookups, ...fixtures.invalidLookups]) {
      const { got, error } = await attempt(() => readCache(json, name), true);
      checks.check(error === undefined && got === '', `pipeline: ${JSON_SECRETS_FILE} has no ${name}: got ${bytes(got)} bytes, ${describe(error)}`);
    }
  }

  const { got: same, error: sameError } = await attempt(() => readFileSync(join(folder, STREAM_JSON_SECRETS_FILE)).equals(readFileSync(jsonPath)), true);
  checks.check(same === true,
    `pipeline: ${STREAM_JSON_SECRETS_FILE} is ${JSON_SECRETS_FILE} byte for byte: ${sameError === undefined ? 'it differs' : describe(sameError)}`);

  const emptyPath = join(folder, EMPTY_JSON_SECRETS_FILE);
  const { got: empty, error: emptyError } = await attempt(() => readFileSync(emptyPath).equals(Buffer.from('{}', 'ascii')), true);
  checks.check(empty === true, `pipeline: ${EMPTY_JSON_SECRETS_FILE} is {}: ${emptyError === undefined ? "it isn't" : describe(emptyError)}`);
  const first = fixtures.secrets[0].fileName;
  const { got: nothing, error: nothingError } = await readFromNewCache(emptyPath, trust, ring, format, first);
  checks.check(nothingError === undefined && nothing === '',
    `pipeline: ${EMPTY_JSON_SECRETS_FILE} has no ${first}: got ${bytes(nothing)} bytes, ${describe(nothingError)}`);

  // On Windows without an owner-only ACL, as the matrix makes D.
  const work = join(folder, CONSUMER_DIR);
  rmSync(work, { recursive: true, force: true });
  mkdirSync(work, process.platform === 'win32' ? { recursive: true } : { recursive: true, mode: 0o700 });
  await checkTampered(checks, ring, format, trust, jsonPath, work);
  await checkArchive(checks, ring, fixtures, trust, folder, work);
}

/**
 * Two copies of secrets.json, each changed one way, must each be refused whole: a lookup of a member
 * the change didn't touch fails authentication too.
 */
async function checkTampered(checks, ring, format, trust, jsonPath, work) {
  let members;
  try {
    // JSON.parse keeps members in file order unless a name is an array index ("0", "1", ...), which
    // JavaScript objects list first; no fixture's file name is one.
    const parsed = JSON.parse(readFileSync(jsonPath, 'utf8'));
    if (!isObject(parsed)) throw new Error("it isn't a JSON object");
    members = Object.entries(parsed);
    if (members.some(([, value]) => typeof value !== 'string')) throw new Error("a member's value isn't a string");
  } catch (error) {
    checks.fail(`pipeline: parsing ${JSON_SECRETS_FILE} to tamper with it: ${describe(error)}`);
    return;
  }
  if (members.length < 3) {
    checks.fail(`pipeline: ${JSON_SECRETS_FILE} holds ${members.length} members, too few to tamper with`);
    return;
  }
  const untouched = members[members.length - 1][0];

  const swapped = members.map(([name, value]) => [name, value]);
  swapped[0][1] = members[1][1];
  swapped[1][1] = members[0][1];
  let { got, error } = await readFromNewCache(writeMembers(join(work, 'swapped.json'), swapped), trust, ring, format, untouched);
  checks.check(error instanceof AuthenticationFailedError,
    `pipeline: ${JSON_SECRETS_FILE} with two values swapped is refused whole: got ${bytes(got)} bytes, ${describe(error)}`);

  const flipped = members.map(([name, value]) => [name, value]);
  try {
    flipped[0][1] = tamper(members[0][1]);
  } catch (tamperError) {
    checks.fail(`pipeline: tampering ${members[0][0]}: ${describe(tamperError)}`);
    return;
  }
  ({ got, error } = await readFromNewCache(writeMembers(join(work, 'flipped.json'), flipped), trust, ring, format, untouched));
  checks.check(error instanceof AuthenticationFailedError,
    `pipeline: ${JSON_SECRETS_FILE} with a flipped tag bit is refused whole: got ${bytes(got)} bytes, ${describe(error)}`);
}

/**
 * Unpacks secrets.tar with the system tar, from its standard input, into a fresh folder: it must hold
 * exactly the files writeProtectedSecretFiles wrote, byte for byte, each reading through a
 * FilePerSecretCache as its value.
 */
async function checkArchive(checks, ring, fixtures, trust, folder, work) {
  const unpacked = join(work, PIPELINE_UNPACKED_DIR);
  mkdirSync(unpacked, { recursive: true });
  try {
    await untar(unpacked, (stdin) => pipeStreams(createReadStream(join(folder, SECRETS_TAR)), stdin, { end: false }));
  } catch (error) {
    checks.fail(`pipeline: unpacking ${SECRETS_TAR}: ${describe(error)}`);
    return;
  }

  const names = fixtures.secrets.map((s) => s.fileName).sort();
  const entries = readdirSync(unpacked).sort();
  checks.check(entries.length === names.length && entries.every((name, i) => name === names[i]),
    `pipeline: ${SECRETS_TAR} holds exactly the secrets' files: it holds ${entries.length}, not ${names.length}`);

  let files;
  try {
    files = new FilePerSecretCache(unpacked, trust, ring, new DefaultFormatProvider());
  } catch (error) {
    checks.fail(`pipeline: opening the unpacked folder: ${describe(error)}`);
    return;
  }
  for (const s of fixtures.secrets) {
    const difference = compareFolders(join(folder, PIPELINE_FILES_DIR), unpacked, [s.fileName]);
    const { got, error } = await attempt(() => readCache(files, s.fileName), true);
    checks.check(difference === undefined && error === undefined && got === s.plaintext,
      `pipeline: ${SECRETS_TAR}'s ${s.fileName} is the written file and reads as its value: `
      + `${difference ?? `got ${bytes(got)} bytes, ${error === undefined ? 'wrong plaintext' : describe(error)}`}`);
  }
}

/** A lookup through a new JsonSecretsFileReadOnlyCache over path, so nothing an earlier cache loaded is reused. */
function readFromNewCache(path, trust, ring, format, name) {
  return attempt(() => readCache(new JsonSecretsFileReadOnlyCache(path, trust, ring, format), name), true);
}

/** Writes members as a JSON object, in their order. The layout is this driver's own: the cache reads any valid JSON object. */
function writeMembers(path, members) {
  writeFileSync(path, JSON.stringify(Object.fromEntries(members), null, 2));
  return path;
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

/** An error's class and message, for a failed check; never a value. */
function describe(error) {
  if (error === undefined) return 'no error';
  return error instanceof Error ? `${error.name}: ${error.message}` : String(error);
}

/** A value's length in UTF-8 bytes: what a failure may say about a value it read, never more. */
function bytes(value) {
  return typeof value === 'string' ? Buffer.byteLength(value, 'utf8') : 0;
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
