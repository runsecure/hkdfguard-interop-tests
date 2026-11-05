package io.github.runsecure.hkdfguard.interop;

import static io.github.runsecure.hkdfguard.interop.Main.JSON;
import static io.github.runsecure.hkdfguard.interop.Main.attempt;
import static io.github.runsecure.hkdfguard.interop.Main.await;
import static io.github.runsecure.hkdfguard.interop.Main.describe;
import static io.github.runsecure.hkdfguard.interop.Main.readCache;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.cache.filepersecret.FilePerSecretCacheImpl;
import io.github.runsecure.hkdfguard.cache.jsonsecretsfile.JsonSecretsFileReadOnlyCacheImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import io.github.runsecure.hkdfguard.interop.Main.Attempt;
import io.github.runsecure.hkdfguard.interop.Main.Checker;
import io.github.runsecure.hkdfguard.pipeline.SecretPipelineWriterBase;
import io.github.runsecure.hkdfguard.pipeline.SecretRequest;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * The secrets pipeline half of a release: every fixture in the fixtures' pipeline section is pulled
 * through the port's real SecretPipelineWriterBase, over an in-memory store, and written in each of
 * the writer's layouts to D/pipeline. A consumer reads them back with its own port's caches over the
 * release's key ring. Ported from the .NET driver's Pipeline.cs; see the README's driver contract.
 */
final class Pipeline {
    private static final String PIPELINE_DIR = "pipeline";
    private static final String JSON_SECRETS_FILE = "secrets.json";
    private static final String STREAM_JSON_SECRETS_FILE = "secrets.stream.json";
    private static final String EMPTY_JSON_SECRETS_FILE = "secrets.empty.json";
    private static final String SECRETS_TAR = "secrets.tar";
    private static final String PIPELINE_FILES_DIR = "files";
    private static final String PIPELINE_UNPACKED_DIR = "unpacked";
    private static final String CONSUMER_DIR = "consumed-by-java";

    /** The base64 of a 32-byte key: 44 ASCII characters, no line ending. */
    static final int KEY_BASE64_LENGTH = 44;

    private Pipeline() {}

    /** One secret the main writer pulls: see fixtures/secrets.json's pipeline section. */
    record PipelineSecret(String name, String fileName, String plaintext, List<String> alsoReadAs) {
        List<String> readAs() {
            var names = new ArrayList<String>(List.of(fileName));
            if (alsoReadAs != null) {
                names.addAll(alsoReadAs);
            }
            return names;
        }
    }

    /** The fixtures' pipeline section: see fixtures/secrets.json and the README. */
    record PipelineFixtures(Map<String, String> store, List<PipelineSecret> secrets, List<String> missing, List<List<String>> refused,
            List<String> missingLookups, List<String> invalidLookups) {}

    /**
     * Writes the release's pipeline folder. The writers use the release's own pipeline protector, so
     * every value decrypts under the release's key ring, and they never close it.
     */
    static void writePipeline(PipelineDataProtector pipeline, PipelineFixtures fixtures, Path dir) throws Exception {
        for (var s : fixtures.secrets()) {
            if (!SecretPipelineWriterBase.getFileName(s.name()).equals(s.fileName())) {
                throw new IllegalStateException("pipeline: " + s.name() + "'s file name isn't " + s.fileName());
            }
        }
        for (var names : fixtures.refused()) {
            try (var refused = new InMemorySecretPipelineWriter(pipeline, names, fixtures.store())) {
                // Accepted: reported below.
            } catch (IllegalArgumentException e) {
                continue;
            }
            throw new IllegalStateException("pipeline: the writer accepted [" + String.join(", ", names) + "]");
        }

        var folder = dir.resolve(PIPELINE_DIR);
        Files.createDirectories(folder);
        var fileNames = fixtures.secrets().stream().map(PipelineSecret::fileName).toList();
        try (var writer = new InMemorySecretPipelineWriter(pipeline, fixtures.secrets().stream().map(PipelineSecret::name).toList(),
                fixtures.store())) {
            await(writer.pullSecretsAsync());
            var expected = fileNames.stream().sorted().toList();
            var actual = writer.getProtectedSecrets().keySet().stream().sorted().toList();
            if (!actual.equals(expected)) {
                throw new IllegalStateException("pipeline: the writer's protected secrets aren't the fixtures' file names");
            }

            writer.writeJsonSecrets(folder.resolve(JSON_SECRETS_FILE));
            try (var stream = Files.newOutputStream(folder.resolve(STREAM_JSON_SECRETS_FILE))) {
                await(writer.writeJsonSecretsAsync(stream));
            }
            writer.writeProtectedSecretFiles(folder.resolve(PIPELINE_FILES_DIR));
            try (var stream = Files.newOutputStream(folder.resolve(SECRETS_TAR))) {
                await(writer.writeProtectedSecretFilesAsync(stream));
            }

            // As a deployment would: the archive straight into a tar process's standard input.
            var unpacked = folder.resolve(PIPELINE_UNPACKED_DIR);
            Files.createDirectories(unpacked);
            untar(unpacked, destination -> await(writer.writeProtectedSecretFilesAsync(destination)));
            var difference = compareFolders(folder.resolve(PIPELINE_FILES_DIR), unpacked, fileNames);
            if (difference != null) {
                throw new IllegalStateException("pipeline: the archive piped to tar unpacked differently: " + difference);
            }
        }

        try (var missing = new InMemorySecretPipelineWriter(pipeline, fixtures.missing(), fixtures.store())) {
            try {
                await(missing.pullSecretsAsync());
                throw new IllegalStateException("pipeline: pulling secrets the store holds no value for succeeded");
            } catch (NoSuchElementException e) {
                // Expected.
            }
            if (!missing.getProtectedSecrets().isEmpty()) {
                throw new IllegalStateException("pipeline: pulling only missing secrets kept " + missing.getProtectedSecrets().size());
            }
            missing.writeJsonSecrets(folder.resolve(EMPTY_JSON_SECRETS_FILE));
        }
    }

    /**
     * Writes the pipeline key through writeDekAsync, as the wrap tool's --dek-stdin reads it, into a
     * buffer of its own, and decodes it into dek: so every wrapper's key file comes from those bytes,
     * and every consumer's DEK check proves them. Checks they are exactly the key's 44 base64
     * characters as ASCII, without a line ending. The JVM can't pin the buffer; it is zeroed.
     */
    static void readDekThroughWriteDek(PipelineDataProtector pipeline, byte[] dek) throws Exception {
        var ascii = new byte[KEY_BASE64_LENGTH];
        try {
            var buffer = new FixedBuffer(ascii);
            try (buffer) {
                await(pipeline.writeDekAsync(buffer));
            }
            var written = buffer.count;
            var key = pipeline.getKeyAsBase64();
            var same = written == key.remaining();
            for (int i = 0; same && i < written; i++) {
                same = ascii[i] == key.get(key.position() + i);
            }
            if (written != KEY_BASE64_LENGTH || !same) {
                throw new IllegalStateException("writeDekAsync wrote " + written + " bytes, not the key's " + KEY_BASE64_LENGTH + " base64 characters");
            }
            int length;
            try {
                length = Base64.getDecoder().decode(ascii, dek);
            } catch (IllegalArgumentException e) {
                length = -1;
            }
            if (length != dek.length) {
                throw new IllegalStateException("The pipeline key isn't " + dek.length + " bytes.");
            }
        } finally {
            ArrayUtility.zeroMemory(ascii);
        }
    }

    /**
     * Reads the release's pipeline folder as a deployed application would: secrets.json through a
     * JsonSecretsFileReadOnlyCacheImpl over the release's ring, tampered copies of it refused whole,
     * and secrets.tar unpacked by the system tar and read through a FilePerSecretCacheImpl.
     */
    static void checkPipeline(Checker checks, KeyRing ring, PipelineFixtures fixtures, Path dir) throws Exception {
        var folder = dir.resolve(PIPELINE_DIR);
        KeyFileTrust trust;
        try {
            trust = Wrappers.keyFileTrust();
        } catch (Exception e) {
            checks.fail("pipeline: trusting this account: " + describe(e));
            return;
        }
        var format = new DefaultFormatProviderImpl();
        var jsonPath = folder.resolve(JSON_SECRETS_FILE);

        JsonSecretsFileReadOnlyCacheImpl json = null;
        try {
            json = new JsonSecretsFileReadOnlyCacheImpl(jsonPath, trust, ring, format);
        } catch (Exception e) {
            checks.fail("pipeline: opening " + JSON_SECRETS_FILE + ": " + describe(e));
        }
        if (json != null) {
            var cache = json;
            for (var s : fixtures.secrets()) {
                for (var name : s.readAs()) {
                    var result = attempt(() -> readCache(cache, name));
                    checks.check(result.error() == null && s.plaintext().equals(result.got()),
                            "pipeline: " + JSON_SECRETS_FILE + " reads " + s.name() + " as " + name + ": "
                                    + (result.error() == null ? result.bytes() + ", wrong plaintext" : result));
                }
            }
            for (var name : concat(fixtures.missingLookups(), fixtures.invalidLookups())) {
                var result = attempt(() -> readCache(cache, name));
                checks.check(result.error() == null && result.got().isEmpty(),
                        "pipeline: " + JSON_SECRETS_FILE + " has no " + name + ": " + result);
            }
        }

        var same = attemptCheck(() -> Arrays.equals(Files.readAllBytes(folder.resolve(STREAM_JSON_SECRETS_FILE)), Files.readAllBytes(jsonPath)));
        checks.check(same.ok(), "pipeline: " + STREAM_JSON_SECRETS_FILE + " is " + JSON_SECRETS_FILE + " byte for byte: "
                + (same.error() != null ? same.error() : "it differs"));

        var emptyPath = folder.resolve(EMPTY_JSON_SECRETS_FILE);
        var empty = attemptCheck(() -> Arrays.equals(Files.readAllBytes(emptyPath), "{}".getBytes(StandardCharsets.US_ASCII)));
        checks.check(empty.ok(), "pipeline: " + EMPTY_JSON_SECRETS_FILE + " is {}: " + (empty.error() != null ? empty.error() : "it isn't"));
        var firstFileName = fixtures.secrets().get(0).fileName();
        var nothing = readFromNewCache(emptyPath, trust, ring, format, firstFileName);
        checks.check(nothing.error() == null && nothing.got().isEmpty(),
                "pipeline: " + EMPTY_JSON_SECRETS_FILE + " has no " + firstFileName + ": " + nothing);

        var work = folder.resolve(CONSUMER_DIR);
        deleteRecursively(work);
        Files.createDirectories(work);
        checkTampered(checks, ring, format, trust, jsonPath, work);
        checkArchive(checks, ring, fixtures, trust, folder, work);
    }

    /**
     * Two copies of secrets.json, each changed one way, must each be refused whole: a lookup of a
     * member the change didn't touch fails authentication too.
     */
    private static void checkTampered(Checker checks, KeyRing ring, EncryptedFormatProvider format, KeyFileTrust trust, Path jsonPath,
            Path work) {
        var members = new ArrayList<Map.Entry<String, String>>();
        try {
            var root = JSON.readTree(Files.readAllBytes(jsonPath));
            if (!root.isObject()) {
                throw new IllegalStateException("it isn't a JSON object");
            }
            for (var member : root.properties()) {
                if (!member.getValue().isTextual()) {
                    throw new IllegalStateException(member.getKey() + "'s value isn't a string");
                }
                members.add(Map.entry(member.getKey(), member.getValue().textValue()));
            }
        } catch (Exception e) {
            checks.fail("pipeline: parsing " + JSON_SECRETS_FILE + " to tamper with it: " + describe(e));
            return;
        }
        if (members.size() < 3) {
            checks.fail("pipeline: " + JSON_SECRETS_FILE + " holds " + members.size() + " members, too few to tamper with");
            return;
        }
        var untouched = members.get(members.size() - 1).getKey();

        var swapped = new ArrayList<>(members);
        swapped.set(0, Map.entry(members.get(0).getKey(), members.get(1).getValue()));
        swapped.set(1, Map.entry(members.get(1).getKey(), members.get(0).getValue()));
        var result = readFromNewCache(work.resolve("swapped.json"), swapped, trust, ring, format, untouched);
        checks.check(result.failedWith(CryptographicException.class),
                "pipeline: " + JSON_SECRETS_FILE + " with two values swapped is refused whole: " + result);

        var flipped = new ArrayList<>(members);
        var tampered = attempt(() -> Main.tamper(members.get(0).getValue()));
        if (tampered.error() != null) {
            checks.fail("pipeline: tampering " + members.get(0).getKey() + ": " + tampered.error());
            return;
        }
        flipped.set(0, Map.entry(members.get(0).getKey(), tampered.got()));
        result = readFromNewCache(work.resolve("flipped.json"), flipped, trust, ring, format, untouched);
        checks.check(result.failedWith(CryptographicException.class),
                "pipeline: " + JSON_SECRETS_FILE + " with a flipped tag bit is refused whole: " + result);
    }

    /**
     * Unpacks secrets.tar with the system tar, from its standard input, into a fresh folder: it must
     * hold exactly the files writeProtectedSecretFiles wrote, byte for byte, each reading through a
     * FilePerSecretCacheImpl as its value.
     */
    private static void checkArchive(Checker checks, KeyRing ring, PipelineFixtures fixtures, KeyFileTrust trust, Path folder, Path work) {
        var unpacked = work.resolve(PIPELINE_UNPACKED_DIR);
        try {
            Files.createDirectories(unpacked);
            untar(unpacked, destination -> Files.copy(folder.resolve(SECRETS_TAR), destination));
        } catch (Exception e) {
            checks.fail("pipeline: unpacking " + SECRETS_TAR + ": " + describe(e));
            return;
        }

        var names = fixtures.secrets().stream().map(PipelineSecret::fileName).sorted().toList();
        List<String> entries;
        try (var listing = Files.list(unpacked)) {
            entries = listing.map(p -> p.getFileName().toString()).sorted().toList();
        } catch (IOException e) {
            entries = List.of();
        }
        checks.check(entries.equals(names),
                "pipeline: " + SECRETS_TAR + " holds exactly the secrets' files: it holds " + entries.size() + ", not " + names.size());

        FilePerSecretCacheImpl files;
        try {
            files = new FilePerSecretCacheImpl(unpacked, trust, ring, new DefaultFormatProviderImpl());
        } catch (Exception e) {
            checks.fail("pipeline: opening the unpacked folder: " + describe(e));
            return;
        }
        for (var s : fixtures.secrets()) {
            String difference;
            try {
                difference = compareFolders(folder.resolve(PIPELINE_FILES_DIR), unpacked, List.of(s.fileName()));
            } catch (IOException e) {
                difference = describe(e);
            }
            var result = attempt(() -> readCache(files, s.fileName()));
            checks.check(difference == null && result.error() == null && s.plaintext().equals(result.got()),
                    "pipeline: " + SECRETS_TAR + "'s " + s.fileName() + " is the written file and reads as its value: "
                            + (difference != null ? difference : result.error() == null ? result.bytes() + ", wrong plaintext" : result));
        }
    }

    /** Writes an archive to a process's standard input. */
    @FunctionalInterface
    private interface ArchiveWriter {
        void write(OutputStream destination) throws Exception;
    }

    /**
     * Runs the system tar - Windows' own bsdtar, else the tar on PATH - to unpack an archive from its
     * standard input into folder: write writes the archive, and its input is closed afterwards. Its
     * arguments are a list, never a shell command line.
     */
    private static void untar(Path folder, ArchiveWriter write) throws Exception {
        var tar = new ProcessBuilder(tarPath(), "-x", "--no-same-owner", "-f", "-", "-C", folder.toString())
                .redirectErrorStream(true)
                .start();
        var output = CompletableFuture.supplyAsync(() -> {
            try {
                return new String(tar.getInputStream().readAllBytes(), StandardCharsets.UTF_8).strip();
            } catch (IOException e) {
                return describe(e);
            }
        });
        try (var stdin = tar.getOutputStream()) {
            write.write(stdin);
        } catch (Exception e) {
            tar.destroy();
            throw e;
        }
        int exit = tar.waitFor();
        if (exit != 0) {
            throw new IllegalStateException("tar exited " + exit + ": " + output.join());
        }
    }

    private static String tarPath() {
        return System.getProperty("os.name").startsWith("Windows")
                ? Path.of(System.getenv("SystemRoot"), "System32", "tar.exe").toString()
                : "tar";
    }

    /** null if each named file in actual is the one in expected byte for byte, else what differs. */
    private static String compareFolders(Path expected, Path actual, List<String> names) throws IOException {
        for (var name : names) {
            var path = actual.resolve(name);
            if (!Files.isRegularFile(path)) {
                return name + " is missing";
            }
            if (!Arrays.equals(Files.readAllBytes(path), Files.readAllBytes(expected.resolve(name)))) {
                return name + " differs";
            }
        }
        return null;
    }

    /** A lookup through a new JsonSecretsFileReadOnlyCacheImpl over path, so nothing an earlier cache loaded is reused. */
    private static Attempt readFromNewCache(Path path, KeyFileTrust trust, KeyRing ring, EncryptedFormatProvider format, String name) {
        return attempt(() -> readCache(new JsonSecretsFileReadOnlyCacheImpl(path, trust, ring, format), name));
    }

    /** Writes members to path as a JSON object, in their order, then looks name up through a new cache over it. */
    private static Attempt readFromNewCache(Path path, List<Map.Entry<String, String>> members, KeyFileTrust trust, KeyRing ring,
            EncryptedFormatProvider format, String name) {
        try {
            writeMembers(path, members);
        } catch (Exception e) {
            return new Attempt(null, e);
        }
        return readFromNewCache(path, trust, ring, format, name);
    }

    /** Writes members as a JSON object, in their order. The layout is Jackson's: the cache reads any valid JSON object. */
    private static void writeMembers(Path path, List<Map.Entry<String, String>> members) throws IOException {
        var object = new LinkedHashMap<String, String>();
        for (var member : members) {
            object.put(member.getKey(), member.getValue());
        }
        Files.write(path, JSON.writeValueAsBytes(object));
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (!Files.exists(path)) {
            return;
        }
        try (Stream<Path> walk = Files.walk(path)) {
            for (var p : walk.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(p);
            }
        }
    }

    private static List<String> concat(List<String> a, List<String> b) {
        var all = new ArrayList<String>(a);
        all.addAll(b);
        return all;
    }

    private record Checked(boolean ok, String error) {}

    @FunctionalInterface
    private interface Check {
        boolean run() throws Exception;
    }

    private static Checked attemptCheck(Check body) {
        try {
            return new Checked(body.run(), null);
        } catch (Exception e) {
            return new Checked(false, describe(e));
        }
    }

    /**
     * An output stream over a fixed array: it keeps the first array.length bytes written, counts every
     * byte, and never grows or copies, so a longer write is caught without another copy of the key.
     */
    private static final class FixedBuffer extends OutputStream {
        private final byte[] buffer;
        int count;

        FixedBuffer(byte[] buffer) {
            this.buffer = buffer;
        }

        @Override
        public void write(int b) {
            if (count < buffer.length) {
                buffer[count] = (byte) b;
            }
            count++;
        }

        @Override
        public void write(byte[] b, int off, int len) {
            java.util.Objects.checkFromIndexSize(off, len, b.length);
            var keep = Math.max(0, Math.min(len, buffer.length - count));
            System.arraycopy(b, off, buffer, count, keep);
            count += len;
        }
    }

    /**
     * A SecretPipelineWriterBase over an in-memory store: each store name maps to its value's exact
     * text, handed to the writer as UTF-8 and zeroed after. Names match exactly, and a store name is 1
     * or more ASCII letters, digits, '/', '_', '.' and '-'.
     */
    static final class InMemorySecretPipelineWriter extends SecretPipelineWriterBase {
        private static final Pattern STORE_NAME = Pattern.compile("^[A-Za-z0-9/_.\\-]+$");
        private final Map<String, String> store;

        InMemorySecretPipelineWriter(PipelineDataProtector protector, List<String> secretNames, Map<String, String> store) {
            super(protector, secretNames, name -> STORE_NAME.matcher(name).matches());
            this.store = store;
        }

        @Override
        protected void readSecret(String name, List<SecretRequest> requests, Map<String, String> values) {
            var text = store.get(name);
            if (text == null) {
                return;
            }
            var secret = text.getBytes(StandardCharsets.UTF_8);
            try {
                protectSecret(secret, secret.length, requests, values);
            } finally {
                ArrayUtility.zeroMemory(secret);
            }
        }
    }
}
